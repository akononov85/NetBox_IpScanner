use anyhow::{anyhow, bail, ensure, Context, Result};
use ipnet::Ipv4Net;
use reqwest::{
    blocking::{Client, RequestBuilder},
    header::{HeaderValue, AUTHORIZATION},
    redirect, Url,
};
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    net::{IpAddr, Ipv4Addr},
    process::Command,
    thread,
    time::Duration,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    netbox_url: String,
    token: String,
    auth_scheme: AuthScheme,
    site_name: String,
    apply: bool,
    max_addresses: u64,
    scan_timeout_seconds: u32,
    #[serde(default)]
    reachable_vrf_ids: Vec<u64>,
}

#[derive(Deserialize)]
enum AuthScheme {
    Bearer,
    Token,
}

struct NetBox {
    client: Client,
    base: Url,
    auth: HeaderValue,
}

#[derive(Deserialize)]
struct Page<T> {
    next: Option<String>,
    results: Vec<T>,
}

#[derive(Deserialize)]
struct Reference {
    id: u64,
}

#[derive(Deserialize)]
struct Site {
    id: u64,
    name: String,
}

#[derive(Deserialize)]
struct Tag {
    slug: String,
}

#[derive(Deserialize)]
struct Prefix {
    id: u64,
    prefix: String,
    scope_type: Option<String>,
    scope_id: Option<u64>,
    tags: Vec<Tag>,
    vrf: Option<Reference>,
}

#[derive(Deserialize)]
struct Address {
    address: String,
    vrf: Option<Reference>,
}

impl NetBox {
    fn new(config: &Config) -> Result<Self> {
        let mut base = Url::parse(&config.netbox_url).context("invalid NetBox URL")?;
        ensure!(
            base.scheme() == "https"
                && base.host().is_some()
                && base.username().is_empty()
                && base.password().is_none()
                && base.query().is_none()
                && base.fragment().is_none(),
            "netbox_url must be an HTTPS base URL"
        );
        if !base.path().ends_with('/') {
            base.path_segments_mut()
                .map_err(|_| anyhow!("invalid NetBox base path"))?
                .push("");
        }

        let token = config.token.trim();
        ensure!(!token.is_empty(), "set token in the configuration file");
        let scheme = match config.auth_scheme {
            AuthScheme::Bearer => "Bearer",
            AuthScheme::Token => "Token",
        };
        let mut auth = HeaderValue::from_str(&format!("{scheme} {token}"))
            .context("invalid authentication header")?;
        auth.set_sensitive(true);
        let client = Client::builder()
            .https_only(true)
            .redirect(redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .build()?;
        Ok(Self { client, base, auth })
    }

    fn send(&self, request: RequestBuilder) -> Result<reqwest::blocking::Response> {
        let response = request.header(AUTHORIZATION, self.auth.clone()).send()?;
        ensure!(
            response.status().is_success(),
            "NetBox returned HTTP {}",
            response.status()
        );
        Ok(response)
    }

    fn list<T: DeserializeOwned>(&self, path: &str, filters: &[(&str, &str)]) -> Result<Vec<T>> {
        let url = self.base.join(path)?;
        let mut offset = 0;
        let mut results = Vec::new();
        loop {
            let page: Page<T> = self
                .send(
                    self.client
                        .get(url.clone())
                        .query(filters)
                        .query(&[("limit", 100), ("offset", offset)]),
                )
                .with_context(|| format!("GET {path} at offset {offset}"))?
                .json()
                .with_context(|| format!("unexpected response from {path}"))?;
            ensure!(
                page.next.is_none() || !page.results.is_empty(),
                "NetBox returned an empty page with a continuation"
            );
            offset += page.results.len();
            results.extend(page.results);
            if page.next.is_none() {
                return Ok(results);
            }
        }
    }

    fn create_address(
        &self,
        address: Ipv4Addr,
        vrf: Option<u64>,
        hostname: Option<&str>,
    ) -> Result<()> {
        let url = self.base.join("api/ipam/ip-addresses/")?;
        self.send(self.client.post(url).json(&json!({
            "address": format!("{address}/32"),
            "vrf": vrf,
            "status": "active",
            "dns_name": hostname.unwrap_or_default(),
            "description": "Discovered by network scan"
        })))
        .with_context(|| format!("create IP {address} in VRF {vrf:?}"))?;
        Ok(())
    }
}

fn valid_hostname(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && name.parse::<IpAddr>().is_err()
        && name.bytes().any(|byte| byte.is_ascii_alphanumeric())
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
}

fn echo_replies(
    xml: &str,
    network: Ipv4Net,
    size: u64,
) -> Result<BTreeMap<Ipv4Addr, Option<String>>> {
    // Nmap emits a DOCTYPE without entities. Remove it before parsing.
    let xml = xml.replace("<!DOCTYPE nmaprun>", "");
    let document = roxmltree::Document::parse(&xml).context("invalid Nmap XML")?;
    let root = document.root_element();
    ensure!(root.has_tag_name("nmaprun"), "unexpected Nmap XML root");
    let stats = root
        .children()
        .find(|node| node.has_tag_name("runstats"))
        .context("missing Nmap run statistics")?;
    let finished = stats
        .children()
        .any(|node| node.has_tag_name("finished") && node.attribute("exit") == Some("success"));
    let total = stats
        .children()
        .find(|node| node.has_tag_name("hosts"))
        .and_then(|node| node.attribute("total"))
        .and_then(|value| value.parse::<u64>().ok());
    ensure!(finished && total == Some(size), "incomplete Nmap scan");

    let mut found = BTreeMap::new();
    for host in root.children().filter(|node| node.has_tag_name("host")) {
        let echo_reply = host.children().any(|node| {
            node.has_tag_name("status")
                && node.attribute("state") == Some("up")
                && node.attribute("reason") == Some("echo-reply")
        });
        if !echo_reply {
            continue;
        }
        let smb_result = host
            .children()
            .filter(|node| node.has_tag_name("hostscript"))
            .flat_map(|node| node.children())
            .find(|node| {
                node.has_tag_name("script") && node.attribute("id") == Some("smb-os-discovery")
            });
        let hostname = smb_result.and_then(|script| {
            ["fqdn", "server"].iter().find_map(|key| {
                script
                    .children()
                    .find(|node| node.has_tag_name("elem") && node.attribute("key") == Some(*key))
                    .and_then(|node| node.text())
                    .map(str::trim)
                    .filter(|name| valid_hostname(name))
                    .map(str::to_ascii_lowercase)
            })
        });
        for node in host.children().filter(|node| {
            node.has_tag_name("address") && node.attribute("addrtype") == Some("ipv4")
        }) {
            let address: Ipv4Addr = node
                .attribute("addr")
                .context("missing host address")?
                .parse()?;
            ensure!(
                network.contains(&address),
                "Nmap returned out-of-prefix IP {address}"
            );
            found.insert(address, hostname.clone());
        }
    }
    Ok(found)
}

fn scan(network: Ipv4Net, size: u64, seconds: u32) -> Result<BTreeMap<Ipv4Addr, Option<String>>> {
    let output = Command::new("/usr/bin/timeout")
        .args(["--kill-after=5s", &format!("{seconds}s"), "/usr/bin/nmap"])
        .args([
            "--privileged",
            "-sT",
            "-n",
            "-PE",
            "--disable-arp-ping",
            "-p",
            "139,445",
            "--script",
            "smb-os-discovery",
            "--script-timeout",
            "5s",
            "-oX",
            "-",
        ])
        .arg(network.to_string())
        .output()
        .context("launching Nmap with timeout")?;
    ensure!(
        output.status.success(),
        "Nmap failed ({}) {}",
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    );
    echo_replies(std::str::from_utf8(&output.stdout)?, network, size)
}

fn snmp_hostname(ip: Ipv4Addr) -> Option<String> {
    let sys_name = snmp2::Oid::from(&[1, 3, 6, 1, 2, 1, 1, 5, 0]).ok()?;
    let mut session =
        snmp2::SyncSession::new_v1((ip, 161), b"public", Some(Duration::from_secs(2)), 1).ok()?;
    let mut response = session.get(&sys_name).ok()?;
    if response.error_status != 0 {
        return None;
    }
    let (oid, snmp2::Value::OctetString(value)) = response.varbinds.next()? else {
        return None;
    };
    if oid != sys_name {
        return None;
    }
    let name = std::str::from_utf8(value).ok()?.trim();
    valid_hostname(name).then(|| name.to_ascii_lowercase())
}

fn process_prefix(netbox: &NetBox, config: &Config, prefix: &Prefix) -> Result<()> {
    let vrf = prefix.vrf.as_ref().map(|value| value.id);
    if let Some(id) = vrf {
        ensure!(
            config.reachable_vrf_ids.contains(&id),
            "VRF {id} is not enabled in reachable_vrf_ids"
        );
    }
    let network: Ipv4Net = prefix.prefix.parse().context("invalid IPv4 CIDR")?;
    let size = 1u64 << (32 - network.prefix_len());
    ensure!(
        size <= config.max_addresses,
        "prefix has {size} addresses, above the limit"
    );
    let mut found: Vec<_> = scan(network, size, config.scan_timeout_seconds)?
        .into_iter()
        .collect();
    if found.is_empty() {
        println!(
            "{} VRF={vrf:?} replies=0 with_smb=0 with_snmp=0",
            prefix.prefix
        );
        return Ok(());
    }
    let smb_count = found.iter().filter(|(_, name)| name.is_some()).count();
    let mut snmp_count = 0;
    thread::scope(|scope| {
        let batch_size = found.len().div_ceil(16);
        let workers: Vec<_> = found
            .chunks_mut(batch_size)
            .map(|batch| {
                scope.spawn(move || {
                    let mut count = 0;
                    for (ip, name) in batch {
                        if let Some(snmp_name) = snmp_hostname(*ip) {
                            count += 1;
                            name.get_or_insert(snmp_name);
                        }
                    }
                    count
                })
            })
            .collect();
        for worker in workers {
            snmp_count += worker.join().expect("SNMP worker panicked");
        }
    });
    println!(
        "{} VRF={vrf:?} replies={} with_smb={smb_count} with_snmp={snmp_count}",
        prefix.prefix,
        found.len()
    );
    let records =
        netbox.list::<Address>("api/ipam/ip-addresses/", &[("parent", &prefix.prefix)])?;
    let mut existing = BTreeSet::new();
    for record in records {
        if record.vrf.map(|value| value.id) == vrf {
            let ip: IpAddr = record
                .address
                .split('/')
                .next()
                .context("missing IP")?
                .parse()?;
            if let IpAddr::V4(ip) = ip {
                existing.insert(ip);
            }
        }
    }
    for (address, hostname) in found
        .iter()
        .filter(|(address, _)| !existing.contains(address))
    {
        let action = if config.apply {
            netbox.create_address(*address, vrf, hostname.as_deref())?;
            "created"
        } else {
            "would create"
        };
        println!(
            "{action} {address} VRF={vrf:?} dns_name={}",
            hostname.as_deref().unwrap_or("-")
        );
    }
    Ok(())
}

fn run() -> Result<()> {
    let mut args = env::args_os().skip(1);
    let path = args
        .next()
        .context("usage: netbox-icmp-agent CONFIG.toml")?;
    ensure!(
        args.next().is_none(),
        "usage: netbox-icmp-agent CONFIG.toml"
    );
    let input = fs::read_to_string(path).context("reading configuration file")?;
    // TOML diagnostics can include the original line with the token.
    let config: Config =
        toml::from_str(&input).map_err(|_| anyhow!("invalid agent configuration"))?;
    ensure!(!config.site_name.trim().is_empty(), "site_name is required");
    ensure!(
        (1..=65_536).contains(&config.max_addresses),
        "max_addresses must be 1–65536"
    );
    ensure!(
        (1..=3_300).contains(&config.scan_timeout_seconds),
        "scan timeout must be 1–3300 seconds"
    );

    let netbox = NetBox::new(&config)?;
    let sites = netbox.list::<Site>("api/dcim/sites/", &[("name", &config.site_name)])?;
    let mut matching = sites.iter().filter(|site| site.name == config.site_name);
    let site = matching.next().context("site not found by exact name")?;
    ensure!(matching.next().is_none(), "site name is ambiguous");
    let site_id = site.id.to_string();
    let prefixes = netbox.list::<Prefix>(
        "api/ipam/prefixes/",
        &[
            ("scope_type", "dcim.site"),
            ("scope_id", &site_id),
            ("tag", "scan"),
            ("family", "4"),
        ],
    )?;

    let mut failed = 0;
    let mut selected = 0;
    for prefix in prefixes.iter().filter(|prefix| {
        prefix.scope_type.as_deref() == Some("dcim.site")
            && prefix.scope_id == Some(site.id)
            && prefix.tags.iter().any(|tag| tag.slug == "scan")
            && !prefix.prefix.contains(':')
    }) {
        selected += 1;
        if let Err(error) = process_prefix(&netbox, &config, prefix) {
            failed += 1;
            eprintln!("prefix #{} {}: {error:#}", prefix.id, prefix.prefix);
        }
    }
    println!(
        "site={} prefixes={selected} failed={failed} apply={}",
        site.name, config.apply
    );
    if failed > 0 {
        bail!("{failed} prefix(es) failed");
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_icmp_echo_replies() -> Result<()> {
        let xml = r#"<!DOCTYPE nmaprun>
        <nmaprun>
          <host><status state="up" reason="echo-reply"/>
            <address addr="192.0.2.1" addrtype="ipv4"/>
            <hostnames><hostname name="ignored.example" type="PTR"/></hostnames>
            <hostscript><script id="smb-os-discovery"><elem key="fqdn">Switch_01.Example</elem><elem key="server">SWITCH</elem></script></hostscript>
          </host>
          <host><status state="up" reason="echo-reply"/>
            <address addr="192.0.2.3" addrtype="ipv4"/>
          </host>
          <host><status state="up" reason="arp-response"/>
            <address addr="192.0.2.2" addrtype="ipv4"/>
          </host>
          <runstats><finished exit="success"/><hosts total="4"/></runstats>
        </nmaprun>"#;
        let network = "192.0.2.0/30".parse()?;
        let found = echo_replies(xml, network, 4)?;
        assert_eq!(
            found,
            BTreeMap::from([
                (
                    Ipv4Addr::new(192, 0, 2, 1),
                    Some("switch_01.example".to_string())
                ),
                (Ipv4Addr::new(192, 0, 2, 3), None),
            ])
        );
        assert!(echo_replies(xml, network, 8).is_err());
        assert!(echo_replies(&xml.replace("192.0.2.1", "192.0.2.5"), network, 4).is_err());
        Ok(())
    }
}
