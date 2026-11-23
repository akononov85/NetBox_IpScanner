# NetBox ICMP Agent

[Русская версия](README.ru.md)

A Linux agent that discovers hosts in IPv4 prefixes tagged `scan` in NetBox. It selects prefixes scoped directly to the configured site. ICMP Echo identifies responding hosts, then SMB and SNMPv1 (community `public`, OID `sysName.0`) supply names. SMB takes precedence when both return a name. The agent performs discovery without DNS lookups.

With `apply = true`, it creates missing IPs as active `/32` entries, populates `dns_name` when available, and sets the description to `Discovered by network scan`. It checks for existing records by IP and VRF regardless of prefix length.

## Configuration

| Setting | Purpose |
|---|---|
| `netbox_url` | Base HTTPS URL, for example `https://netbox.example.org/`. |
| `token` | Full API token. Keep it in the proxy configuration. |
| `auth_scheme` | `"Bearer"` for v2 or `"Token"` for v1. |
| `site_name` | Exact, case-sensitive site name in NetBox. |
| `apply` | `false` reports changes. `true` writes to IPAM. |
| `max_addresses` | Maximum address count per prefix. The template uses 4096. |
| `scan_timeout_seconds` | Nmap timeout per prefix. The template uses 180 seconds. |
| `reachable_vrf_ids` | Numeric IDs of VRFs reachable from this proxy. Prefixes in the global routing table are always eligible. |

The token user needs read access to sites, prefixes, and IP addresses. Import requires permission to add IP addresses and a write-enabled token.

## Install on a Linux proxy

Use NetBox 4.2 or later, Linux with systemd, `/usr/bin/nmap` and `/usr/bin/timeout`. The proxy needs HTTPS access to NetBox and routes to the selected prefixes. Discovery uses ICMP Echo. Name lookup uses SMB (TCP/139 and 445) and SNMP (UDP/161).

On Debian 13, install `nmap`, `coreutils`, `ca-certificates`, and `libssl3t64`. To build, install Rust/Cargo, `build-essential`, `pkg-config`, and `libssl-dev` on a Linux system compatible with the target proxy.

```sh
cargo build --release --locked
```

Copy the executable from `target/release/`, [agent.example.toml](agent.example.toml), and the [systemd units](systemd/) to the proxy. Run as root from the directory containing these files.

```sh
getent passwd netbox-scan >/dev/null || useradd --system --user-group --no-create-home --shell /usr/sbin/nologin netbox-scan
install -m 0755 netbox-icmp-agent /usr/local/bin/netbox-icmp-agent
install -d -o root -g netbox-scan -m 0750 /etc/netbox-icmp-agent
if [ ! -e /etc/netbox-icmp-agent/agent.toml ]; then
    install -o root -g netbox-scan -m 0640 agent.example.toml /etc/netbox-icmp-agent/agent.toml
fi
install -m 0644 systemd/netbox-icmp-agent.service systemd/netbox-icmp-agent.timer /etc/systemd/system/
systemctl daemon-reload
```

Set the connection details and `apply = false` in `/etc/netbox-icmp-agent/agent.toml`. In NetBox, scope a test IPv4 prefix directly to the configured site and tag it `scan`.

```sh
systemctl start netbox-icmp-agent.service
journalctl -u netbox-icmp-agent.service -n 50 --no-pager
```

Review the prefix count, ICMP replies, and `would create` entries. Set `apply = true`, rerun the service, and verify the `created` entries in IPAM. Enable the hourly timer when ready.

```sh
systemctl enable --now netbox-icmp-agent.timer
systemctl list-timers netbox-icmp-agent.timer
```

## Troubleshooting

- **`prefixes=0`**. Check the site scope, site name, tag slug and API read permissions.
- **HTTP 401 or 403**. Check the token version, authorization scheme, expiry, IP restrictions and permissions.
- **TLS errors**. Check the server certificate chain and the proxy trust store. A service-specific CA bundle can be configured through `SSL_CERT_FILE` in a systemd drop-in.
- **Missing names**. Check access to SMB and SNMP from the proxy. SNMP devices must accept v1 queries and expose `sysName.0`.
- **Pause the schedule**. Run `systemctl disable --now netbox-icmp-agent.timer`. To keep reporting without writes, set `apply = false`.
