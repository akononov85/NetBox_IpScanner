#Requires -Version 7.2
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)]
    [string] $Cidr,

    [Parameter(Mandatory)]
    [string[]] $AllowedCidr,

    [ValidateRange(1, 65536)]
    [int] $MaxAddresses = 4096,

    [switch] $Apply,
    [uri] $NetBoxUrl = $env:NETBOX_URL,
    [ValidateRange(1, 2147483647)]
    [int] $VrfId,
    [ValidateSet('Bearer', 'Token')]
    [string] $AuthScheme = 'Bearer'
)

$ErrorActionPreference = 'Stop'

function ConvertTo-IPv4Number([string] $Address) {
    if ($Address -notmatch '^(0|[1-9][0-9]{0,2})(\.(0|[1-9][0-9]{0,2})){3}$') {
        throw "Некорректный IPv4-адрес: $Address"
    }
    $bytes = ([ipaddress]::Parse($Address)).GetAddressBytes()
    return ([long]$bytes[0] * 16777216 + $bytes[1] * 65536 + $bytes[2] * 256 + $bytes[3])
}

function Get-NetworkRange([string] $Network) {
    if ($Network -notmatch '^([^/]+)/([0-9]|[12][0-9]|3[0-2])$') {
        throw "Ожидается IPv4 CIDR: $Network"
    }
    $address = $Matches[1]
    $prefix = [int]$Matches[2]
    $first = ConvertTo-IPv4Number $address
    $size = [long]1 -shl (32 - $prefix)
    if ($first % $size -ne 0) {
        throw "Укажите адрес сети в CIDR: $Network"
    }
    return @{ First = $first; Last = $first + $size - 1; Size = $size }
}

$target = Get-NetworkRange $Cidr
$allowed = @($AllowedCidr | ForEach-Object { Get-NetworkRange $_ })
if (-not ($allowed | Where-Object { $_.First -le $target.First -and $_.Last -ge $target.Last })) {
    throw "CIDR $Cidr выходит за пределы разрешённых сетей площадки."
}
if ($target.Size -gt $MaxAddresses) {
    throw "CIDR $Cidr превышает лимит $MaxAddresses адресов."
}

$vrf = $null
if ($PSBoundParameters.ContainsKey('VrfId')) { $vrf = $VrfId }

if ($Apply) {
    if (-not $NetBoxUrl -or -not $NetBoxUrl.IsAbsoluteUri -or $NetBoxUrl.Scheme -ne 'https' -or
        $NetBoxUrl.UserInfo -or $NetBoxUrl.Query -or $NetBoxUrl.Fragment -or -not $env:NETBOX_TOKEN) {
        throw 'Для записи задайте HTTPS URL NetBox и переменную NETBOX_TOKEN.'
    }
    $endpoint = $NetBoxUrl.AbsoluteUri.TrimEnd('/') + '/api/ipam/ip-addresses/'
    $api = @{
        Headers = @{ Authorization = "$AuthScheme $env:NETBOX_TOKEN" }
        TimeoutSec = 30
        MaximumRedirection = 0
    }
}

$nmap = Get-Command nmap -CommandType Application | Select-Object -First 1
$xml = & $nmap.Source -sn -n -oX - $Cidr
if ($LASTEXITCODE -ne 0) { throw "Nmap завершился с кодом $LASTEXITCODE." }
$scan = [xml]($xml -join "`n")
if ($scan.nmaprun.runstats.finished.exit -ne 'success' -or
    [long]$scan.nmaprun.runstats.hosts.total -ne $target.Size) {
    throw 'Nmap вернул неполный результат.'
}
$found = @(
    foreach ($entry in $scan.nmaprun.host) {
        if ($entry.status.state -ne 'up') { continue }
        foreach ($address in $entry.address) {
            if ($address.addrtype -ne 'ipv4') { continue }
            $number = ConvertTo-IPv4Number $address.addr
            if ($number -ge $target.First -and $number -le $target.Last) { $address.addr }
        }
    }
)
$found = @($found | Sort-Object -Unique)
if (-not $Apply -or $found.Count -eq 0) {
    ConvertTo-Json -InputObject $found
    return
}

# Compare host addresses regardless of the prefix length stored in NetBox.
$existing = [System.Collections.Generic.HashSet[string]]::new()
$parent = [uri]::EscapeDataString($Cidr)
$offset = 0
do {
    $page = Invoke-RestMethod @api -Uri "${endpoint}?parent=$parent&limit=100&offset=$offset"
    if (-not $page.PSObject.Properties['results'] -or -not $page.PSObject.Properties['next']) {
        throw 'NetBox вернул неожиданный формат ответа.'
    }
    foreach ($record in $page.results) {
        if ($record.vrf.id -eq $vrf) {
            [void]$existing.Add(($record.address -split '/', 2)[0])
        }
    }
    $offset += $page.results.Count
    if ($page.next -and $page.results.Count -eq 0) { throw 'NetBox вернул пустую страницу с продолжением.' }
} while ($page.next)

foreach ($address in $found) {
    if ($existing.Contains($address)) {
        [pscustomobject]@{ Address = $address; Action = 'existing' }
        continue
    }
    $body = @{
        address = "$address/32"
        vrf = $vrf
        status = 'active'
        description = 'Discovered by Nmap'
    } | ConvertTo-Json -Compress
    $created = Invoke-RestMethod @api -Uri $endpoint -Method Post -ContentType 'application/json' -Body $body
    [pscustomobject]@{ Address = $address; Action = 'created'; Id = $created.id }
}
