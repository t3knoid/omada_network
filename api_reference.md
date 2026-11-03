# Omada Open API Reference

This document lists the API endpoints used by the application for each
resource type. All resource endpoints use the base path:

```
/openapi/v1/{omadacId}/
```

The `{omadacId}` (controller ID) is auto-discovered via `GET /api/info` unless
explicitly provided.

The official API documentation is available at:
<https://use1-omada-northbound.tplinkcloud.com/doc.html#/home>

---

## Authentication

### Client Credentials Mode

| Step | Method | Endpoint | Notes |
| --- | --- | --- | --- |
| Obtain token | `POST` | `/openapi/authorize/token?grant_type=client_credentials` | Client ID and Secret in JSON body |

### Authorization Code Mode

| Step | Method | Endpoint | Notes |
| --- | --- | --- | --- |
| 1. Login | `POST` | `/openapi/authorize/login?client_id={clientId}` | Username and password in JSON body; establishes login session (does **not** return authorization code) |
| 2. Get authorization code | `POST` | `/openapi/authorize/code?client_id={clientId}` | Uses active login session; returns authorization code |
| 3. Exchange code | `POST` | `/openapi/authorize/token?grant_type=authorization_code` | Authorization code, Client ID, and Secret in JSON body |

> **API docs:** Authentication endpoints are documented under the
> [Authorize](https://use1-omada-northbound.tplinkcloud.com/doc.html#/Authorize) tag.

---

## Discovery

| Purpose | Method | Endpoint | Notes |
| --- | --- | --- | --- |
| Controller ID | `GET` | `/api/info` | Returns `result.omadacId` |
| Sites | `GET` | `/openapi/v1/{omadacId}/sites` | Returns available sites; used to resolve site name → site ID |

> **API docs:**
> - Controller info — not part of the Open API spec (internal endpoint).
> - Sites — documented under the [Site](https://use1-omada-northbound.tplinkcloud.com/doc.html#/Site) tag.

---

## Resources

### ACL Rules

Fetches gateway, switch, and EAP ACL rules separately and merges the results.
An `aclType` field (`gateway`, `switch`, or `eap`) is added to each rule.

| ACL Type | Method | Endpoint |
| --- | --- | --- |
| Gateway | `GET` | `sites/{siteId}/acls/osg-acls` |
| Switch | `GET` | `sites/{siteId}/acls/osw-acls` |
| EAP | `GET` | `sites/{siteId}/acls/eap-acls` |

All three endpoints are paginated. Failures are logged and skipped (partial
results are still returned).

> **API docs:** Documented under the [ACL](https://use1-omada-northbound.tplinkcloud.com/doc.html#/ACL) tag —
> *Get gateway ACL list*, *Get switch ACL list*, *Get eap ACL list*.

---

### IP Groups

IP groups are profile groups with `groupType=0`.

| Method | Endpoint | Notes |
| --- | --- | --- |
| `GET` | `sites/{siteId}/profiles/groups/0` | Primary — returns only IP groups |
| `GET` | `sites/{siteId}/profiles/groups` | Fallback — returns all groups; filtered client-side by `type == 0` |

> **API docs:** Documented under the [Profiles](https://use1-omada-northbound.tplinkcloud.com/doc.html#/Profiles) tag —
> *Get group profile list by type* (`groupType=0`).

---

### Port Groups (IP-Port Groups)

Port groups are profile groups with `groupType=1`.

| Method | Endpoint | Notes |
| --- | --- | --- |
| `GET` | `sites/{siteId}/profiles/groups/1` | Primary — returns only IP-Port groups |
| `GET` | `sites/{siteId}/profiles/groups` | Fallback — returns all groups; filtered client-side by `type == 1` |

> **API docs:** Documented under the [Profiles](https://use1-omada-northbound.tplinkcloud.com/doc.html#/Profiles) tag —
> *Get group profile list by type* (`groupType=1`).

---

### Networks

| Method | Endpoint | Notes |
| --- | --- | --- |
| `GET` | `sites/{siteId}/lan-networks/all` | Primary — returns all LAN networks |
| `GET` | `sites/{siteId}/lan-networks` | Fallback — paginated |

> **API docs:** Documented under the [Wired Network](https://use1-omada-northbound.tplinkcloud.com/doc.html#/Wired%20Network) tag —
> *Get all networks for the omada id and site id*, *Get LAN network list*.

---

### VLANs

VLANs are derived from the Networks endpoint by filtering for entries that
contain a `vlan` or `vlanId` field. If no entries match, the full network
list is returned.

| Method | Endpoint | Notes |
| --- | --- | --- |
| — | — | Uses `get_networks()` internally (see Networks above) |

> **API docs:** See Networks above — same [Wired Network](https://use1-omada-northbound.tplinkcloud.com/doc.html#/Wired%20Network) tag.

---

### Switch Port Profiles

Attempts multiple endpoints with fallback.

The Markdown output has a summary table (type, native / untagged / tagged
networks, PoE, spanning tree, loopback detect) followed by one section per
profile listing every property, grouped as General, VLAN, Switching,
QoS & Bandwidth, and Spanning Tree. Fields without a dedicated mapping are
listed under **Other**, so no profile property is left out. Profile `type` follows
the API definition: 0 = built-in *All*, 1 = built-in *Disable*, 2 = any other
(*Standard*) profile.

| Priority | Method | Endpoint | Notes |
| --- | --- | --- | --- |
| 1 | `GET` | `sites/{siteId}/lan-profiles` | v1 API (paginated) |
| 2 | `GET` | `sites/{siteId}/lan-profiles` | v2 API (`/openapi/v2/…`) |
| 3 | `GET` | `sites/{siteId}/lan-switch-setting` | Legacy fallback (paginated) |

> **API docs:** Documented under the [Wired Network](https://use1-omada-northbound.tplinkcloud.com/doc.html#/Wired%20Network) tag —
> *Get LAN profile list* (v1), *Get switch profile list* (v2), *Get switch port profile info* (legacy).

---

### Gateway Settings

Attempts multiple endpoints with fallback.

| Priority | Method | Endpoint | Notes |
| --- | --- | --- | --- |
| 1 | `GET` | `sites/{siteId}/internet/ports-config` | Most detailed |
| 2 | `GET` | `sites/{siteId}/internet/basic-info` | Basic internet info |
| 3 | `GET` | `sites/{siteId}/setting/virtual-wans` | Virtual WAN settings |

> **API docs:** Documented under the [Wired Network](https://use1-omada-northbound.tplinkcloud.com/doc.html#/Wired%20Network) tag —
> *Get internet wan ports config*, *Get internet basic info*, *Query virtual WAN list*.

---

### SSIDs

The SSID list is only a summary, so each SSID is merged with its detail.

| Step | Method | Endpoint | Notes |
| --- | --- | --- | --- |
| 1. List WLANs | `GET` | `sites/{siteId}/wireless-network/wlans` | Paginated |
| 2. List SSIDs | `GET` | `sites/{siteId}/wireless-network/wlans/{wlanId}/ssids` | Paginated; called per WLAN |
| 3. SSID detail | `GET` | `sites/{siteId}/wireless-network/ssids/{ssidId}` | Falls back to `…/wlans/{wlanId}/ssids/{ssidId}`; best-effort |
| 4. AP overrides | `GET` | `sites/{siteId}/wireless-network/ssids/{ssidId}/overrides` | Paginated; stored as `apOverrides`; best-effort |

Each SSID is enriched with the parent WLAN's `name` / ID as `wlanName` /
`wlanId`. The detail adds security (PSK / Enterprise / PPSK settings, RADIUS
profile, PMF, 802.11r, OWE, MLO), VLAN, client and SSID rate limits, WLAN
schedule, band steering, data/management rate control, MAC filter,
multicast, DHCP option 82, and Hotspot 2.0. The WPA passphrase and AP
override passwords are redacted.

The Markdown summary resolves the referenced RADIUS, rate limit, and schedule
profiles, networks, and the portal bound to each SSID by name. Each SSID then
gets a detail section, plus an **AP overrides** table when any AP overrides
the SSID name, VLAN, or password.

> `security` codes follow the API: 0 Open, 2 WPA-Enterprise, 3 WPA-Personal,
> 4 PPSK, 5 PPSK + RADIUS. Earlier versions mislabelled 3 as "WPA2". The
> SSID band-steer setting appears in the spec under a field named
> `ssidDhcpOption`; both that and `bandSteer` are read.

> **API docs:** Documented under the [Wireless Network](https://use1-omada-northbound.tplinkcloud.com/doc.html#/Wireless%20Network) tag —
> *Get WLAN group list*, *Get SSID list*, *Get SSID detail info*, *Get Ssid override details*.

### RADIUS Profiles

| Method | Endpoint | Notes |
| --- | --- | --- |
| `GET` | `sites/{siteId}/profiles/radius` | Auth / accounting servers (with RadSec), interim updates, VLAN assignment, CoA, Message-Authenticator, built-in server |

Auth, accounting, CoA, and built-in server secrets are redacted.

### Guest Portals

| Method | Endpoint | Notes |
| --- | --- | --- |
| `GET` | `sites/{siteId}/portals` | Portal list |
| `GET` | `sites/{siteId}/portal/{portalId}` | Per-portal detail, merged; best-effort |

Summary: status, authentication (No Auth, Simple Password, External RADIUS,
External Portal Server, Hotspot with its methods, LDAP, Social Login), bound
SSIDs and networks, auth timeout, landing page, HTTPS redirect. Each portal
gets a detail section for its method (RADIUS profile, PAP/CHAP, NAS ID,
disconnect requests, external portal server, LDAP profile, Google client ID,
Twilio account SID and sender). Portal passwords, OAuth client secrets, and
SMS auth tokens are redacted.

### Schedules and Rate Limit Profiles

| Resource | Method | Endpoint | Notes |
| --- | --- | --- | --- |
| `time_range_profiles` | `GET` | `sites/{siteId}/time-range-profiles` | Day mode (every day / weekdays / weekends / custom days) and time slots |
| `rate_limit_profiles` | `GET` | `sites/{siteId}/rate-limit-profiles` | Download / upload limit (Kbps), default profile |

SSIDs reference both by ID; the SSID tables show their names.

### Wireless Site Settings

| Method | Endpoint | Stored as |
| --- | --- | --- |
| `GET` | `sites/{siteId}/band-steering` | `bandSteering` (Disabled / Prefer 5GHz/6GHz / Balance) |
| `GET` | `sites/{siteId}/roaming` | `roaming` (fast, AI, non-stick roaming) |
| `GET` | `sites/{siteId}/mesh` | `mesh` (mesh, auto failover, connectivity detection, full-sector DFS) |
| `GET` | `sites/{siteId}/multicast-rate-limit` | `multicastRateLimit` (per-protocol packets per second) |

Each part is best-effort; the resource fails only if all four fail.

### AP Radio Settings

| Method | Endpoint | Notes |
| --- | --- | --- |
| `GET` | `sites/{siteId}/aps/{apMac}/radio-config` | Per AP (`type: ap`); unavailable APs are logged and skipped |

One row per AP radio (2.4 GHz, 5 GHz, 5 GHz-1/-2, 6 GHz): radio on/off,
channel (`0` = Auto), channel width, Tx power level (custom power shown in
dBm), wireless mode, and channel limit. These are the per-AP radio overrides
configured on the controller.

---

### DHCP Reservations

| Method | Endpoint | Notes |
| --- | --- | --- |
| `GET` | `sites/{siteId}/setting/service/dhcp` | Paginated |

Rows are sorted by network, then numerically by IP, and include the
reservation description and any per-reservation DHCP options.

> **API docs:** Documented under the [Service](https://use1-omada-northbound.tplinkcloud.com/doc.html#/Service) tag —
> *Get DHCP Reservation List*.

### DHCP Scopes

Reservations alone don't recreate the DHCP service, so `dhcp_scopes` holds
the DHCP definition of every LAN network: one YAML record per network
containing only DHCP-related fields.

| Method | Endpoint | Notes |
| --- | --- | --- |
| `GET` | `sites/{siteId}/lan-networks/all` | Via `get_networks()`; DHCP fields are extracted per network |
| `GET` | `sites/{siteId}/networks/{networkId}/dhcp-server-info` | Pool usage (`poolStatus`), only for networks serving DHCP; best-effort |

Fields kept per network: identity (`id`, `name`, `vlan`, `gatewaySubnet`,
`purpose`), the serving device (`deviceType` 0 External / 1 Gateway / 2 Switch
/ 3 None, `deviceMac`, and switch `mode` 1 Server / 2 Relay), gateway
`dhcpSettings` (pools, lease time in minutes, DNS mode and servers, gateway,
options 60 / 66 / 138, next server, custom options), switch `dhcpServer` /
`dhcpRelay`, `domain`, `dhcpL2RelayEnable` (option 82), `dhcpGuard` /
`dhcpv6Guard`, and the network's IPv6 config.

The Markdown summary shows, per network: DHCP server, pools (with free
addresses), lease time, DNS, gateway, domain, relay targets, and L2 relay.
Each network then gets a detail section (Server, Pool, DNS / Domain, Options,
Relay, Guard).

> Custom DHCP option *type* codes differ by server: gateway 0 String /
> 1 IP Address / 2 Hex Array; switch 0 Hex Array / 1 String / 2 IP Address.

### DHCP Leases

| Method | Endpoint | Notes |
| --- | --- | --- |
| `GET` | `sites/{siteId}/setting/service/dhcp/user-list` | Paginated; leases from every DHCP server in the site |

Network, IP, MAC, name, device/client type, binding (Dynamic / Static), lease
time remaining, and serving device, sorted by network then IP. Leases are
runtime state: they change between runs and are not needed to recreate the
service.

---

### Devices

Returns the adopted devices for the selected site.

| Method | Endpoint | Notes |
| --- | --- | --- |
| `GET` | `sites/{siteId}/devices` | Paginated |

> **API docs:** See the [Device](https://use1-omada-northbound.tplinkcloud.com/doc.html#/Device) tag.

---

### Device Ports

Port configuration for every switch and gateway in the site, exported as one
record per port. Each record is tagged with `deviceName`, `deviceMac`,
`deviceType`, and `deviceModel`. Other device types (e.g. access points) are
skipped.

| Device type | Method | Endpoint | Notes |
| --- | --- | --- | --- |
| — | `GET` | `sites/{siteId}/devices` | Device list (paginated) |
| Switch | `GET` | `sites/{siteId}/switches/ports/overview` | One site-wide paginated call: label, connection, type, operation, profile, native network |
| Switch (fallback) | `GET` | `sites/{siteId}/switches/{switchMac}` | `portList`; used only for switches missing from the overview |
| Gateway | `GET` | `sites/{siteId}/gateways/{gatewayMac}` | `portConfigs`: link speed, duplex, mirroring, PVID, flow control, enabled |
| Gateway | `GET` | `sites/{siteId}/gateways/{gatewayMac}/ports` | `osgPortInfos`: name, type, physical type, mode |
| Gateway | `GET` | `sites/{siteId}/gateways/{gatewayMac}/wan-status` | Link status, speed, duplex — stored as `portStatus` |

Gateway sources are merged by port number; if some fail, the rest are still
used. Failures for a device are logged as warnings and the remaining devices
are still exported.

The Markdown table mirrors the controller's port list:

| Column | Switch | Gateway |
| --- | --- | --- |
| Label | `tagName` | — |
| Connection | `connectedStatus` + negotiated speed/duplex from `portStatus` | `portStatus.linkStatus` + speed/duplex; `Disabled` when `status` is 0 |
| Type | `type`: 1 Copper, 2 Combo, 3 SFP | `type`: 0 WAN, 1 WAN/LAN, 2 LAN |
| Operation | `operation`: Switching, Mirroring, Aggregating | `mode`: 0 WAN, 1 LAN (`Mirroring` when mirroring is enabled) |
| Profile | `profileName` | — |
| Native Network | `nativeNetworkId` resolved to the network name | LAN-mode ports: `pvid` resolved to the network with that VLAN |

> **API docs:** See the [Device](https://use1-omada-northbound.tplinkcloud.com/doc.html#/Device) tag —
> *Get the switches ports overview*, *Get switch info*, *Get gateway info*,
> *Get gateway ports*, *Get gateway wan status*.

---

### NAT

Gateway NAT settings, exported as three resources. WAN port IDs in the rules
(e.g. `1_<uuid>`) are shown as WAN port names, resolved from `gateway_settings`
(`wanPortsConfig[].portId` → `portName`); unknown IDs are shown as-is.

| Resource | Method | Endpoint | Notes |
| --- | --- | --- | --- |
| `port_forwarding` | `GET` | `sites/{siteId}/nat/port-forwardings` | Paginated. Name, status, interface (WAN ports / virtual WANs / WAN IPs), source IP (Any or limited addresses), external port, forward IP/port, protocol (All/TCP/UDP), DMZ |
| `one_to_one_nat` | `GET` | `sites/{siteId}/nat/one-to-one-nat` | Paginated. Name, status, interface, internal IP, external IP, DMZ, description |
| `alg` | `GET` | `sites/{siteId}/nat/alg` | Single object, rendered as Setting / Value rows: FTP (+ ports), H.323, PPTP, IPSec, SIP (+ TCP/UDP, ports, direct signaling/media, timeouts when SIP is on) |

> **API docs:** Documented under the NAT tag —
> *Get port forwarding list*, *Get One-to-One NAT list*, *Get ALG Info*.

---

### Static Routes

Gateway and switch static routes, combined into one resource. Each route is
tagged with `routeSource` (`gateway` or `switch`); switch routes also carry
`deviceName` and `deviceMac`.

| Source | Method | Endpoint | Notes |
| --- | --- | --- | --- |
| Gateway | `GET` | `sites/{siteId}/routing/static-routings` | Paginated. Failure is logged as a warning |
| Gateway | `GET` | `sites/{siteId}/routing/static-routings/interfaces` | Interface ID → name, stored on each route as `interfaceName` |
| Switch | `GET` | `sites/{siteId}/switches/{switchMac}/staticRoutings` | Paginated, per switch. Switches without L3 routing are skipped (debug log only) |

| Column | Gateway route | Switch route |
| --- | --- | --- |
| Destinations | `destinations` (IP/subnet list) | `destinations` |
| Route Type | `routeType`: 0 Next Hop, 1 Interface | Next Hop |
| Next Hop | `nextHopIp` | `nextHopIp` |
| Interface (WAN binding) | `interfaceType` (0 WAN, 1 LAN, 2 L2TP, 3 PPTP, 5 Virtual WAN) + interface name | — |
| Metric | `metric` (0–15) | — |
| Distance | — | `distance` (administrative distance, 1–255) |

> **API docs:** *Get static routing list*, *Get static routing interface list*,
> *Get grid switch staticRouting*.

---

### Policy Routes

| Method | Endpoint | Notes |
| --- | --- | --- |
| `GET` | `sites/{siteId}/routing/policy-routings` | Paginated |

Rows are listed in evaluation order (`index`). Source and destination IDs are
resolved to network / IP group / IP-Port group names; protocols use the same
codes as ACL rules. **WAN Binding** comes from `interfaceType` (0 WAN, 2 L2TP,
3 PPTP, 4 multiple): a single `interfaceId`, or for type 4 the lists of
`wanPortIds`, `vpnIds`, and `virtualWanIds`. WAN port IDs are resolved to
port names from `gateway_settings`. **Backup Interface** shows whether traffic
fails over to another WAN when the bound one is down.

> **API docs:** *Get policy routing list*.

---

### VPN

> **Secrets are redacted by default** before data reaches YAML or Markdown,
> both in the client and again for every resource in `OmadaService.fetch_all`
> (`omada/redaction.py`): any non-empty string whose field name contains
> password, pwd, secret, token, security key, pre-shared key, or private key
> becomes `<redacted>`. `--include-secrets` (or the web UI checkbox) turns
> this off; Markdown then shows the values and flags each affected file. Markdown shows only
> `Configured` / `Not set`.

| Resource | Method | Endpoint | Notes |
| --- | --- | --- | --- |
| `site_to_site_vpns` | `GET` | `sites/{siteId}/vpn/site-to-site-vpns` | Auto / Manual IPsec tunnels |
| `remote_access_vpns` | `GET` | `sites/{siteId}/vpn/client-to-site-vpn-servers` | Tagged `vpnRole: server` (paginated) |
| `remote_access_vpns` | `GET` | `sites/{siteId}/vpn/client-to-site-vpn-clients` | Tagged `vpnRole: client` (paginated). If only one endpoint fails, the other is still used |
| `wireguard` | `GET` | `sites/{siteId}/vpn/wireguards` | Interfaces (paginated) |
| `wireguard` | `GET` | `sites/{siteId}/vpn/wireguard-peers` | Peers, nested under their interface as `peers` |
| `vpn_users` | `GET` | `sites/{siteId}/vpn/users` | Accounts referenced by L2TP / PPTP / OpenVPN servers |

**Site-to-site** summary: name, status, type (Auto / Manual IPsec), remote
peer (remote site or IP), remote subnets, local networks (network names or
custom subnets), WAN, encryption (e.g. `IKEv2 AES256/SHA256/DH14, ESP
AES256/SHA256, PFS DH14`), authentication. Each tunnel then gets a detail
section: Phase 1 (key exchange version, encryption, hash, DH group, exchange
and negotiation mode, SA lifetime, DPD), Phase 2 (encapsulation, AH/ESP,
encryption, hash, PFS, SA lifetime), and Authentication (method, local /
remote ID type and value).

**Remote access** summary: name, role (server / client), status, protocol
(L2TP, PPTP, IPsec, OpenVPN), remote peer, remote subnets, local networks,
client IP pool, WAN, service (UDP/TCP and port), encryption (L2TP over IPsec,
MPPE, IKE suite, or TLS), and authentication references (local / LDAP users and
the usernames assigned to that server from `vpn_users`, OpenVPN certificate
mode and config file, client username, and pre-shared key / password state).
Each tunnel gets a detail section titled `<name> (<role>)`.

**WireGuard**: one row per interface (listen port, local IP, MTU, public key,
private-key state, peer count) and one section per interface listing its peers
(endpoint, allowed addresses, keepalive, public key, preshared-key state,
comment).

### SSL VPN Server

| Method | Endpoint | Stored as | Notes |
| --- | --- | --- | --- |
| `GET` | `sites/{siteId}/vpn/ssl-vpn-server/setting` | `setting` | Required; a failure is reported as a fetch failure |
| `GET` | `sites/{siteId}/vpn/ssl-vpn-server/user-groups` | `userGroups` | Paginated, best-effort |
| `GET` | `sites/{siteId}/vpn/ssl-vpn-server/users` | `users` | Paginated, best-effort; passwords redacted |
| `GET` | `sites/{siteId}/vpn/ssl-vpn-server/resources` | `resources` | Paginated, best-effort |
| `GET` | `sites/{siteId}/vpn/ssl-vpn-server/resource-groups` | `resourceGroups` | Paginated, best-effort |
| `GET` | `sites/{siteId}/vpn/ssl-vpn-server/radius` | `radiusServers` | Used to name the RADIUS profile |

The Markdown starts with server settings as Setting / Value rows: status, WAN
and WAN IP, service port, client IP pool, DNS, tunnel mode (full / split),
authentication (Local / RADIUS / LDAP, with RADIUS profile, PAP/CHAP, retries,
timeout, NAS IP, default user group, or LDAP profile), username and IP
lockout, and idle logout. Sections follow for **User Groups** (users, resource
groups, RADIUS / LDAP attribute), **Users** (group, status, validity,
concurrent logins, password state), **Resources** (IP/subnet or domain,
protocol, ports or ICMP type/code, groups), and **Resource Groups**.

### EoGRE Tunnel

| Method | Endpoint | Notes |
| --- | --- | --- |
| `GET` | `sites/{siteId}/vpn/gre-tunnel` | Single object: enabled, MTU, keepalive interval, max missed keepalives, primary / secondary gateway |

### IPsec Failover

| Method | Endpoint | Notes |
| --- | --- | --- |
| `GET` | `sites/{siteId}/vpn/ipsec_failovers` | Paginated. Name, primary tunnel, candidate tunnels in failover order, failback |

Tunnel references include the state the controller reports (`Active`,
`Standby`, `Disconnected`). The failback time is shown as returned; the spec
does not state its unit.

> **API docs:** VPN tag — *Get site-to-site VPN list*, *Get client-to-site VPN
> server list*, *Get client-to-site VPN client list*, *Get wireguard list*,
> *Get wireguard peer list*, *Get VPN user list*, *Get SSL VPN server setting*,
> *Get user group / user / resource / resource group list for SSL VPN server*,
> *Get radius server for SSL VPN server*, *Get EoGRE tunnel config*,
> *Get IPsec failover list*.

---

## WAN Failover and Site Services

These resources each combine several endpoints. Every part is best-effort: a
failing endpoint is logged and left out, and the resource only fails if all
of its endpoints fail.

### WAN Failover & Load Balancing (`wan_failover`)

| Part | Method | Endpoint | Notes |
| --- | --- | --- | --- |
| `loadBalance` | `GET` | `sites/{siteId}/internet/load-balance` | Weights, link backup, primary / backup WANs, backup mode and trigger, schedule, application-optimized routing, virtual WAN weights |
| `internet` | `GET` | `sites/{siteId}/internet/basic-info` | WAN port list, and the online-detection (health check) interval: `0` = disabled |
| `wanHealth` | `GET` | `sites/{siteId}/gateways/{gatewayMac}/wan-status` | Per gateway: link, internet state, online detection, latency, packet loss, health level |

- **Backup trigger** (`mode`): 0 when any primary WAN fails, 1 when all fail, 2 on schedule (time range profile).
- **Backup mode** (`backupMode`): 0 stays on backup until it fails, 1 returns to primary when it recovers.
- **Weights** are listed "sorted by port ID". They are matched to the WAN-mode ports from `basic-info` in port-number order, and shown unlabelled if the counts differ.
- **Health checks:** the Open API exposes only the detection *interval*. The ping / DNS-lookup targets are not available. `wanHealth` is the status at export time, not configuration, so it changes between runs.

### DNS (`dns_settings`)

| Part | Method | Endpoint | Notes |
| --- | --- | --- | --- |
| `dnsProxy` | `GET` | `sites/{siteId}/setting/service/dns-proxy` | DNSSEC (servers, bogus-reply policy), DoH / DoT (preset and custom servers), DNS Override (servers, networks) |
| `dnsCache` | `GET` | `sites/{siteId}/setting/service/dns-cache` | Enabled, TTL |
| `lanDns` | `GET` | `sites/{siteId}/setting/lan/dns` | Paginated. Local records: IP (A/AAAA), CNAME, or forward; aliases, networks, TTL |
| `ddns` | `GET` | `sites/{siteId}/setting/service/ddns` | Paginated. Provider, domain, interface, username, interval, custom URL; password redacted |

### Time & NTP (`time_settings`)

| Part | Method | Endpoint | Notes |
| --- | --- | --- | --- |
| `site` | `GET` | `sites/{siteId}` | Only `timeZone`, `ntpServers`, `region`, `name`, `scenario` are kept |
| `dst` | `GET` | `sites/{siteId}/dst-info` | DST mode (disabled / automatic / manual), offset, start / end |
| `ntpStatus` | `GET` | `sites/{siteId}/setting/ntp` | Gateway NTP server status; returned as-is (untyped in the spec) |

### Multicast, Bonjour & UPnP (`multicast_services`)

| Part | Method | Endpoint | Notes |
| --- | --- | --- | --- |
| `igmp` | `GET` | `sites/{siteId}/setting/service/igmp` | IGMP proxy: version, upstream WAN / virtual WAN |
| `mld` | `GET` | `sites/{siteId}/setting/service/mld` | MLD proxy: version, upstream WAN |
| `iptv` | `GET` | `sites/{siteId}/setting/service/iptv` | Bridge / custom mode, IPTV and IP-phone VLANs with priority, LAN port roles |
| `upnp` | `GET` | `sites/{siteId}/upnp` | Enabled, WAN ports, LAN networks |
| `mdnsRules` | `GET` | `sites/{siteId}/setting/service/mdns` | Paginated. Bonjour services forwarded between service and client networks (by network or VLAN) |
| `bonjourServices` | `GET` | `sites/{siteId}/profiles/bonjour-service` | Service profiles and their `_service._proto.local` IDs |
| `lanMulticasts` | `GET` | `sites/{siteId}/lan-multicasts` | Paginated. IGMP / MLD snooping: networks, unknown-multicast handling, querier, router ports, report suppression, leave time |

---

### Link Aggregation (`lags`)

| Part | Method | Endpoint | Notes |
| --- | --- | --- | --- |
| Standalone switch LAGs | `GET` | `sites/{siteId}/switches/ports/overview` | Rebuilt from each member port's `lagSetting` (the API has no LAG list for standalone switches) |
| Fallback | `GET` | `sites/{siteId}/switches/{switchMac}` | Only for a switch missing from the overview: ports flagged `lagPort` are listed as a group with `lagId: null` |
| Stack LAGs | `GET` | `sites/{siteId}/stacks`, then `stacks/{stackId}/lags` | Full LAG records: name, mode, ports (`unit/slot/port`), profile, status |
| `mlagGroups` | `GET` | `sites/{siteId}/mlag` | Paginated, best-effort. M-LAG groups: status, member switches and roles, peer-link ports |
| `hashAlgorithm` | `GET` | `sites/{siteId}/lag-hash-alg` | Best-effort. Site LAG hash: source / destination MAC or IP |

**Group membership.** Ports are grouped by (switch, `lagId`). A group's
members are the union of every member's `lagSetting.ports`, plus the ports
carrying that `lagId`. A port marked `operation: AGGREGATING` therefore isn't
the only source: a member is listed even if its own record is missing or
incomplete. An aggregating port with no `lagSetting` is shown under
"LAG (group unknown)".

**Mode** (`lagType`): 1 Static, 2 LACP, 3 LACP (Active), 4 LACP (Passive).

The Markdown has one row per LAG (device, LAG ID, name, mode, member ports,
link: up/down with speed for stacks, or "x/y members up", profile, M-LAG),
then a member-port table for each LAG, the M-LAG groups, and the site hash
algorithm. In `device_ports`, the Operation column of an aggregating port
names its group, e.g. `Aggregating (LAG 1)`.

---

### Switch Settings (`switch_settings`)

| Part | Method | Endpoint | Notes |
| --- | --- | --- | --- |
| `site.jumbo` | `GET` | `sites/{siteId}/jumbo` | Site jumbo frame size (1518–9216 bytes) |
| `site.lldp` | `GET` | `sites/{siteId}/lldp` | Site LLDP |
| `switches[].general` | `GET` | `sites/{siteId}/switches/{switchMac}/general-config` | LED, jumbo override, LAG-hash override, SNMP location / contact, SDM template (GPS location dropped) |
| `switches[].networks` | `GET` | `sites/{siteId}/switches/{switchMac}/networks` | Paginated. VLAN interfaces; `mvlan` marks the **management VLAN**; static / DHCP addressing, MTU, DHCP mode |
| `switches[].rpvst` | `GET` | `sites/{siteId}/switches/{switchMac}/rpvst-instances` | Per-VLAN STP priority (untyped in the spec; common wrappers accepted) |

Every part is best-effort.

**Derived from other resources** (no extra API calls):

- **Loop prevention / STP per switch:** each switch port (`device_ports`) is
  matched to its profile (`switch_port_profiles`, by ID, then by name). The
  table counts ports with STP, port-based loopback detection, and VLAN-based
  loopback detection. Ports with an unknown profile, and ports with a profile
  override (whose own settings may differ), are reported separately.
- **IGMP snooping:** the per-network `igmpSnoopEnable` from `networks`.
  Snooping details (querier, unknown multicast, …) are in
  `multicast_services`.

**Not available through the Open API:** the switch-wide STP mode
(STP / RSTP / MSTP / RPVST) and bridge priority, and site loopback control,
can be set but not read. The Markdown says so instead of leaving a blank.

