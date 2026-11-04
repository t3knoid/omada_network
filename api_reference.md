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

---

## Conventions

- **Paths.** Endpoints below are relative to `/openapi/v1/{omadacId}/` unless a
  version (`v2`) is shown. `{siteId}` is resolved from the site name during
  discovery.
- **Output.** Each resource is written to `docs/<site>/<resource>.yaml` (the raw
  API data, source of truth) and `docs/<site>/<resource>.md` (formatted
  tables). Many Markdown files start with a summary table, followed by one
  detail section per item.
- **Best-effort parts.** Resources built from several endpoints treat
  secondary endpoints as optional: a failing endpoint is logged and left out,
  and the rest of the resource is still exported. A resource fails (and is
  reported in the run summary) only when its primary endpoint, or every one
  of its endpoints, fails. A failed resource is written as an empty file.
- **Read-only POST.** `POST sites/{siteId}/switches/ports/select` is a query
  that takes its filter in the body; nothing on the controller is modified.
  Every other call is a `GET`.
- **Codes and names.** Numeric codes are translated to labels as defined in
  the Open API schemas, and IDs are resolved to names (networks, profiles,
  WAN ports, devices) using the other exported resources. Unknown codes and
  IDs are shown as-is.
- **Secrets.** Any non-empty string whose field name looks like a credential
  (password, pwd, secret, token, security key, pre-shared key, private key)
  is replaced with `<redacted>` before anything is written, both in the client
  and again for every resource in `OmadaService.fetch_all`
  (`omada/redaction.py`). The Markdown then shows `Configured` / `Not set`.
  `--include-secrets` (or the web UI checkbox) exports the real values. Every
  Markdown file containing one then gets a warning banner.
- **Not readable through the Open API.** Some settings can be written but not
  read: the switch-wide STP mode and bridge priority, site loopback control,
  and the WAN health-check (online detection) targets. The relevant sections
  note this.

---

## Resource Index

| Resource (file name) | Markdown title | Section |
| --- | --- | --- |
| `devices` | Devices | [Devices](#devices) |
| `device_ports` | Device Ports | [Device Ports](#device-ports) |
| `port_schedules` | PoE & Port Schedules | [PoE & Port Schedules](#poe--port-schedules) |
| `switch_port_profiles` | Switch Port Profiles | [Switch Port Profiles](#switch-port-profiles) |
| `lags` | Link Aggregation (LAGs) | [Link Aggregation](#link-aggregation) |
| `switch_settings` | Switch Settings | [Switch Settings](#switch-settings) |
| `uplinks` | Uplinks & Stacks | [Uplinks & Stacks](#uplinks--stacks) |
| `switch_port_sheets` | Switch Port Sheets | [Switch Port Sheets](#switch-port-sheets) |
| `switch_security` | Switch Security (802.1X, DHCP Snooping, ARP Detection, IP-MAC Binding) | [Switch Security](#switch-security) |
| `oui_vlans` | OUI-Based VLANs | [OUI-Based VLANs](#oui-based-vlans) |
| `switch_qos` | Switch QoS | [Switch QoS](#switch-qos) |
| `port_labels` | Switch Port Labels | [Switch Port Labels](#switch-port-labels) |
| `networks` | Networks | [Networks](#networks) |
| `vlans` | VLANs | [VLANs](#vlans) |
| `dhcp_scopes` | DHCP Scopes | [DHCP Scopes](#dhcp-scopes) |
| `dhcp_reservations` | DHCP Reservations | [DHCP Reservations](#dhcp-reservations) |
| `dhcp_leases` | DHCP Leases | [DHCP Leases](#dhcp-leases) |
| `ip_groups` | IP Groups | [IP Groups](#ip-groups) |
| `port_groups` | Port Groups | [Port Groups (IP-Port Groups)](#port-groups-ip-port-groups) |
| `acl_rules` | ACL Rules | [ACL Rules](#acl-rules) |
| `gateway_settings` | Gateway Settings | [Gateway Settings](#gateway-settings) |
| `gateway_port_sheets` | Gateway Port Sheets | [Gateway Port Sheets](#gateway-port-sheets) |
| `wan_failover` | WAN Failover & Load Balancing | [WAN Failover & Load Balancing](#wan-failover--load-balancing) |
| `port_forwarding` | Port Forwarding | [NAT](#nat) |
| `one_to_one_nat` | One-to-One NAT | [NAT](#nat) |
| `alg` | ALG | [NAT](#nat) |
| `static_routes` | Static Routes | [Static Routes](#static-routes) |
| `policy_routes` | Policy Routes | [Policy Routes](#policy-routes) |
| `dns_settings` | DNS | [DNS](#dns) |
| `time_settings` | Time & NTP | [Time & NTP](#time--ntp) |
| `multicast_services` | Multicast, Bonjour & UPnP | [Multicast, Bonjour & UPnP](#multicast-bonjour--upnp) |
| `ssids` | SSIDs | [SSIDs](#ssids) |
| `radius_profiles` | RADIUS Profiles | [RADIUS Profiles](#radius-profiles) |
| `portals` | Guest Portals | [Guest Portals](#guest-portals) |
| `time_range_profiles` | Schedules (Time Range Profiles) | [Schedules and Rate Limit Profiles](#schedules-and-rate-limit-profiles) |
| `rate_limit_profiles` | Rate Limit Profiles | [Schedules and Rate Limit Profiles](#schedules-and-rate-limit-profiles) |
| `wireless_settings` | Wireless Site Settings | [Wireless Site Settings](#wireless-site-settings) |
| `ap_radios` | AP Radio Settings | [AP Radio Settings](#ap-radio-settings) |
| `ap_sheets` | Access Point Sheets | [Access Point Sheets](#access-point-sheets) |
| `site_to_site_vpns` | Site-to-Site VPNs | [Site-to-Site, Remote-Access & WireGuard VPN](#site-to-site-remote-access--wireguard-vpn) |
| `remote_access_vpns` | Remote-Access VPNs | [Site-to-Site, Remote-Access & WireGuard VPN](#site-to-site-remote-access--wireguard-vpn) |
| `wireguard` | WireGuard VPN | [Site-to-Site, Remote-Access & WireGuard VPN](#site-to-site-remote-access--wireguard-vpn) |
| `vpn_users` | VPN Users | [Site-to-Site, Remote-Access & WireGuard VPN](#site-to-site-remote-access--wireguard-vpn) |
| `ssl_vpn` | SSL VPN Server | [SSL VPN Server](#ssl-vpn-server) |
| `eogre_tunnel` | EoGRE Tunnel | [EoGRE Tunnel](#eogre-tunnel) |
| `ipsec_failover` | IPsec Failover | [IPsec Failover](#ipsec-failover) |

---

## Devices & Switching

### Devices

**Resource:** `devices`

Returns the adopted devices for the selected site.

| Method | Endpoint | Notes |
| --- | --- | --- |
| `GET` | `sites/{siteId}/devices` | Paginated |

> **API docs:** See the [Device](https://use1-omada-northbound.tplinkcloud.com/doc.html#/Device) tag.

### Device Ports

**Resource:** `device_ports`

Port configuration for every switch and gateway in the site, exported as one
record per port. Each record is tagged with `deviceName`, `deviceMac`,
`deviceType`, and `deviceModel`. Other device types (e.g. access points) are
skipped.

| Device type | Method | Endpoint | Notes |
| --- | --- | --- | --- |
| — | `GET` | `sites/{siteId}/devices` | Device list (paginated) |
| Switch | `GET` | `sites/{siteId}/switches/ports/overview` | One site-wide paginated call: label, connection, type, operation, profile, native network |
| Switch (fallback) | `GET` | `sites/{siteId}/switches/{switchMac}` | `portList`; used only for switches missing from the overview |
| Switch (full config) | `POST` | `sites/{siteId}/switches/ports/select` | Read-only query, body `{"selectAll": true, "switchList": []}`. Full per-port config merged into each switch port; best-effort |
| Switch (schedules) | `GET` | `sites/{siteId}/poe-schedules`, `sites/{siteId}/port-schedules` | Adds `poeSchedules` / `portSchedules` (schedule names) to member ports |
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

#### Per-port overrides

The port overview only has profile, PoE,
speed/duplex, native network and tag mode. Each switch port is therefore
merged with its full configuration from `switches/ports/select`, and then
compared with its assigned profile (`switch_port_profiles`, matched by ID,
then name). Compared settings: PoE, 802.1X, bandwidth control, rate limit,
storm control, port isolation, voice network / VLAN / DSCP, loopback
detection (port and VLAN based), STP, LLDP-MED, topology notification, EEE,
flow control, IGMP / MLD fast leave, DHCP L2 relay, 802.1p priority, trust
mode, network tags setting, and native / untagged / tagged networks
(compared as sets). Settings with no profile equivalent are always listed
as port-level: fixed speed or duplex, mirroring, disabled ports, and PoE /
port schedule membership. The controller's `networkConflict` flag is
reported too.

`device_ports.md` gains an **Overrides** column and a **Ports differing
from their profile** table (setting, port value, profile value, and whether
the port is in custom-settings / custom-VLAN mode). A profile PoE of "use
device setting" isn't counted as a difference. Rate limit and storm
control are compared only when both sides use that control type.

If the full-config call fails, ports keep their overview data. Only the
settings present there (PoE, speed/duplex, native network, tag mode) are
compared.

### PoE & Port Schedules

**Resource:** `port_schedules`

| Part | Method | Endpoint | Notes |
| --- | --- | --- | --- |
| `poeSchedules` | `GET` | `sites/{siteId}/poe-schedules` | Paginated, best-effort. PoE powered only during the time range; `poePortsMap` = switch MAC → ports |
| `portSchedules` | `GET` | `sites/{siteId}/port-schedules` | Paginated, best-effort. Port enabled only during the time range; `portsMap` = switch MAC → ports |

The Markdown lists each schedule's type, status, time range (by name from
`time_range_profiles`), and the switch ports it covers. Each member port is
also tagged in `device_ports` and shows up there as a port-level override.

### Switch Port Profiles

**Resource:** `switch_port_profiles`

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

### Link Aggregation

**Resource:** `lags`

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

### Switch Settings

**Resource:** `switch_settings`

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

### Uplinks & Stacks

**Resource:** `uplinks`

| Part | Method | Endpoint | Notes |
| --- | --- | --- | --- |
| `switches[]` | `GET` | `sites/{siteId}/switches/ports/switch-detail` | Per switch: `uplink`, `downlinks` (`downlinkList`), `stackMsg` |
| Fallback | `POST` | `sites/{siteId}/switches/ports/select` | Read-only; only for switches missing from switch-detail |
| `stacks[]` | `GET` | `sites/{siteId}/stacks` | Paginated. Members: unit, priority, role (master / member), stack port groups, uplink, downlinks; runtime stats dropped |

All parts are best-effort.

A link's **local port** is the port on this switch: `port`, `stPort` for
stacks (`unit/slot/port`), or `lagId`, shown as `LAG n`. The remote device is
`name` / `type` / `model`, and its port is `linkPeerPortInfo`. Speeds use the
port-status codes (1 10M, 2 100M, 3 1000M, 4 10G).

The Markdown has a summary row per switch (uplink port, upstream device and
port, speed, downlink count, stack unit), a downlink table per switch, and a
member table per stack. It ends with a **Remapping checklist** listing every
port whose role depends on the hardware: uplink ports / LAGs, downlink ports,
stack port groups, and LAG members (from `lags`). On a different switch model
those port numbers may not exist or may mean something else (e.g. SFP vs.
copper), so each one needs a deliberate mapping.


### Switch Port Sheets

**Resource:** `switch_port_sheets`

| Method | Endpoint | Notes |
| --- | --- | --- |
| `GET` | `sites/{siteId}/devices` | Switch list only; the sheet is built from other resources |

A per-switch record of every port, meant for manually reconfiguring a
replacement switch, especially one with fewer ports. Built at Markdown time
from `device_ports` (full port config), `switch_port_profiles`, `uplinks`, and
`networks`, so it also regenerates from YAML.

**Summary** (one row per switch): ports, connected, ports with custom
settings, **Must Carry Over**, and how many of those are SFP / Combo or
powering PoE devices.

**Per switch** (one row per port):

| Column | Source |
| --- | --- |
| Name, Label, Type | Port name, label, Copper / Combo / SFP |
| Connection | `connectedStatus`; speed only when `portStatus` reports link up |
| Connected To | Uplink / downlink device and peer port, from `uplinks` (LAG links included) |
| Profile, Native VLAN, Untagged, Tagged | Port values, falling back to the profile's; tags show `All` / `None (blocked)` for allow-all / block-all |
| PoE, Speed / Duplex, LAG | Port configuration; PoE `n/a` on non-PoE ports |
| Set Manually (differs from profile) | The per-port overrides (see [Device Ports](#device-ports)) |
| Port-Bound Rules | Site rules that select this port: DHCP snooping / ARP detection ports ([Switch Security](#switch-security)), OUI-VLAN rules and QoS rules bound to custom ports. LAG selections are expanded to member ports. Rules covering *all* ports of a switch are not repeated per port |
| Carry Over | Why the port matters: connected, uplink, downlink, LAG, custom settings, port rules, named / labelled. Otherwise `No (unused, default)` |

The sheet reflects the last export. For an exact record, run `fetch` just
before replacing a switch.


### Switch Security

**Resource:** `switch_security`

| Part | Method | Endpoint | Notes |
| --- | --- | --- | --- |
| `dot1x` | `GET` | `sites/{siteId}/dot1x` | Switch 802.1X: RADIUS profile, PAP / EAP, port / MAC based, VLAN assignment, MAB, MAC format, NAS ID, guest VLAN |
| `macAuth` | `GET` | `sites/{siteId}/mac-auth` | MAC-based authentication for SSIDs: RADIUS profile, MAB, MAC format |
| `dhcpSnoopStatus`, `dhcpSnoops` | `GET` | `sites/{siteId}/dhcpSnoops/status`, `sites/{siteId}/dhcpSnoops` | Global switch, and per switch the **selected ports** (paginated) |
| `arpDetectStatus`, `arpDetects` | `GET` | `sites/{siteId}/arpDetects/status`, `sites/{siteId}/arpDetects` | Global switch, "use DHCP snooping entries", and per switch the selected ports and IP-MAC bindings (paginated) |
| `ipMacBind`, `ipMacBinds` | `GET` | `sites/{siteId}/ip-mac-bind`, `sites/{siteId}/ip-mac-binds` | IP-MAC binding general setting (LANs, WANs, gratuitous ARP) and the binding list (paginated) |

Each part is best-effort. The per-port 802.1X *mode* is part of the port
configuration (see [Device Ports](#device-ports)). The spec doesn't say
whether DHCP snooping / ARP detection "selected ports" are the trusted or the
monitored ports, so the export uses the controller's wording.

### OUI-Based VLANs

**Resource:** `oui_vlans`

| Part | Method | Endpoint | Notes |
| --- | --- | --- | --- |
| `rules` | `GET` | `sites/{siteId}/switch-oui-rules` | Paginated. Name, enabled, scope (all device ports / custom ports), target switches / ports / LAGs, OUI profile → VLAN + priority |
| `profiles` | `GET` | `sites/{siteId}/oui-profiles` | Paginated. OUI profiles and their OUIs |

### Switch QoS

**Resource:** `switch_qos`

| Part | Method | Endpoint | Notes |
| --- | --- | --- | --- |
| `mode` | `GET` | `sites/{siteId}/switch-qos/qos-mode` | QoS profiles (legacy) vs. QoS rules |
| `rules` | `GET` | `sites/{siteId}/switch-qos/qos-rule` | Paginated. Index, type (network / port / custom), match (networks, protocol, DSCP, ports), queue, DSCP remark, target switch ports (`unit/slot/port`) |
| `dscpMapping` | `GET` | `sites/{siteId}/switch-qos/qos-rule/dscp-mapping` | Queue → DSCP values |
| `schedulerMapping` | `GET` | `sites/{siteId}/switch-qos/qos-rule/scheduler-mapping` | Queue scheduler type and weight, shown as returned (codes undocumented) |

### Switch Port Labels

**Resource:** `port_labels`

| Method | Endpoint | Notes |
| --- | --- | --- |
| `GET` | `sites/{siteId}/switches/port-tag` | Label definitions; ports reference them by ID and show the label name |

---

## LAN & Addressing

### Networks

**Resource:** `networks`

| Method | Endpoint | Notes |
| --- | --- | --- |
| `GET` | `sites/{siteId}/lan-networks/all` | Primary — returns all LAN networks |
| `GET` | `sites/{siteId}/lan-networks` | Fallback — paginated |

> **API docs:** Documented under the [Wired Network](https://use1-omada-northbound.tplinkcloud.com/doc.html#/Wired%20Network) tag —
> *Get all networks for the omada id and site id*, *Get LAN network list*.

### VLANs

**Resource:** `vlans`

VLANs are derived from the Networks endpoint by filtering for entries that
contain a `vlan` or `vlanId` field. If no entries match, the full network
list is returned.

| Method | Endpoint | Notes |
| --- | --- | --- |
| — | — | Uses `get_networks()` internally (see Networks above) |

> **API docs:** See Networks above — same [Wired Network](https://use1-omada-northbound.tplinkcloud.com/doc.html#/Wired%20Network) tag.

### DHCP Scopes

**Resource:** `dhcp_scopes`

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

### DHCP Reservations

**Resource:** `dhcp_reservations`

| Method | Endpoint | Notes |
| --- | --- | --- |
| `GET` | `sites/{siteId}/setting/service/dhcp` | Paginated |

Rows are sorted by network, then numerically by IP, and include the
reservation description and any per-reservation DHCP options.

> **API docs:** Documented under the [Service](https://use1-omada-northbound.tplinkcloud.com/doc.html#/Service) tag —
> *Get DHCP Reservation List*.

### DHCP Leases

**Resource:** `dhcp_leases`

| Method | Endpoint | Notes |
| --- | --- | --- |
| `GET` | `sites/{siteId}/setting/service/dhcp/user-list` | Paginated; leases from every DHCP server in the site |

Network, IP, MAC, name, device/client type, binding (Dynamic / Static), lease
time remaining, and serving device, sorted by network then IP. Leases are
runtime state: they change between runs and are not needed to recreate the
service.

---

## Security Groups & ACLs

### IP Groups

**Resource:** `ip_groups`

IP groups are profile groups with `groupType=0`.

| Method | Endpoint | Notes |
| --- | --- | --- |
| `GET` | `sites/{siteId}/profiles/groups/0` | Primary — returns only IP groups |
| `GET` | `sites/{siteId}/profiles/groups` | Fallback — returns all groups; filtered client-side by `type == 0` |

> **API docs:** Documented under the [Profiles](https://use1-omada-northbound.tplinkcloud.com/doc.html#/Profiles) tag —
> *Get group profile list by type* (`groupType=0`).

### Port Groups (IP-Port Groups)

**Resource:** `port_groups`

Port groups are profile groups with `groupType=1`.

| Method | Endpoint | Notes |
| --- | --- | --- |
| `GET` | `sites/{siteId}/profiles/groups/1` | Primary — returns only IP-Port groups |
| `GET` | `sites/{siteId}/profiles/groups` | Fallback — returns all groups; filtered client-side by `type == 1` |

> **API docs:** Documented under the [Profiles](https://use1-omada-northbound.tplinkcloud.com/doc.html#/Profiles) tag —
> *Get group profile list by type* (`groupType=1`).

### ACL Rules

**Resource:** `acl_rules`

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

## Gateway, WAN & Routing

### Gateway Settings

**Resource:** `gateway_settings`

Attempts multiple endpoints with fallback.

| Priority | Method | Endpoint | Notes |
| --- | --- | --- | --- |
| 1 | `GET` | `sites/{siteId}/internet/ports-config` | Most detailed |
| 2 | `GET` | `sites/{siteId}/internet/basic-info` | Basic internet info |
| 3 | `GET` | `sites/{siteId}/setting/virtual-wans` | Virtual WAN settings |

> **API docs:** Documented under the [Wired Network](https://use1-omada-northbound.tplinkcloud.com/doc.html#/Wired%20Network) tag —
> *Get internet wan ports config*, *Get internet basic info*, *Query virtual WAN list*.

### WAN Failover & Load Balancing

**Resource:** `wan_failover`

| Part | Method | Endpoint | Notes |
| --- | --- | --- | --- |
| `loadBalance` | `GET` | `sites/{siteId}/internet/load-balance` | Weights, link backup, primary / backup WANs, backup mode and trigger, schedule, application-optimized routing, virtual WAN weights |
| `internet` | `GET` | `sites/{siteId}/internet/basic-info` | WAN port list, and the online-detection (health check) interval: `0` = disabled |
| `wanHealth` | `GET` | `sites/{siteId}/gateways/{gatewayMac}/wan-status` | Per gateway: link, internet state, online detection, latency, packet loss, health level |

- **Backup trigger** (`mode`): 0 when any primary WAN fails, 1 when all fail, 2 on schedule (time range profile).
- **Backup mode** (`backupMode`): 0 stays on backup until it fails, 1 returns to primary when it recovers.
- **Weights** are listed "sorted by port ID". They are matched to the WAN-mode ports from `basic-info` in port-number order, and shown unlabelled if the counts differ.
- **Health checks:** the Open API exposes only the detection *interval*. The ping / DNS-lookup targets are not available. `wanHealth` is the status at export time, not configuration, so it changes between runs.

### Gateway Port Sheets

**Resource:** `gateway_port_sheets`

| Method | Endpoint | Notes |
| --- | --- | --- |
| `GET` | `sites/{siteId}/devices` | Gateway list only; the sheet is built from other resources |

Meant for replacing a gateway with another model. Gateway port IDs have the
form `<port number>_<uuid>`, so the sheet maps every ID back to a physical
port by its prefix. Built at Markdown time from `device_ports`,
`gateway_settings`, `wan_failover`, `networks`, `uplinks` and the resources
listed below, so it also regenerates from YAML.

**Summary** (one row per gateway): ports, WAN-mode ports, connected ports,
port-bound rules, ports that must carry over.

**Per gateway** (one row per port):

| Column | Source |
| --- | --- |
| Capability, Mode | Port `type` (0 WAN only, 1 WAN or LAN, 2 LAN only) and `mode` (0 WAN, 1 LAN); `Mirroring` when mirroring is on |
| Connection | Link state from `wan-status`; the controller reports it only for WAN ports |
| Connected To | A switch whose uplink peer is this gateway port (`uplinks`) |
| WAN Connection | `gateway_settings.wanPortsConfig`: type (`protoType` 0 Static, 1 DHCP, 2 PPPoE, 3 L2TP, 4 PPTP, 5 DS-Lite, 6 MAP-E), address, user, DNS, MTU, extra IPs, VLAN tag / priority, cloned MAC, IPv6 type |
| LAN Networks | Networks whose `interfaceIds` include this port; `All N LAN networks` when it carries all of them |
| PVID (Native VLAN), Speed / Duplex, Mirroring | Port configuration (`linkSpeed` 0 Auto, 1 10M, 2 100M, 3 1000M, 4 2500M, 5 10G, 6 5G) |
| Rules Bound, Carry Over | Count of checklist rows for this port; why the port matters (WAN, connected, downlink, rules, fixed speed, mirroring, PVID, disabled) |

**Connected switches:** switches uplinked to the gateway, with the gateway
port when the controller reports the link peer.

**Port reference checklist:** every setting that names a gateway port.

| Resource | Field |
| --- | --- |
| `networks` | `interfaceIds` (LAN ports) |
| `port_forwarding` | `interfaceWanPortId`, `wanIps[].wanId` |
| `one_to_one_nat` | `interfaceIds` |
| `static_routes` | `interfaceId` (gateway routes with WAN interface) |
| `policy_routes` | `interfaceId` (WAN), `wanPortIds` |
| `site_to_site_vpns`, `remote_access_vpns` | `wan` / `wans` |
| `ssl_vpn` | `setting.wanPort` |
| `ipsec_failover` | `backupWan` |
| `wan_failover` | `primaryWans`, `backupWan` (when link backup is on), per-WAN weights, virtual WAN `physicalWanId` |
| `dns_settings` | Dynamic DNS `interfacePortId` |
| `multicast_services` | IGMP / MLD proxy `wanPortId`, IPTV `wanPortId` and port roles, UPnP `wanPortIds` (enabled features only) |
| `switch_security` | IP-MAC binding `wanIds`, WAN bindings' `interfaceId` |

Not covered, because they aren't exported: gateway QoS bandwidth control
(`wan`) and virtual WAN definitions.

### NAT

**Resources:** `port_forwarding`, `one_to_one_nat`, `alg`

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

### Static Routes

**Resource:** `static_routes`

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

### Policy Routes

**Resource:** `policy_routes`

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

## Site Services

### DNS

**Resource:** `dns_settings`

| Part | Method | Endpoint | Notes |
| --- | --- | --- | --- |
| `dnsProxy` | `GET` | `sites/{siteId}/setting/service/dns-proxy` | DNSSEC (servers, bogus-reply policy), DoH / DoT (preset and custom servers), DNS Override (servers, networks) |
| `dnsCache` | `GET` | `sites/{siteId}/setting/service/dns-cache` | Enabled, TTL |
| `lanDns` | `GET` | `sites/{siteId}/setting/lan/dns` | Paginated. Local records: IP (A/AAAA), CNAME, or forward; aliases, networks, TTL |
| `ddns` | `GET` | `sites/{siteId}/setting/service/ddns` | Paginated. Provider, domain, interface, username, interval, custom URL; password redacted |

### Time & NTP

**Resource:** `time_settings`

| Part | Method | Endpoint | Notes |
| --- | --- | --- | --- |
| `site` | `GET` | `sites/{siteId}` | Only `timeZone`, `ntpServers`, `region`, `name`, `scenario` are kept |
| `dst` | `GET` | `sites/{siteId}/dst-info` | DST mode (disabled / automatic / manual), offset, start / end |
| `ntpStatus` | `GET` | `sites/{siteId}/setting/ntp` | Gateway NTP server status; returned as-is (untyped in the spec) |

### Multicast, Bonjour & UPnP

**Resource:** `multicast_services`

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

## Wireless

### SSIDs

**Resource:** `ssids`

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

**Resource:** `radius_profiles`

| Method | Endpoint | Notes |
| --- | --- | --- |
| `GET` | `sites/{siteId}/profiles/radius` | Auth / accounting servers (with RadSec), interim updates, VLAN assignment, CoA, Message-Authenticator, built-in server |

Auth, accounting, CoA, and built-in server secrets are redacted.

### Guest Portals

**Resource:** `portals`

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

**Resources:** `time_range_profiles`, `rate_limit_profiles`

| Resource | Method | Endpoint | Notes |
| --- | --- | --- | --- |
| `time_range_profiles` | `GET` | `sites/{siteId}/time-range-profiles` | Day mode (every day / weekdays / weekends / custom days) and time slots |
| `rate_limit_profiles` | `GET` | `sites/{siteId}/rate-limit-profiles` | Download / upload limit (Kbps), default profile |

SSIDs reference both by ID; the SSID tables show their names.

### Wireless Site Settings

**Resource:** `wireless_settings`

| Method | Endpoint | Stored as |
| --- | --- | --- |
| `GET` | `sites/{siteId}/band-steering` | `bandSteering` (Disabled / Prefer 5GHz/6GHz / Balance) |
| `GET` | `sites/{siteId}/roaming` | `roaming` (fast, AI, non-stick roaming) |
| `GET` | `sites/{siteId}/mesh` | `mesh` (mesh, auto failover, connectivity detection, full-sector DFS) |
| `GET` | `sites/{siteId}/multicast-rate-limit` | `multicastRateLimit` (per-protocol packets per second) |

Each part is best-effort; the resource fails only if all four fail.

### AP Radio Settings

**Resource:** `ap_radios`

| Method | Endpoint | Notes |
| --- | --- | --- |
| `GET` | `sites/{siteId}/aps/{apMac}/radio-config` | Per AP (`type: ap`); unavailable APs are logged and skipped |

One row per AP radio (2.4 GHz, 5 GHz, 5 GHz-1/-2, 6 GHz): radio on/off,
channel (`0` = Auto), channel width, Tx power level (custom power shown in
dBm), wireless mode, and channel limit. These are the per-AP radio overrides
configured on the controller.

### Access Point Sheets

**Resource:** `ap_sheets`

Per-AP settings that don't follow an AP to a new model. For every AP
(`type: ap`), each part is a `GET sites/{siteId}/aps/{apMac}/<path>`, kept
when available. A model that doesn't support a feature just has no entry.
Radios come from [`ap_radios`](#ap-radio-settings) and SSID overrides from
[`ssids`](#ssids) at Markdown time.

| Part | Path | Notes |
| --- | --- | --- |
| `general` | `general-config` | LED (0 off, 1 on, 2 site setting), name, tags |
| `ipSetting` | `ip-setting` | DHCP (reservation, fallback IP) or static IP, mask, gateway, DNS |
| `managementVlan` | `vlan` | 0 default, 1 custom (`lanNetworkId`) |
| `managementWlan` | `management-wlan` | Management SSID: status, name, security, VLAN. The key is redacted |
| `uplinkConfig` | `uplink-config` | Uplink port selection: auto or fixed |
| `wiredUplink` | `wired-uplink` | Upstream device, its port, AP port, rate. Counters are dropped |
| `wiredDownlinks` | `wired-downlink` | Devices on the AP's LAN ports. Counters are dropped |
| `lanPorts` | `ports` | LAN ports: link, VLAN (`localVlanEnable` / `localVlanId`, or custom tagged / untagged), PoE out, rate limits, uplink. `portStatus` counters are dropped |
| `portVlans` | `port-vlans` | Paginated. Effective VLAN membership per LAN port |
| `trunk` | `trunk-setting` | Link aggregation (mode 0 SRC+DST MAC, 1 DST MAC, 2 SRC MAC) |
| `loadBalance` | `load-balance` | Per band: max clients, RSSI threshold |
| `lldp` | `lldp` | 0 off, 1 on, 2 site setting |
| `powerSaving` | `power-saving` | Mode (0 off, 1 standard, 2 smart, 3 deep), time window, bands |
| `qos` | `qos` | U-APSD per band |
| `bridge` | `bridge` | P2P bridge SSID (password redacted), DIP switch |

**Summary** (one row per AP): bands, IP setting, management VLAN, uplink, LAN
ports (and how many carry over), SSID overrides, settings to carry over.

**Per AP:** a Category / Setting / Value table. **Carry Over** is `Yes` for
values set on this AP by hand: fixed channel or Tx power, static IP or
reservation / fallback, custom management VLAN, management SSID, SSID
overrides, fixed uplink port, LAG, bridge, and LED / LLDP / power saving /
load balancing / U-APSD changed from the defaults. Then a **LAN ports** table
(role, connection, connected device, VLAN, PoE out, rate limit, carry over)
and the effective **port VLANs**.

---

## VPN

### Site-to-Site, Remote-Access & WireGuard VPN

**Resources:** `site_to_site_vpns`, `remote_access_vpns`, `wireguard`, `vpn_users`

Pre-shared keys, user / client passwords, and WireGuard private / preshared keys are
redacted (see [Conventions](#conventions)); the Markdown shows `Configured` / `Not set`.

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

**Resource:** `ssl_vpn`

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

**Resource:** `eogre_tunnel`

| Method | Endpoint | Notes |
| --- | --- | --- |
| `GET` | `sites/{siteId}/vpn/gre-tunnel` | Single object: enabled, MTU, keepalive interval, max missed keepalives, primary / secondary gateway |

### IPsec Failover

**Resource:** `ipsec_failover`

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
