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

A two-step process: first fetch all WLANs, then fetch SSIDs for each WLAN.

| Step | Method | Endpoint | Notes |
| --- | --- | --- | --- |
| 1. List WLANs | `GET` | `sites/{siteId}/wireless-network/wlans` | Paginated |
| 2. List SSIDs | `GET` | `sites/{siteId}/wireless-network/wlans/{wlanId}/ssids` | Paginated; called per WLAN |

Each SSID is enriched with the parent WLAN's `name` as `wlanName`.

> **API docs:** Documented under the [Wireless Network](https://use1-omada-northbound.tplinkcloud.com/doc.html#/Wireless%20Network) tag —
> *Get WLAN group list*, *Get SSID list*.

---

### DHCP Reservations

| Method | Endpoint | Notes |
| --- | --- | --- |
| `GET` | `sites/{siteId}/setting/service/dhcp` | Paginated |

> **API docs:** Documented under the [Service](https://use1-omada-northbound.tplinkcloud.com/doc.html#/Service) tag —
> *Get DHCP Reservation List*.

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
