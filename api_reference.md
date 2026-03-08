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
| 1. Login | `POST` | `/openapi/authorize/login?client_id={clientId}` | Username and password in JSON body; returns authorization code |
| 2. Exchange code | `POST` | `/openapi/authorize/token?grant_type=authorization_code` | Authorization code, Client ID, and Secret in JSON body |

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
