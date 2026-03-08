"""Resource registry: single source of truth for all Omada resource types.

Each :class:`ResourceDefinition` describes one resource category:

* **name** – snake_case identifier used as file stem (``acl_rules``, …)
* **title** – human-readable Markdown heading
* **fetch_method** – method name on :class:`~omada.api.openapi_client.OmadaOpenApiClient`
* **row_formatter** – callable that converts raw API/YAML data to a list of
  display-row dicts (used by :class:`~omada.exporters.markdown_generator.MarkdownGenerator`)
* **sort_key** – column header to sort rows by; ``""`` disables sorting

Adding a new resource category requires only:

1. A new ``get_*`` method on ``OmadaOpenApiClient``
2. A new :class:`ResourceDefinition` appended to :data:`RESOURCES`

No other files need to be modified.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable


# ---------------------------------------------------------------------------
# Dataclass
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ResourceDefinition:
    """Describes a single Omada resource category."""

    name: str
    title: str
    fetch_method: str
    row_formatter: Callable[..., list[dict[str, Any]]]
    sort_key: str = "Name"
    needs_context: bool = False


# ---------------------------------------------------------------------------
# Row-formatter functions
# ---------------------------------------------------------------------------

_PROTO_MAP: dict[int, str] = {
    1: "ICMP", 6: "TCP", 17: "UDP", 256: "All",
}

_POLICY_MAP: dict[int, str] = {0: "Deny", 1: "Permit"}

_SOURCE_TYPE_MAP: dict[int, str] = {0: "Network", 1: "IP Group", 2: "IP-Port Group"}

_PROFILE_TYPE_MAP: dict[int, str] = {0: "Trunk", 1: "Disabled", 2: "Access"}

_PROTO_TYPE_MAP: dict[int, str] = {1: "DHCP", 2: "Static", 3: "PPPoE"}


def _flatten(value: Any) -> str:
    """Convert a value to a display string, handling dicts and lists."""
    if value is None:
        return ""
    if isinstance(value, dict):
        return value.get("name", value.get("ip", str(value)))
    if isinstance(value, list):
        return ", ".join(_flatten(v) for v in value)
    return str(value)


def _format_ip_entry(entry: Any) -> str:
    """Format an ipList entry (dict with ip/mask/description or plain str)."""
    if isinstance(entry, dict):
        ip = entry.get("ip", "")
        mask = entry.get("mask", "")
        if mask:
            try:
                if int(mask) != 32:
                    return f"{ip}/{mask}"
            except (ValueError, TypeError):
                return f"{ip}/{mask}"
        return ip
    return str(entry)


def _format_protocols(protocols: Any) -> str:
    """Convert a list of protocol numbers to readable names."""
    if isinstance(protocols, list):
        return ", ".join(_PROTO_MAP.get(p, str(p)) for p in protocols)
    if isinstance(protocols, (int, str)):
        v = int(protocols) if isinstance(protocols, str) and protocols.isdigit() else protocols
        return _PROTO_MAP.get(v, str(v)) if isinstance(v, int) else str(v)
    return ""


def _parse_subnet(gw_subnet: str) -> tuple[str, str]:
    """Split 'x.x.x.x/prefix' into (subnet, prefix_len)."""
    if "/" in str(gw_subnet):
        parts = str(gw_subnet).split("/", 1)
        return parts[0], parts[1]
    return str(gw_subnet), ""


def _build_id_lookup(context: dict[str, Any] | None) -> dict[str, str]:
    """Build a combined ID → name lookup from networks, IP groups, and port groups."""
    lookup: dict[str, str] = {}
    if not context:
        return lookup
    for net in (context.get("networks") or []):
        if isinstance(net, dict):
            net_id = net.get("id", "")
            if net_id:
                lookup[net_id] = net.get("name", net_id)
    for grp in (context.get("ip_groups") or []):
        if isinstance(grp, dict):
            grp_id = grp.get("groupId", grp.get("id", ""))
            if grp_id:
                lookup[grp_id] = grp.get("name", grp_id)
    for grp in (context.get("port_groups") or []):
        if isinstance(grp, dict):
            grp_id = grp.get("groupId", grp.get("id", ""))
            if grp_id:
                lookup[grp_id] = grp.get("name", grp_id)
    return lookup


def _resolve_ids(ids: list[str], lookup: dict[str, str]) -> str:
    """Resolve a list of IDs to a comma-separated string of names."""
    if not ids:
        return ""
    return ", ".join(lookup.get(i, i) for i in ids)


def _acl_rule_rows(data: Any, context: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    items = data if isinstance(data, list) else []
    lookup = _build_id_lookup(context)
    rows = []
    for r in items:
        policy_raw = r.get("policy", "")
        policy = _POLICY_MAP.get(policy_raw, policy_raw) if isinstance(policy_raw, int) else policy_raw

        src_type_raw = r.get("sourceType", r.get("srcType", ""))
        src_type = _SOURCE_TYPE_MAP.get(src_type_raw, src_type_raw) if isinstance(src_type_raw, int) else src_type_raw

        dst_type_raw = r.get("destinationType", r.get("dstType", ""))
        dst_type = _SOURCE_TYPE_MAP.get(dst_type_raw, dst_type_raw) if isinstance(dst_type_raw, int) else dst_type_raw

        rows.append({
            "Description": r.get("description", r.get("name", "")),
            "Status": "Enabled" if r.get("status", True) else "Disabled",
            "Policy": policy,
            "Protocols": _format_protocols(r.get("protocols", r.get("protocol", ""))),
            "Source": _resolve_ids(r.get("sourceIds", []), lookup),
            "Source Type": src_type,
            "Destination": _resolve_ids(r.get("destinationIds", []), lookup),
            "Destination Type": dst_type,
            "ACL Type": r.get("aclType", ""),
        })
    return rows


def _ip_group_rows(data: Any) -> list[dict[str, Any]]:
    items = data if isinstance(data, list) else []
    return [
        {
            "Name": g.get("name", ""),
            "IPs / Subnets": ", ".join(
                _format_ip_entry(ip) for ip in g.get("ipList", [])
            ),
        }
        for g in items
    ]


def _port_group_rows(data: Any) -> list[dict[str, Any]]:
    items = data if isinstance(data, list) else []
    return [
        {
            "Name": g.get("name", ""),
            "Ports": ", ".join(str(p) for p in g.get("portList", [])),
        }
        for g in items
    ]


def _network_rows(data: Any) -> list[dict[str, Any]]:
    items = data if isinstance(data, list) else []
    rows = []
    for n in items:
        gw = n.get("gatewaySubnet", "")
        subnet, prefix = _parse_subnet(gw) if gw else ("", "")
        # Fall back to networkIp / prefixLen if present
        if not subnet:
            subnet = n.get("networkIp", "")
            prefix = n.get("prefixLen", "")
        gw_display = gw or (f"{subnet}/{prefix}" if subnet and prefix else subnet)
        dhcp_settings = n.get("dhcpSettings")
        dhcp_enabled = False
        if isinstance(dhcp_settings, dict):
            dhcp_enabled = dhcp_settings.get("enable", False)
        else:
            dhcp_enabled = n.get("dhcpEnable", False)
        rows.append({
            "Name": n.get("name", ""),
            "Purpose": n.get("purpose", ""),
            "Gateway / Subnet": gw_display,
            "VLAN ID": n.get("vlan", n.get("vlanId", "")),
            "DHCP": "Enabled" if dhcp_enabled else "Disabled",
        })
    return rows


def _vlan_rows(data: Any) -> list[dict[str, Any]]:
    items = data if isinstance(data, list) else []
    return [
        {
            "Name": n.get("name", ""),
            "VLAN ID": n.get("vlan", n.get("vlanId", "")),
            "Gateway / Subnet": n.get("gatewaySubnet", ""),
            "Purpose": n.get("purpose", ""),
        }
        for n in items
    ]


def _switch_port_profile_rows(data: Any, context: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    items = data if isinstance(data, list) else []
    lookup = _build_id_lookup(context)
    rows = []
    for p in items:
        type_raw = p.get("type", "")
        profile_type = _PROFILE_TYPE_MAP.get(type_raw, type_raw) if isinstance(type_raw, int) else type_raw

        poe_raw = p.get("poe", p.get("poeEnable", ""))
        if isinstance(poe_raw, bool):
            poe = "Enabled" if poe_raw else "Disabled"
        elif isinstance(poe_raw, int):
            poe = {0: "Disabled", 1: "Enabled", 2: "Use Device Setting"}.get(poe_raw, str(poe_raw))
        else:
            poe = str(poe_raw)

        tagged_ids = p.get("tagNetworkIds", p.get("taggedNetworkIds",
                     p.get("taggedVlans", [])))
        tagged = _resolve_ids(tagged_ids, lookup)

        rows.append({
            "Name": p.get("name", ""),
            "Type": profile_type,
            "Spanning Tree": "Enabled" if p.get("spanningTreeEnable") else "Disabled",
            "Loopback Detect": "Enabled" if p.get("loopbackDetectEnable") else "Disabled",
            "PoE": poe,
            "Tagged Networks": tagged,
        })
    return rows


def _gateway_rows(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, dict):
        items = [data]
    elif isinstance(data, list):
        items = data
    else:
        items = []

    # If the data is in the Open API format with wanPortsConfig
    if items and isinstance(items[0], dict) and "wanPortsConfig" not in items[0]:
        # Legacy flat format
        return [
            {
                "WAN Mode": r.get("wanMode", ""),
                "WAN1 IP": r.get("wan1Ip", ""),
                "WAN1 Type": r.get("wan1Type", ""),
                "WAN2 IP": r.get("wan2Ip", ""),
                "WAN2 Type": r.get("wan2Type", ""),
                "Load Balancing": "Enabled" if r.get("loadBalance") else "Disabled",
            }
            for r in items
            if isinstance(r, dict)
        ]

    # Open API format — extract WAN port details
    rows = []
    for item in items:
        if not isinstance(item, dict):
            continue
        wan_ports = item.get("wanPortsConfig", [])
        for wp in wan_ports:
            port_name = wp.get("portName", "")
            ipv4 = wp.get("wanPortIpv4Setting", {})
            proto_type = ipv4.get("protoType", "")
            proto = _PROTO_TYPE_MAP.get(proto_type, proto_type) if isinstance(proto_type, int) else proto_type
            mac_setting = wp.get("wanPortMacSetting", {})
            rows.append({
                "Port": port_name,
                "Type": proto,
                "MAC": mac_setting.get("mac", ""),
                "IPv6": "Enabled" if wp.get("wanPortIpv6Setting", {}).get("enable") else "Disabled",
            })
    return rows


# Band bits: 1=2.4GHz, 2=5GHz, 4=6GHz  (7=all, 3=2.4+5, etc.)
_BAND_MAP: dict[int, str] = {
    1: "2.4 GHz",
    2: "5 GHz",
    3: "2.4 GHz / 5 GHz",
    4: "6 GHz",
    5: "2.4 GHz / 6 GHz",
    6: "5 GHz / 6 GHz",
    7: "2.4 GHz / 5 GHz / 6 GHz",
}

_SECURITY_MAP: dict[int, str] = {
    0: "None",
    1: "WEP",
    2: "WPA",
    3: "WPA2",
    4: "WPA/WPA2",
    5: "WPA3",
    6: "WPA2/WPA3",
}


def _ssid_rows(data: Any) -> list[dict[str, Any]]:
    items = data if isinstance(data, list) else []
    return [
        {
            "WLAN": s.get("wlanName", ""),
            "SSID": s.get("name", s.get("ssid", "")),
            "Security": _SECURITY_MAP.get(s.get("security"), str(s.get("security", ""))),
            "Band": _BAND_MAP.get(s.get("band"), str(s.get("band", ""))),
            "Broadcast": "Yes" if s.get("broadcast", True) else "No",
            "VLAN": s.get("vlanId", s.get("vlan", "")),
            "Guest": "Yes" if s.get("guestNetEnable") else "No",
        }
        for s in items
    ]


def _dhcp_reservation_rows(data: Any) -> list[dict[str, Any]]:
    items = data if isinstance(data, list) else []
    return [
        {
            "Network": r.get("netName", r.get("networkName", "")),
            "IP Address": r.get("ip", ""),
            "MAC Address": r.get("mac", ""),
            "Name": r.get("name", r.get("clientName", "")),
            "Status": "Enabled" if r.get("status") else "Disabled",
            "Server": r.get("serverName", ""),
        }
        for r in items
    ]


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

RESOURCES: list[ResourceDefinition] = [
    ResourceDefinition(
        name="acl_rules",
        title="ACL Rules",
        fetch_method="get_acl_rules",
        row_formatter=_acl_rule_rows,
        sort_key="Description",
        needs_context=True,
    ),
    ResourceDefinition(
        name="ip_groups",
        title="IP Groups",
        fetch_method="get_ip_groups",
        row_formatter=_ip_group_rows,
        sort_key="Name",
    ),
    ResourceDefinition(
        name="port_groups",
        title="Port Groups",
        fetch_method="get_port_groups",
        row_formatter=_port_group_rows,
        sort_key="Name",
    ),
    ResourceDefinition(
        name="networks",
        title="Networks",
        fetch_method="get_networks",
        row_formatter=_network_rows,
        sort_key="Name",
    ),
    ResourceDefinition(
        name="vlans",
        title="VLANs",
        fetch_method="get_vlans",
        row_formatter=_vlan_rows,
        sort_key="Name",
    ),
    ResourceDefinition(
        name="switch_port_profiles",
        title="Switch Port Profiles",
        fetch_method="get_switch_port_profiles",
        row_formatter=_switch_port_profile_rows,
        sort_key="Name",
        needs_context=True,
    ),
    ResourceDefinition(
        name="gateway_settings",
        title="Gateway Settings",
        fetch_method="get_gateway_settings",
        row_formatter=_gateway_rows,
        sort_key="",  # typically a single row; sorting not meaningful
    ),
    ResourceDefinition(
        name="ssids",
        title="SSIDs",
        fetch_method="get_ssids",
        row_formatter=_ssid_rows,
        sort_key="SSID",
    ),
    ResourceDefinition(
        name="dhcp_reservations",
        title="DHCP Reservations",
        fetch_method="get_dhcp_reservations",
        row_formatter=_dhcp_reservation_rows,
        sort_key="Hostname",
    ),
]

#: Fast lookup by resource name.
REGISTRY: dict[str, ResourceDefinition] = {r.name: r for r in RESOURCES}
