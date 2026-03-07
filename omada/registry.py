"""Resource registry: single source of truth for all Omada resource types.

Each :class:`ResourceDefinition` describes one resource category:

* **name** – snake_case identifier used as file stem (``acl_rules``, …)
* **title** – human-readable Markdown heading
* **fetch_method** – method name on :class:`~omada.api.client.OmadaClient`
* **row_formatter** – callable that converts raw API/YAML data to a list of
  display-row dicts (used by :class:`~omada.exporters.markdown_generator.MarkdownGenerator`)
* **sort_key** – column header to sort rows by; ``""`` disables sorting

Adding a new resource category requires only:

1. A new ``get_*`` method on ``OmadaClient``
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
    row_formatter: Callable[[Any], list[dict[str, Any]]]
    sort_key: str = "Name"


# ---------------------------------------------------------------------------
# Row-formatter functions
# ---------------------------------------------------------------------------

def _acl_rule_rows(data: Any) -> list[dict[str, Any]]:
    items = data if isinstance(data, list) else []
    return [
        {
            "Name": r.get("name", ""),
            "Status": "Enabled" if r.get("status", True) else "Disabled",
            "Policy": r.get("policy", ""),
            "Protocol": r.get("protocol", ""),
            "Source Type": r.get("srcType", ""),
            "Source": r.get("srcIp", r.get("srcIpGroup", "")),
            "Destination Type": r.get("dstType", ""),
            "Destination": r.get("dstIp", r.get("dstIpGroup", "")),
            "Port": r.get("dstPort", ""),
        }
        for r in items
    ]


def _ip_group_rows(data: Any) -> list[dict[str, Any]]:
    items = data if isinstance(data, list) else []
    return [
        {
            "Name": g.get("name", ""),
            "Type": g.get("type", ""),
            "IPs / Subnets": ", ".join(g.get("ipList", [])),
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
    return [
        {
            "Name": n.get("name", ""),
            "Purpose": n.get("purpose", ""),
            "Subnet": n.get("networkIp", ""),
            "Prefix Length": n.get("prefixLen", ""),
            "VLAN ID": n.get("vlanId", ""),
            "DHCP": "Enabled" if n.get("dhcpEnable") else "Disabled",
            "Domain Name": n.get("domainName", ""),
        }
        for n in items
    ]


def _vlan_rows(data: Any) -> list[dict[str, Any]]:
    items = data if isinstance(data, list) else []
    return [
        {
            "Name": n.get("name", ""),
            "VLAN ID": n.get("vlanId", ""),
            "Subnet": n.get("networkIp", ""),
            "Prefix Length": n.get("prefixLen", ""),
            "Purpose": n.get("purpose", ""),
        }
        for n in items
    ]


def _switch_port_profile_rows(data: Any) -> list[dict[str, Any]]:
    items = data if isinstance(data, list) else []
    return [
        {
            "Name": p.get("name", ""),
            "Type": p.get("type", ""),
            "Native VLAN": p.get("nativeNetworkId", p.get("nativeVlan", "")),
            "Tagged VLANs": ", ".join(
                str(v)
                for v in p.get("taggedNetworkIds", p.get("taggedVlans", []))
            ),
            "Speed / Duplex": p.get("speed", ""),
            "PoE": "Enabled" if p.get("poeEnable") else "Disabled",
        }
        for p in items
    ]


def _gateway_rows(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, dict):
        items = [data]
    elif isinstance(data, list):
        items = data
    else:
        items = []

    rows = [
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
    # Fall back to raw rows if all extracted fields are empty
    if rows and all(not any(v for v in row.values()) for row in rows):
        rows = [r for r in items if isinstance(r, dict)]
    return rows


def _ssid_rows(data: Any) -> list[dict[str, Any]]:
    items = data if isinstance(data, list) else []
    return [
        {
            "WLAN": s.get("wlanName", ""),
            "SSID": s.get("ssid", s.get("name", "")),
            "Security": s.get("security", ""),
            "Band": s.get("band", ""),
            "Status": "Enabled" if s.get("enable", True) else "Disabled",
            "VLAN": s.get("vlanId", ""),
            "Hidden": "Yes" if s.get("hide") else "No",
        }
        for s in items
    ]


def _dhcp_reservation_rows(data: Any) -> list[dict[str, Any]]:
    items = data if isinstance(data, list) else []
    return [
        {
            "Network": r.get("networkName", ""),
            "IP Address": r.get("ip", r.get("ipAddress", "")),
            "MAC Address": r.get("mac", r.get("macAddress", "")),
            "Hostname": r.get("name", r.get("hostname", "")),
            "Description": r.get("description", ""),
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
        sort_key="Name",
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
