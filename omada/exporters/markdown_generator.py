"""Markdown documentation generator.

For each resource type a Markdown file is produced containing a human-friendly
table derived from the YAML source-of-truth data.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _header(text: str) -> str:
    return f"# {text}\n\n"


def _sanitize(value: Any) -> str:
    """Flatten a value to a Markdown-safe string."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "✓" if value else "✗"
    if isinstance(value, (list, dict)):
        text = str(value)
    else:
        text = str(value)
    # Escape pipe characters so they don't break table formatting
    return text.replace("|", "\\|").replace("\n", " ")


def _table(rows: list[dict[str, Any]]) -> str:
    """Render a list of dicts as a GitHub Flavoured Markdown table."""
    if not rows:
        return "_No records found._\n"

    # Collect all unique keys while preserving insertion order
    keys: list[str] = []
    for row in rows:
        for k in row:
            if k not in keys:
                keys.append(k)

    # Header row
    header = "| " + " | ".join(_column_header(k) for k in keys) + " |"
    separator = "| " + " | ".join("---" for _ in keys) + " |"
    body_lines = [
        "| " + " | ".join(_sanitize(row.get(k, "")) for k in keys) + " |"
        for row in rows
    ]
    return "\n".join([header, separator] + body_lines) + "\n"


def _column_header(key: str) -> str:
    """Convert a snake_case key to Title Case for use as a column header."""
    return re.sub(r"[_\-]+", " ", key).title()


def _wrap_single(data: Any) -> list[dict[str, Any]]:
    """Wrap non-list data in a list so _table() always receives a list."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return [data]
    return [{"value": data}]


# ---------------------------------------------------------------------------
# Per-resource formatters
# ---------------------------------------------------------------------------

def _acl_rules(data: list[dict]) -> str:
    rows = [
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
        for r in data
    ]
    return _header("ACL Rules") + _table(rows)


def _ip_groups(data: list[dict]) -> str:
    rows = [
        {
            "Name": g.get("name", ""),
            "Type": g.get("type", ""),
            "IPs / Subnets": ", ".join(g.get("ipList", [])),
        }
        for g in data
    ]
    return _header("IP Groups") + _table(rows)


def _port_groups(data: list[dict]) -> str:
    rows = [
        {
            "Name": g.get("name", ""),
            "Ports": ", ".join(str(p) for p in g.get("portList", [])),
        }
        for g in data
    ]
    return _header("Port Groups") + _table(rows)


def _networks(data: list[dict]) -> str:
    rows = [
        {
            "Name": n.get("name", ""),
            "Purpose": n.get("purpose", ""),
            "Subnet": n.get("networkIp", ""),
            "Prefix Length": n.get("prefixLen", ""),
            "VLAN ID": n.get("vlanId", ""),
            "DHCP": "Enabled" if n.get("dhcpEnable") else "Disabled",
            "Domain Name": n.get("domainName", ""),
        }
        for n in data
    ]
    return _header("Networks") + _table(rows)


def _vlans(data: list[dict]) -> str:
    rows = [
        {
            "Name": n.get("name", ""),
            "VLAN ID": n.get("vlanId", ""),
            "Subnet": n.get("networkIp", ""),
            "Prefix Length": n.get("prefixLen", ""),
            "Purpose": n.get("purpose", ""),
        }
        for n in data
    ]
    return _header("VLANs") + _table(rows)


def _switch_port_profiles(data: list[dict]) -> str:
    rows = [
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
        for p in data
    ]
    return _header("Switch Port Profiles") + _table(rows)


def _gateway_settings(data: Any) -> str:
    rows = _wrap_single(data)
    simplified = [
        {
            "WAN Mode": r.get("wanMode", ""),
            "WAN1 IP": r.get("wan1Ip", ""),
            "WAN1 Type": r.get("wan1Type", ""),
            "WAN2 IP": r.get("wan2Ip", ""),
            "WAN2 Type": r.get("wan2Type", ""),
            "Load Balancing": "Enabled" if r.get("loadBalance") else "Disabled",
        }
        for r in rows
        if isinstance(r, dict)
    ]
    if not simplified or simplified == [{}]:
        simplified = [r for r in rows if isinstance(r, dict)]
    return _header("Gateway Settings") + _table(simplified)


def _ssids(data: list[dict]) -> str:
    rows = [
        {
            "WLAN": s.get("wlanName", ""),
            "SSID": s.get("ssid", s.get("name", "")),
            "Security": s.get("security", ""),
            "Band": s.get("band", ""),
            "Status": "Enabled" if s.get("enable", True) else "Disabled",
            "VLAN": s.get("vlanId", ""),
            "Hidden": "Yes" if s.get("hide") else "No",
        }
        for s in data
    ]
    return _header("SSIDs") + _table(rows)


def _dhcp_reservations(data: list[dict]) -> str:
    rows = [
        {
            "Network": r.get("networkName", ""),
            "IP Address": r.get("ip", r.get("ipAddress", "")),
            "MAC Address": r.get("mac", r.get("macAddress", "")),
            "Hostname": r.get("name", r.get("hostname", "")),
            "Description": r.get("description", ""),
        }
        for r in data
    ]
    return _header("DHCP Reservations") + _table(rows)


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

_FORMATTERS = {
    "acl_rules": _acl_rules,
    "ip_groups": _ip_groups,
    "port_groups": _port_groups,
    "networks": _networks,
    "vlans": _vlans,
    "switch_port_profiles": _switch_port_profiles,
    "gateway_settings": _gateway_settings,
    "ssids": _ssids,
    "dhcp_reservations": _dhcp_reservations,
}


class MarkdownGenerator:
    """Generates Markdown documentation files from resource data.

    Parameters
    ----------
    output_dir:
        Directory where Markdown files will be written.
    """

    def __init__(self, output_dir: str | Path) -> None:
        self.output_dir = Path(output_dir)

    def generate(self, name: str, data: Any) -> Path:
        """Generate a Markdown file for *name* and return the path."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        formatter = _FORMATTERS.get(name)
        if formatter is not None:
            content = formatter(data if isinstance(data, list) else data)
        else:
            content = _header(_column_header(name)) + _table(_wrap_single(data))

        path = self.output_dir / f"{name}.md"
        path.write_text(content, encoding="utf-8")
        return path

    def generate_all(self, data: dict[str, Any]) -> dict[str, Path]:
        """Generate Markdown for every key in *data*."""
        return {name: self.generate(name, value) for name, value in data.items()}
