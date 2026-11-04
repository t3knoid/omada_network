"""Resource registry: single source of truth for all Omada resource types.

Each :class:`ResourceDefinition` describes one resource category:

* **name** – snake_case identifier used as file stem (``acl_rules``, …)
* **title** – human-readable Markdown heading
* **fetch_method** – method name on :class:`~omada.api.openapi_client.OmadaOpenApiClient`
* **row_formatter** – callable that converts raw API/YAML data to a list of
  display-row dicts (used by :class:`~omada.exporters.markdown_generator.MarkdownGenerator`)
* **sort_key** – column header to sort rows by; ``""`` disables sorting
* **detail_formatter** – optional callable returning ``(title, rows)`` pairs;
  each pair is rendered as its own ``##`` section below the summary table

Adding a new resource category requires only:

1. A new ``get_*`` method on ``OmadaOpenApiClient``
2. A new :class:`ResourceDefinition` appended to :data:`RESOURCES`

No other files need to be modified.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable

from omada.redaction import REDACTED


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
    detail_formatter: Callable[..., list[tuple[str, list[dict[str, Any]]]]] | None = None


# ---------------------------------------------------------------------------
# Row-formatter functions
# ---------------------------------------------------------------------------

_PROTO_MAP: dict[int, str] = {
    1: "ICMP", 6: "TCP", 17: "UDP", 256: "All",
}

_POLICY_MAP: dict[int, str] = {0: "Deny", 1: "Permit"}

_SOURCE_TYPE_MAP: dict[int, str] = {0: "Network", 1: "IP Group", 2: "IP-Port Group"}

# Port (LAN) profile codes, per the Open API LanProfileInfoOpenApiVO schema.
_PROFILE_TYPE_MAP: dict[int, str] = {0: "All", 1: "Disable", 2: "Standard"}
_PROFILE_FLAG_MAP: dict[int, str] = {0: "Default", 1: "Network-generated", 2: "User-created"}
_PROFILE_POE_MAP: dict[int, str] = {0: "Disabled", 1: "Enabled", 2: "Use Device Setting"}
_DOT1X_MAP: dict[int, str] = {0: "Force Unauthorized", 1: "Force Authorized", 2: "Auto"}
_NETWORK_TAGS_MAP: dict[int, str] = {0: "Allow All", 1: "Block All", 2: "Custom"}
_BANDWIDTH_CTRL_MAP: dict[int, str] = {0: "Off", 1: "Rate Limit", 2: "Storm Control"}
_RATE_UNIT_MAP: dict[int, str] = {1: "Kbps", 2: "Mbps"}
_STORM_ACTION_MAP: dict[int, str] = {0: "Drop", 1: "Shutdown"}
_TRUST_MODE_MAP: dict[int, str] = {0: "Untrusted", 1: "Trust 802.1p", 2: "Trust DSCP"}
_RELAY_FORMAT_MAP: dict[int, str] = {0: "Normal", 1: "Private"}
# The spec only gives the 0-2 range; labels follow the controller UI order.
_P2P_LINK_MAP: dict[int, str] = {0: "Auto", 1: "Open (True)", 2: "Closed (False)"}

_UNTAGGED_KEYS = ("untagNetworkIds", "untaggedNetworkIds")
_TAGGED_KEYS = ("tagNetworkIds", "taggedNetworkIds", "taggedVlans")

_SWITCHING_FLAGS: tuple[tuple[str, str], ...] = (
    ("portIsolationEnable", "Port Isolation"),
    ("lldpMedEnable", "LLDP-MED"),
    ("topoNotifyEnable", "Topology Change Notification"),
    ("loopbackDetectEnable", "Loopback Detect (Port Based)"),
    ("loopbackDetectVlanBasedEnable", "Loopback Detect (VLAN Based)"),
    ("eeeEnable", "EEE"),
    ("flowControlEnable", "Flow Control"),
    ("fastLeaveEnable", "IGMP Snooping Fast Leave"),
    ("igmpFastLeaveEnable", "IGMP Fast Leave"),
    ("mldFastLeaveEnable", "MLD Fast Leave"),
    ("esEnable", "ES (Easy Managed Switch)"),
)

# Keys rendered explicitly (or deliberately hidden as internal bookkeeping);
# anything else a profile carries is listed under "Other".
_PROFILE_HANDLED_KEYS: frozenset[str] = frozenset({
    "id", "name", "type", "flag", "prohibitModify", "poe", "poeEnable", "dot1x",
    "nativeNetworkId", "networkTagsSetting", "networkConflict",
    *_UNTAGGED_KEYS, *_TAGGED_KEYS,
    "voiceNetworkEnable", "voiceNetworkId", "voiceDscpEnable", "voiceDscp",
    *(key for key, _ in _SWITCHING_FLAGS), "dhcpL2RelaySettings",
    "dot1pPriority", "trustMode", "bandWidthCtrlType", "bandCtrl", "stormCtrl",
    "spanningTreeEnable", "spanningTreeSetting", "supportESEnable",
    # internal
    "nativeBridgeVlan", "tagBridgeVlanMap", "untagBridgeVlanMap", "voiceBridgeVlan",
    "esEnableTagBridgeVlanMap", "createByNewUI", "resource",
})

# WAN IPv4 connection type, per WanPortIpv4SettingOpenApiVO.protoType.
_PROTO_TYPE_MAP: dict[int, str] = {
    0: "Static", 1: "DHCP", 2: "PPPoE", 3: "L2TP", 4: "PPTP", 5: "DS-Lite", 6: "MAP-E",
}


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


def _enabled(value: Any) -> str:
    return "Enabled" if value else "Disabled"


def _profile_poe(value: Any) -> str:
    if isinstance(value, bool):
        return _enabled(value)
    if isinstance(value, int):
        return _PROFILE_POE_MAP.get(value, str(value))
    return _flatten(value)


def _profile_code(value: Any, mapping: dict[int, str]) -> str:
    if isinstance(value, int) and not isinstance(value, bool):
        return mapping.get(value, str(value))
    return _flatten(value)


def _profile_networks(profile: dict[str, Any], keys: tuple[str, ...], lookup: dict[str, str]) -> str:
    ids = next((profile[k] for k in keys if profile.get(k) is not None), [])
    return _resolve_ids(ids if isinstance(ids, list) else [ids], lookup)


def _profile_native(profile: dict[str, Any], lookup: dict[str, str]) -> str:
    native = profile.get("nativeNetworkId")
    return lookup.get(str(native), str(native)) if native else ""


def _switch_port_profile_rows(data: Any, context: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Summary table: one row per port profile."""
    items = data if isinstance(data, list) else []
    lookup = _build_id_lookup(context)
    rows = []
    for p in items:
        if not isinstance(p, dict):
            continue
        rows.append({
            "Name": p.get("name", ""),
            "Type": _profile_code(p.get("type", ""), _PROFILE_TYPE_MAP),
            "Native Network": _profile_native(p, lookup),
            "Untagged Networks": _profile_networks(p, _UNTAGGED_KEYS, lookup),
            "Tagged Networks": _profile_networks(p, _TAGGED_KEYS, lookup),
            "PoE": _profile_poe(p.get("poe", p.get("poeEnable", ""))),
            "Spanning Tree": _enabled(p.get("spanningTreeEnable")),
            "Loopback Detect": _enabled(p.get("loopbackDetectEnable")),
        })
    return rows


def _bandwidth_rows(p: dict[str, Any]) -> list[tuple[str, str]]:
    ctrl_type = p.get("bandWidthCtrlType")
    rows = [("Bandwidth Control", _profile_code(ctrl_type, _BANDWIDTH_CTRL_MAP))]
    if ctrl_type == 1 and isinstance(p.get("bandCtrl"), dict):
        band = p["bandCtrl"]
        for direction in ("ingress", "egress"):
            if band.get(f"{direction}Enable"):
                unit = _profile_code(band.get(f"{direction}Unit"), _RATE_UNIT_MAP)
                value = f"{band.get(f'{direction}Limit', '')} {unit}".strip()
            else:
                value = "Disabled"
            rows.append((f"{direction.title()} Rate Limit", value))
    elif ctrl_type == 2 and isinstance(p.get("stormCtrl"), dict):
        storm = p["stormCtrl"]
        unit = "%" if storm.get("rateMode") == 0 else " kbps"
        for key, label in (
            ("unknownUnicast", "Unknown Unicast"),
            ("multicast", "Multicast"),
            ("broadcast", "Broadcast"),
        ):
            value = f"{storm.get(key, '')}{unit}" if storm.get(f"{key}Enable") else "Disabled"
            rows.append((f"Storm Control: {label}", value))
        rows.append(("Storm Control: Action", _profile_code(storm.get("action"), _STORM_ACTION_MAP)))
        if storm.get("action") == 1 and storm.get("recoverTime") is not None:
            rows.append(("Storm Control: Recover Time", f"{storm['recoverTime']} s"))
    return rows


def _spanning_tree_rows(p: dict[str, Any]) -> list[tuple[str, str]]:
    rows = [("Spanning Tree", _enabled(p.get("spanningTreeEnable")))]
    stp = p.get("spanningTreeSetting")
    if not p.get("spanningTreeEnable") or not isinstance(stp, dict):
        return rows
    for key, label in (("priority", "Priority"), ("extPathCost", "External Path Cost"),
                       ("intPathCost", "Internal Path Cost")):
        if key in stp:
            rows.append((label, _flatten(stp[key])))
    if "p2pLink" in stp:
        rows.append(("P2P Link", _profile_code(stp["p2pLink"], _P2P_LINK_MAP)))
    for key, label in (
        ("edgePort", "Edge Port"), ("mcheck", "MCheck"), ("loopProtect", "Loop Protect"),
        ("rootProtect", "Root Protect"), ("tcGuard", "TC Guard"),
        ("bpduProtect", "BPDU Protect"), ("bpduFilter", "BPDU Filter"),
        ("bpduForward", "BPDU Forward"),
    ):
        if key in stp:
            rows.append((label, _enabled(stp[key])))
    for inst in stp.get("instances") or []:
        if isinstance(inst, dict):
            kind = "RPVST" if inst.get("stp") == 1 else "MSTP"
            ident = inst.get("vlan") if inst.get("stp") == 1 else inst.get("id")
            cost = "Auto" if inst.get("costMode", 0) == 0 else _flatten(inst.get("cost"))
            rows.append((f"{kind} Instance {ident}", f"Priority {inst.get('priority', '')}, Cost {cost}"))
    return rows


def _humanize_key(key: str) -> str:
    """``vlanConfigEnable`` → ``Vlan Config Enable``; keeps acronyms (``ES``)."""
    words = re.sub(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])", " ", key).split()
    return " ".join(w if w.isupper() else w.capitalize() for w in words)


def _switch_port_profile_details(
    data: Any, context: dict[str, Any] | None = None,
) -> list[tuple[str, list[dict[str, Any]]]]:
    """Per-profile detail tables: (profile name, [Category/Setting/Value rows])."""
    items = data if isinstance(data, list) else []
    lookup = _build_id_lookup(context)
    details = []
    for p in items:
        if not isinstance(p, dict):
            continue
        groups: list[tuple[str, list[tuple[str, str]]]] = []

        general = [
            ("Type", _profile_code(p.get("type", ""), _PROFILE_TYPE_MAP)),
            ("Origin", _profile_code(p.get("flag", ""), _PROFILE_FLAG_MAP)),
            ("Profile ID", _flatten(p.get("id", ""))),
        ]
        if "prohibitModify" in p:
            general.append(("Modifiable", "No" if p["prohibitModify"] else "Yes"))
        general += [
            ("PoE", _profile_poe(p.get("poe", p.get("poeEnable", "")))),
            ("802.1X", _profile_code(p.get("dot1x", ""), _DOT1X_MAP)),
        ]
        groups.append(("General", general))

        vlan = [
            ("Native Network", _profile_native(p, lookup)),
            ("Untagged Networks", _profile_networks(p, _UNTAGGED_KEYS, lookup)),
            ("Tagged Networks", _profile_networks(p, _TAGGED_KEYS, lookup)),
        ]
        if "networkTagsSetting" in p:
            vlan.append(("Network Tags Setting",
                         _profile_code(p["networkTagsSetting"], _NETWORK_TAGS_MAP)))
        if "voiceNetworkEnable" in p:
            voice = "Disabled"
            if p["voiceNetworkEnable"]:
                voice = lookup.get(str(p.get("voiceNetworkId", "")), _flatten(p.get("voiceNetworkId", "")))
            vlan.append(("Voice Network", voice))
            if p["voiceNetworkEnable"] and "voiceDscpEnable" in p:
                vlan.append(("Voice DSCP", _flatten(p.get("voiceDscp")) if p["voiceDscpEnable"] else "Disabled"))
        if "networkConflict" in p:
            vlan.append(("Network Conflict", "Yes" if p["networkConflict"] else "No"))
        groups.append(("VLAN", vlan))

        switching = []
        for key, label in _SWITCHING_FLAGS:
            if key in p:
                switching.append((label, _enabled(p[key])))
        relay = p.get("dhcpL2RelaySettings")
        if isinstance(relay, dict):
            value = _enabled(relay.get("enable"))
            if relay.get("enable") and "format" in relay:
                value += f" ({_profile_code(relay['format'], _RELAY_FORMAT_MAP)})"
            switching.append(("DHCP L2 Relay", value))
        if "supportESEnable" in p:
            switching.append(("ES Supported", "Yes" if p["supportESEnable"] else "No"))
        groups.append(("Switching", switching))

        qos = []
        if "dot1pPriority" in p:
            qos.append(("802.1p Priority", _flatten(p["dot1pPriority"])))
        if "trustMode" in p:
            qos.append(("Trust Mode", _profile_code(p["trustMode"], _TRUST_MODE_MAP)))
        qos += _bandwidth_rows(p)
        groups.append(("QoS & Bandwidth", qos))

        groups.append(("Spanning Tree", _spanning_tree_rows(p)))

        other = [
            (_humanize_key(key), ("Yes" if value else "No") if isinstance(value, bool) else _flatten(value))
            for key, value in p.items()
            if key not in _PROFILE_HANDLED_KEYS
        ]
        if other:
            groups.append(("Other", other))

        rows = [
            {"Category": category, "Setting": setting, "Value": value}
            for category, settings in groups
            for setting, value in settings
        ]
        details.append((_flatten(p.get("name", "")) or _flatten(p.get("id", "")), rows))
    return details


def _gateway_rows(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, dict):
        items = [data]
    elif isinstance(data, list):
        items = data
    else:
        items = []

    if items and isinstance(items[0], dict):
        first = items[0]
        legacy_keys = ("wanMode", "wan1Ip", "wan1Type", "wan2Ip", "wan2Type", "loadBalance")
        has_legacy = any(key in first for key in legacy_keys)
        has_wan_ports = "wanPortsConfig" in first

        if has_legacy:
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

        if not has_wan_ports:
            # Unknown format (e.g. OpenAPI fallback shapes) – return raw dicts
            return [r for r in items if isinstance(r, dict)]
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


_NAT_PROTOCOL_MAP: dict[int, str] = {0: "All", 1: "TCP", 2: "UDP"}


def _wan_port_names(context: dict[str, Any] | None) -> dict[str, str]:
    """Map WAN port IDs (``1_<uuid>``) to port names from ``gateway_settings``."""
    names: dict[str, str] = {}
    settings = (context or {}).get("gateway_settings")
    for item in settings if isinstance(settings, list) else [settings]:
        if not isinstance(item, dict):
            continue
        for wan in item.get("wanPortsConfig") or []:
            if isinstance(wan, dict) and wan.get("portId"):
                names[str(wan["portId"])] = str(wan.get("portName") or wan["portId"])
    return names


def _nat_interfaces(ids: Any, wan_names: dict[str, str]) -> str:
    if not ids:
        return ""
    return ", ".join(wan_names.get(str(i), str(i)) for i in (ids if isinstance(ids, list) else [ids]))


def _port_forwarding_rows(data: Any, context: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    items = data if isinstance(data, list) else []
    wan_names = _wan_port_names(context)
    rows = []
    for r in items:
        if not isinstance(r, dict):
            continue
        interfaces = [_nat_interfaces(r.get("interfaceWanPortId"), wan_names)]
        if r.get("virtualWanId"):
            interfaces.append("Virtual WAN " + _nat_interfaces(r["virtualWanId"], {}))
        wan_ips = [
            f"{w.get('ip', '')} ({wan_names.get(str(w.get('wanId', '')), w.get('wanId', ''))})"
            if w.get("wanId") else str(w.get("ip", ""))
            for w in r.get("wanIps") or [] if isinstance(w, dict)
        ]
        if wan_ips:
            interfaces.append("WAN IP " + ", ".join(wan_ips))
        if r.get("from") == 1:
            source = ", ".join(str(a) for a in r.get("limitedAddresses") or []) or "Limited"
        else:
            source = "Any"
        rows.append({
            "Name": r.get("name", ""),
            "Status": _enabled(r.get("status")),
            "Interface": "; ".join(i for i in interfaces if i),
            "Source IP": source,
            "External Port": _flatten(r.get("externalPort", "")),
            "Forward IP": _flatten(r.get("forwardIp", "")),
            "Forward Port": _flatten(r.get("forwardPort", "")),
            "Protocol": _profile_code(r.get("protocol", ""), _NAT_PROTOCOL_MAP),
            "DMZ": _enabled(r.get("dMZ", r.get("dmz"))),
        })
    return rows


def _one_to_one_nat_rows(data: Any, context: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    items = data if isinstance(data, list) else []
    wan_names = _wan_port_names(context)
    return [
        {
            "Name": r.get("name", ""),
            "Status": _enabled(r.get("status")),
            "Interface": _nat_interfaces(r.get("interfaceIds"), wan_names),
            "Internal IP": _flatten(r.get("internalIp", "")),
            "External IP": _flatten(r.get("externalIp", "")),
            "DMZ": _enabled(r.get("dmz")),
            "Description": _flatten(r.get("description", "")),
        }
        for r in items
        if isinstance(r, dict)
    ]


def _alg_rows(data: Any) -> list[dict[str, Any]]:
    """ALG settings as Setting / Value rows (the API returns one object)."""
    if not isinstance(data, dict) or not data:
        return []
    rows: list[tuple[str, str]] = []

    def ports(key: str) -> str:
        return ", ".join(str(p) for p in data.get(key) or [])

    if "ftp" in data:
        rows.append(("FTP ALG", _enabled(data["ftp"])))
        if data["ftp"] and data.get("ftpPorts"):
            rows.append(("FTP Ports", ports("ftpPorts")))
    for key, label in (("h323", "H.323 ALG"), ("pptp", "PPTP ALG"), ("ipSec", "IPSec ALG")):
        if key in data:
            rows.append((label, _enabled(data[key])))
    if "sip" in data:
        rows.append(("SIP ALG", _enabled(data["sip"])))
        if data["sip"]:
            for key, label in (
                ("sipTcp", "SIP over TCP"),
                ("sipUdp", "SIP over UDP"),
                ("sipDirectSignaling", "SIP Direct Signaling"),
                ("sipDirectMedia", "SIP Direct Media"),
                ("sipTimeout", "SIP Timeout"),
            ):
                if key in data:
                    rows.append((label, _enabled(data[key])))
            if data.get("sipPorts"):
                rows.append(("SIP Ports", ports("sipPorts")))
            if data.get("sipTimeout"):
                for key, label in (
                    ("sipSignalingTimeout", "SIP Signaling Timeout"),
                    ("sipMediaTimeout", "SIP Media Timeout"),
                ):
                    if data.get(key) is not None:
                        rows.append((label, f"{data[key]} s"))
    return [{"Setting": setting, "Value": value} for setting, value in rows]


_ROUTE_TYPE_MAP: dict[int, str] = {0: "Next Hop", 1: "Interface"}

_STATIC_INTERFACE_TYPE_MAP: dict[int, str] = {
    0: "WAN", 1: "LAN", 2: "L2TP", 3: "PPTP", 5: "Virtual WAN",
}

_POLICY_INTERFACE_TYPE_MAP: dict[int, str] = {0: "WAN", 2: "L2TP", 3: "PPTP", 4: "Multiple"}


def _static_route_interface(
    r: dict[str, Any], wan_names: dict[str, str], lookup: dict[str, str],
) -> str:
    """Return e.g. ``"WAN: WAN1"`` or ``"LAN: IoT Devices"`` for interface routes."""
    if r.get("routeType") != 1 and not r.get("interfaceId"):
        return ""
    kind = _profile_code(r.get("interfaceType", ""), _STATIC_INTERFACE_TYPE_MAP)
    iface_id = str(r.get("interfaceId", ""))
    name = (
        r.get("interfaceName")
        or wan_names.get(iface_id)
        or lookup.get(iface_id)
        or iface_id
    )
    return f"{kind}: {name}" if kind and name else kind or name


def _static_route_rows(data: Any, context: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    items = data if isinstance(data, list) else []
    wan_names = _wan_port_names(context)
    lookup = _build_id_lookup(context)
    rows = []
    for r in items:
        if not isinstance(r, dict):
            continue
        is_switch = r.get("routeSource") == "switch"
        rows.append({
            "Name": _flatten(r.get("description") if is_switch else r.get("name", "")),
            "Status": _enabled(r.get("status")),
            "Device": _flatten(r.get("deviceName", "")) if is_switch else "Gateway",
            "Destinations": ", ".join(str(d) for d in r.get("destinations") or []),
            "Route Type": "Next Hop" if is_switch else _profile_code(r.get("routeType", ""), _ROUTE_TYPE_MAP),
            "Next Hop": _flatten(r.get("nextHopIp", "")),
            "Interface": "" if is_switch else _static_route_interface(r, wan_names, lookup),
            "Metric": "" if is_switch else _flatten(r.get("metric", "")),
            "Distance": _flatten(r.get("distance", "")) if is_switch else "",
        })
    return rows


def _policy_route_binding(r: dict[str, Any], wan_names: dict[str, str]) -> str:
    """Describe where a policy route sends traffic (its WAN/VPN binding)."""
    iface_type = r.get("interfaceType")
    if iface_type == 4:
        parts = []
        if r.get("wanPortIds"):
            parts.append("WAN: " + _nat_interfaces(r["wanPortIds"], wan_names))
        if r.get("vpnIds"):
            parts.append("VPN: " + _nat_interfaces(r["vpnIds"], {}))
        if r.get("virtualWanIds"):
            parts.append("Virtual WAN: " + _nat_interfaces(r["virtualWanIds"], {}))
        return "; ".join(parts)
    kind = _profile_code(iface_type, _POLICY_INTERFACE_TYPE_MAP) if iface_type is not None else ""
    iface_id = r.get("interfaceId")
    if not iface_id:
        return kind
    name = wan_names.get(str(iface_id), str(iface_id))
    return f"{kind}: {name}" if kind else name


def _policy_route_rows(data: Any, context: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Policy routes in evaluation order (by ``index``)."""
    items = [r for r in (data if isinstance(data, list) else []) if isinstance(r, dict)]
    items.sort(key=lambda r: (0, r["index"]) if isinstance(r.get("index"), int) else (1, 0))
    wan_names = _wan_port_names(context)
    lookup = _build_id_lookup(context)
    rows = []
    for r in items:
        src_type = _profile_code(r.get("sourceType", ""), _SOURCE_TYPE_MAP)
        dst_type = _profile_code(r.get("destinationType", ""), _SOURCE_TYPE_MAP)
        rows.append({
            "Index": _flatten(r.get("index", "")),
            "Name": _flatten(r.get("name", "")),
            "Status": _enabled(r.get("status")),
            "Protocols": _format_protocols(r.get("protocols", "")),
            "Source": _resolve_ids(r.get("sourceIds") or [], lookup),
            "Source Type": src_type,
            "Destination": _resolve_ids(r.get("destinationIds") or [], lookup),
            "Destination Type": dst_type,
            "WAN Binding": _policy_route_binding(r, wan_names),
            "Backup Interface": "Yes" if r.get("backupInterface") else "No",
        })
    return rows


# --- VPN ---------------------------------------------------------------------
# Codes from the Open API VPN schemas (VpnAdvancedSettingOpenApiVO etc.).

_VPN_HASH_MAP: dict[int, str] = {0: "MD5", 1: "SHA1", 2: "SHA256", 3: "SHA384", 4: "SHA512"}
_VPN_CIPHER_MAP: dict[int, str] = {0: "DES", 1: "3DES", 2: "AES128", 3: "AES192", 4: "AES256"}
_VPN_DH_MAP: dict[int, str] = {
    0: "DH1", 1: "DH2", 2: "DH5", 3: "DH14", 4: "DH15", 5: "DH16",
    6: "DH19", 7: "DH20", 8: "DH21", 9: "DH25", 10: "DH26",
}
_VPN_PFS_MAP: dict[int, str] = {0: "None", 1: "DH1", 2: "DH2", 3: "DH5", 14: "DH14", 15: "DH15"}
_VPN_IKE_MAP: dict[int, str] = {0: "IKEv1", 1: "IKEv2"}
_VPN_EXCHANGE_MAP: dict[int, str] = {0: "Main Mode", 1: "Aggressive Mode"}
# The spec labels 1 as "Aggressive Mode" (a copy error); the UI calls it Responder Mode.
_VPN_NEGOTIATION_MAP: dict[int, str] = {0: "Initiator Mode", 1: "Responder Mode"}
_VPN_ID_TYPE_MAP: dict[int, str] = {0: "IP Address", 1: "Name"}
_VPN_ENCAP_MAP: dict[int, str] = {0: "Tunnel Mode", 1: "Transport Mode"}
_VPN_PHASE2_PROTO_MAP: dict[int, str] = {0: "AH", 1: "ESP"}
_SITE_VPN_TYPE_MAP: dict[int, str] = {0: "Auto IPsec", 1: "Manual IPsec"}
_CLIENT_VPN_TYPE_MAP: dict[int, str] = {0: "L2TP", 1: "PPTP", 2: "IPsec", 3: "OpenVPN"}
_OPENVPN_MODE_MAP: dict[int, str] = {0: "Certificate", 1: "Certificate + Account"}
_VPN_TUNNEL_MODE_MAP: dict[int, str] = {0: "Split", 1: "Full"}
_VPN_SERVICE_MAP: dict[int, str] = {0: "UDP", 1: "TCP"}
_VPN_AUTH_MODE_MAP: dict[int, str] = {0: "Local", 1: "LDAP"}
_VPN_WORKING_MODE_MAP: dict[int, str] = {0: "NAT", 1: "Routing"}
_VPN_USER_PROTOCOL_MAP: dict[int, str] = {0: "L2TP/PPTP", 1: "OpenVPN"}
_VPN_CLIENT_MODE_MAP: dict[int, str] = {0: "Client-to-Site", 1: "Site-to-Site"}


def _secret_state(value: Any) -> str:
    """``Not set`` / ``Configured`` (redacted), or the value itself when the
    export was run with secrets included."""
    if not value:
        return "Not set"
    if value == REDACTED:
        return "Configured"
    return _flatten(value)


def _vpn_subnets(subnets: Any) -> str:
    parts = []
    for s in subnets or []:
        if isinstance(s, dict):
            parts.append(f"{s.get('ip', '')}/{s['mask']}" if s.get("mask") is not None else str(s.get("ip", "")))
        else:
            parts.append(str(s))
    return ", ".join(parts)


def _vpn_local_networks(v: dict[str, Any], lookup: dict[str, str]) -> str:
    if v.get("networkType") == 1:
        return _vpn_subnets(v.get("customNetwork"))
    return _resolve_ids(v.get("networkList") or [], lookup)


def _vpn_ike_summary(adv: Any) -> str:
    """Compact cipher suite, e.g. ``IKEv2 AES256/SHA256/DH14, ESP AES256/SHA256, PFS DH14``."""
    if not isinstance(adv, dict) or not adv:
        return ""
    p1 = "/".join(x for x in (
        _profile_code(adv.get("phase1Proposal2", ""), _VPN_CIPHER_MAP),
        _profile_code(adv.get("phase1Proposal1", ""), _VPN_HASH_MAP),
        _profile_code(adv.get("phase1Proposal3", ""), _VPN_DH_MAP),
    ) if x)
    p2 = "/".join(x for x in (
        _profile_code(adv.get("phase2Proposal3", ""), _VPN_CIPHER_MAP),
        _profile_code(adv.get("phase2Proposal2", ""), _VPN_HASH_MAP),
    ) if x)
    proto = _profile_code(adv.get("phase2Proposal1", ""), _VPN_PHASE2_PROTO_MAP)
    ike = _profile_code(adv.get("keyExchangeVersion", ""), _VPN_IKE_MAP)
    parts = [f"{ike} {p1}".strip()]
    if p2 or proto:
        parts.append(f"{proto} {p2}".strip())
    if "pfs" in adv:
        parts.append(f"PFS {_profile_code(adv['pfs'], _VPN_PFS_MAP)}")
    return ", ".join(p for p in parts if p)


def _vpn_advanced_details(adv: Any) -> list[tuple[str, str, str]]:
    """(category, setting, value) rows for an IPsec advanced setting."""
    if not isinstance(adv, dict) or not adv:
        return []
    rows: list[tuple[str, str, str]] = []

    def add(category: str, key: str, label: str, mapping: dict[int, str] | None = None,
            suffix: str = "") -> None:
        if key in adv and adv[key] is not None:
            value = _profile_code(adv[key], mapping) if mapping else _flatten(adv[key])
            rows.append((category, label, f"{value}{suffix}"))

    add("Phase 1 (IKE)", "keyExchangeVersion", "Key Exchange Version", _VPN_IKE_MAP)
    add("Phase 1 (IKE)", "phase1Proposal2", "Encryption", _VPN_CIPHER_MAP)
    add("Phase 1 (IKE)", "phase1Proposal1", "Authentication (Hash)", _VPN_HASH_MAP)
    add("Phase 1 (IKE)", "phase1Proposal3", "DH Group", _VPN_DH_MAP)
    add("Phase 1 (IKE)", "exchangeMode", "Exchange Mode", _VPN_EXCHANGE_MAP)
    add("Phase 1 (IKE)", "negotiationMode", "Negotiation Mode", _VPN_NEGOTIATION_MAP)
    add("Phase 1 (IKE)", "saLifetime", "SA Lifetime", suffix=" s")
    if "dpd" in adv:
        dpd = _enabled(adv["dpd"])
        if adv["dpd"] and adv.get("dpdInterval") is not None:
            dpd += f" ({adv['dpdInterval']} s)"
        rows.append(("Phase 1 (IKE)", "Dead Peer Detection", dpd))
    add("Phase 2 (IPsec)", "encapsulationMode", "Encapsulation Mode", _VPN_ENCAP_MAP)
    add("Phase 2 (IPsec)", "phase2Proposal1", "Protocol", _VPN_PHASE2_PROTO_MAP)
    add("Phase 2 (IPsec)", "phase2Proposal3", "Encryption", _VPN_CIPHER_MAP)
    add("Phase 2 (IPsec)", "phase2Proposal2", "Authentication (Hash)", _VPN_HASH_MAP)
    add("Phase 2 (IPsec)", "pfs", "PFS", _VPN_PFS_MAP)
    add("Phase 2 (IPsec)", "saLifetime2", "SA Lifetime", suffix=" s")
    add("Authentication", "localIdType", "Local ID Type", _VPN_ID_TYPE_MAP)
    add("Authentication", "localName", "Local ID")
    add("Authentication", "remoteIdType", "Remote ID Type", _VPN_ID_TYPE_MAP)
    add("Authentication", "remoteName", "Remote ID")
    return rows


def _detail_rows(rows: list[tuple[str, str, str]]) -> list[dict[str, Any]]:
    return [{"Category": c, "Setting": s, "Value": v} for c, s, v in rows]


# Site-to-site --------------------------------------------------------------

def _s2s_peer(v: dict[str, Any]) -> str:
    return _flatten(v.get("remoteSite") if v.get("siteVpnType") == 0 else v.get("remoteIp", ""))


def _s2s_auth(v: dict[str, Any]) -> str:
    if v.get("siteVpnType") == 0:
        return "Automatic (controller-managed)"
    return f"Pre-shared Key ({_secret_state(v.get('preSharedKey'))})"


def _site_to_site_vpn_rows(data: Any, context: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    items = data if isinstance(data, list) else []
    lookup = _build_id_lookup(context)
    wan_names = _wan_port_names(context)
    return [
        {
            "Name": _flatten(v.get("name", "")),
            "Status": _enabled(v.get("status")),
            "Type": _profile_code(v.get("siteVpnType", ""), _SITE_VPN_TYPE_MAP),
            "Remote Peer": _s2s_peer(v),
            "Remote Subnets": _vpn_subnets(v.get("remoteSubnet")),
            "Local Networks": _vpn_local_networks(v, lookup),
            "WAN": _nat_interfaces(v.get("wan"), wan_names),
            "Encryption": _vpn_ike_summary(v.get("advancedSetting")),
            "Authentication": _s2s_auth(v),
        }
        for v in items
        if isinstance(v, dict)
    ]


def _site_to_site_vpn_details(
    data: Any, context: dict[str, Any] | None = None,
) -> list[tuple[str, list[dict[str, Any]]]]:
    items = data if isinstance(data, list) else []
    lookup = _build_id_lookup(context)
    wan_names = _wan_port_names(context)
    details = []
    for v in items:
        if not isinstance(v, dict):
            continue
        rows = [
            ("Tunnel", "Type", _profile_code(v.get("siteVpnType", ""), _SITE_VPN_TYPE_MAP)),
            ("Tunnel", "Status", _enabled(v.get("status"))),
            ("Tunnel", "Remote Peer", _s2s_peer(v)),
            ("Tunnel", "WAN", _nat_interfaces(v.get("wan"), wan_names)),
            ("Networks", "Remote Subnets", _vpn_subnets(v.get("remoteSubnet"))),
            ("Networks", "Local Networks", _vpn_local_networks(v, lookup)),
            ("Authentication", "Method", _s2s_auth(v)),
        ]
        rows += _vpn_advanced_details(v.get("advancedSetting"))
        details.append((_flatten(v.get("name", "")) or _flatten(v.get("id", "")), _detail_rows(rows)))
    return details


# Remote access (client-to-site servers and clients) ---------------------------

def _vpn_users_by_server(context: dict[str, Any] | None) -> dict[str, list[str]]:
    users: dict[str, list[str]] = {}
    for u in (context or {}).get("vpn_users") or []:
        if isinstance(u, dict):
            for server_id in u.get("servers") or []:
                users.setdefault(str(server_id), []).append(str(u.get("username", "")))
    return users


def _ra_ip_pool(v: dict[str, Any]) -> str:
    if v.get("ipPoolStart") or v.get("ipPoolEnd"):
        return f"{v.get('ipPoolStart', '')} – {v.get('ipPoolEnd', '')}"
    return _flatten(v.get("ipPool", ""))


def _ra_service(v: dict[str, Any]) -> str:
    if v.get("clientVpnType") != 3 and v.get("servicePort") is None:
        return ""
    proto = _profile_code(v.get("serviceType", ""), _VPN_SERVICE_MAP) if "serviceType" in v else ""
    port = v.get("servicePort")
    return f"{proto} {port}".strip() if port is not None else proto


def _ra_encryption(v: dict[str, Any]) -> str:
    kind = v.get("clientVpnType")
    if kind == 2:
        return _vpn_ike_summary(v.get("advancedSetting")) or "IPsec"
    if kind == 3:
        return "TLS"
    if kind == 0:
        return "L2TP over IPsec" if v.get("encryption") == 0 else "Unencrypted"
    if kind == 1:
        return "MPPE" if v.get("encryption") == 0 else "Unencrypted"
    return ""


def _ra_auth(v: dict[str, Any], users_by_server: dict[str, list[str]]) -> str:
    """Authentication references: method, account and PSK state, never secrets."""
    kind = v.get("clientVpnType")
    parts: list[str] = []
    if v.get("vpnRole") == "client":
        if kind == 3:
            parts.append(_profile_code(v.get("openVpnMode", v.get("mode", "")), _OPENVPN_MODE_MAP))
            cert = v.get("vpnConfiguration")
            if isinstance(cert, dict) and cert.get("fileName"):
                parts.append(f"Config file {cert['fileName']}")
        if v.get("clientUserName"):
            parts.append(f"User {v['clientUserName']}")
        if "clientPassword" in v:
            parts.append(f"Password {_secret_state(v['clientPassword'])}")
    else:
        if kind == 3:
            parts.append(_profile_code(v.get("openVpnMode", ""), _OPENVPN_MODE_MAP))
        elif "authMode" in v:
            parts.append(f"{_profile_code(v['authMode'], _VPN_AUTH_MODE_MAP)} users")
        users = users_by_server.get(str(v.get("id", "")))
        if users:
            parts.append("Users: " + ", ".join(sorted(users)))
    if "preSharedKey" in v and (kind == 2 or (kind == 0 and v.get("encryption") == 0)):
        parts.append(f"Pre-shared Key {_secret_state(v['preSharedKey'])}")
    return "; ".join(p for p in parts if p)


def _remote_access_vpn_rows(data: Any, context: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    items = data if isinstance(data, list) else []
    lookup = _build_id_lookup(context)
    wan_names = _wan_port_names(context)
    users_by_server = _vpn_users_by_server(context)
    return [
        {
            "Name": _flatten(v.get("name", "")),
            "Role": _flatten(v.get("vpnRole", "")).title(),
            "Status": _enabled(v.get("status")),
            "Protocol": _profile_code(v.get("clientVpnType", ""), _CLIENT_VPN_TYPE_MAP),
            "Remote Peer": _flatten(v.get("remoteIp") or v.get("remoteSite") or ""),
            "Remote Subnets": _vpn_subnets(v.get("remoteSubnet")),
            "Local Networks": _vpn_local_networks(v, lookup),
            "Client IP Pool": _ra_ip_pool(v),
            "WAN": _nat_interfaces(v.get("wan"), wan_names),
            "Service": _ra_service(v),
            "Encryption": _ra_encryption(v),
            "Authentication": _ra_auth(v, users_by_server),
        }
        for v in items
        if isinstance(v, dict)
    ]


def _remote_access_vpn_details(
    data: Any, context: dict[str, Any] | None = None,
) -> list[tuple[str, list[dict[str, Any]]]]:
    items = data if isinstance(data, list) else []
    lookup = _build_id_lookup(context)
    wan_names = _wan_port_names(context)
    users_by_server = _vpn_users_by_server(context)
    details = []
    for v in items:
        if not isinstance(v, dict):
            continue
        role = _flatten(v.get("vpnRole", "")).title()
        rows = [
            ("Tunnel", "Role", role),
            ("Tunnel", "Protocol", _profile_code(v.get("clientVpnType", ""), _CLIENT_VPN_TYPE_MAP)),
            ("Tunnel", "Status", _enabled(v.get("status"))),
            ("Tunnel", "Remote Peer", _flatten(v.get("remoteIp") or v.get("remoteSite") or "")),
            ("Tunnel", "WAN", _nat_interfaces(v.get("wan"), wan_names)),
            ("Tunnel", "Service", _ra_service(v)),
        ]
        tunnel_mode = v.get("tunnelMode", v.get("openVpnTunnelMode"))
        if tunnel_mode is not None:
            rows.append(("Tunnel", "Tunnel Mode", _profile_code(tunnel_mode, _VPN_TUNNEL_MODE_MAP)))
        if "workingMode" in v:
            rows.append(("Tunnel", "Working Mode", _profile_code(v["workingMode"], _VPN_WORKING_MODE_MAP)))
        rows += [
            ("Networks", "Remote Subnets", _vpn_subnets(v.get("remoteSubnet"))),
            ("Networks", "Local Networks", _vpn_local_networks(v, lookup)),
            ("Networks", "Client IP Pool", _ra_ip_pool(v)),
        ]
        dns = ", ".join(str(x) for x in (v.get("primaryDns"), v.get("secondaryDns")) if x)
        if dns:
            rows.append(("Networks", "DNS", dns))
        rows.append(("Encryption", "Encryption", _ra_encryption(v)))
        rows.append(("Authentication", "References", _ra_auth(v, users_by_server)))
        rows += _vpn_advanced_details(v.get("advancedSetting"))
        rows = [r for r in rows if r[2] != ""]
        title = _flatten(v.get("name", "")) or _flatten(v.get("id", ""))
        details.append((f"{title} ({role})" if role else title, _detail_rows(rows)))
    return details


# WireGuard -------------------------------------------------------------------

def _wireguard_rows(data: Any) -> list[dict[str, Any]]:
    items = data if isinstance(data, list) else []
    return [
        {
            "Name": _flatten(w.get("name", "")),
            "Status": _enabled(w.get("status")),
            "Listen Port": _flatten(w.get("listenPort", "")),
            "Local IP": _flatten(w.get("localIp", "")),
            "MTU": _flatten(w.get("mtu", "")),
            "Public Key": _flatten(w.get("publicKey", "")),
            "Private Key": _secret_state(w.get("privateKey")),
            "Peers": str(len(w.get("peers") or [])),
        }
        for w in items
        if isinstance(w, dict)
    ]


def _wireguard_details(
    data: Any, context: dict[str, Any] | None = None,
) -> list[tuple[str, list[dict[str, Any]]]]:
    """One section per interface listing its peers."""
    items = data if isinstance(data, list) else []
    details = []
    for w in items:
        if not isinstance(w, dict):
            continue
        peers = [
            {
                "Peer": _flatten(p.get("name", "")),
                "Status": _enabled(p.get("status")),
                "Endpoint": (
                    f"{p.get('endPoint', '')}:{p['endPointPort']}"
                    if p.get("endPoint") and p.get("endPointPort") is not None
                    else _flatten(p.get("endPoint", ""))
                ),
                "Allowed Addresses": ", ".join(str(a) for a in p.get("allowAddress") or []),
                "Keepalive": f"{p['keepAlive']} s" if p.get("keepAlive") else "Off",
                "Public Key": _flatten(p.get("publicKey", "")),
                "Preshared Key": _secret_state(p.get("presharedKey")),
                "Comment": _flatten(p.get("comment", "")),
            }
            for p in w.get("peers") or []
            if isinstance(p, dict)
        ]
        details.append((f"{_flatten(w.get('name', ''))} peers", peers))
    return details


# VPN users -------------------------------------------------------------------

def _vpn_user_rows(data: Any) -> list[dict[str, Any]]:
    items = data if isinstance(data, list) else []
    return [
        {
            "Username": _flatten(u.get("username", "")),
            "Protocol": _profile_code(u.get("protocol", ""), _VPN_USER_PROTOCOL_MAP),
            "Client Mode": _profile_code(u.get("clientMode", ""), _VPN_CLIENT_MODE_MAP),
            "Servers": _flatten(u.get("serverNames", "")) or ", ".join(str(s) for s in u.get("servers") or []),
            "Max Connections": _flatten(u.get("maxConnections", "")),
            "Remote Subnets": _vpn_subnets(u.get("userRemoteSubnets")),
            "Local IP": _flatten(u.get("localIp", "")),
            "Password": _secret_state(u.get("password")),
        }
        for u in items
        if isinstance(u, dict)
    ]


# SSL VPN ---------------------------------------------------------------------

_SSL_AUTH_TYPE_MAP: dict[int, str] = {0: "Local", 1: "RADIUS", 2: "LDAP"}
_RADIUS_AUTH_MAP: dict[int, str] = {0: "PAP", 1: "CHAP"}
_SSL_RESOURCE_TYPE_MAP: dict[int, str] = {0: "IP", 1: "Domain"}
_SSL_RESOURCE_PROTOCOL_MAP: dict[int, str] = {
    0: "All", 1: "TCP", 2: "UDP", 3: "TCP/UDP", 4: "ICMP", 5: "Other",
}


def _ssl_lock(lock: Any) -> str:
    if not isinstance(lock, dict) or not lock.get("status"):
        return "Disabled"
    return f"Enabled ({lock.get('times', '')} failures, {lock.get('duration', '')} min)"


def _brief_names(items: Any) -> str:
    return ", ".join(
        _flatten(i.get("name") or i.get("id", "")) if isinstance(i, dict) else str(i)
        for i in items or []
    )


def _ssl_vpn_rows(data: Any, context: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """SSL VPN server settings as Setting / Value rows."""
    if not isinstance(data, dict):
        return []
    s = data.get("setting")
    if not isinstance(s, dict) or not s:
        return []
    wan_names = _wan_port_names(context)
    radius_names = {
        str(r["id"]): _flatten(r.get("name") or r["id"])
        for r in data.get("radiusServers") or [] if isinstance(r, dict) and r.get("id")
    }
    group_names = {
        str(g["id"]): _flatten(g.get("name") or g["id"])
        for g in data.get("userGroups") or [] if isinstance(g, dict) and g.get("id")
    }
    rows: list[tuple[str, str]] = [("Status", _enabled(s.get("status")))]
    if s.get("wanPort"):
        rows.append(("WAN", wan_names.get(str(s["wanPort"]), str(s["wanPort"]))))
    if s.get("wanIp"):
        rows.append(("WAN IP", _flatten(s["wanIp"])))
    if s.get("servicePort") is not None:
        rows.append(("Service Port", _flatten(s["servicePort"])))
    if s.get("ipPoolStart") or s.get("ipPoolEnd"):
        rows.append(("Client IP Pool", f"{s.get('ipPoolStart', '')} – {s.get('ipPoolEnd', '')}"))
    dns = ", ".join(str(x) for x in (s.get("primaryDns"), s.get("secondaryDns")) if x)
    if dns:
        rows.append(("DNS", dns))
    if "totalTraffic" in s:
        rows.append(("Tunnel Mode", "Full (all traffic)" if s["totalTraffic"] else "Split"))

    auth = s.get("authType")
    rows.append(("Authentication", _profile_code(auth, _SSL_AUTH_TYPE_MAP) if auth is not None else ""))
    radius = s.get("radiusSetting")
    if auth == 1 and isinstance(radius, dict):
        profile = radius.get("radiusProfile")
        rows.append(("RADIUS Profile", radius_names.get(str(profile), _flatten(profile))))
        if "authType" in radius:
            rows.append(("RADIUS Auth Protocol", _profile_code(radius["authType"], _RADIUS_AUTH_MAP)))
        if radius.get("repeatTime") is not None:
            rows.append(("RADIUS Retries", _flatten(radius["repeatTime"])))
        if radius.get("overTime") is not None:
            rows.append(("RADIUS Timeout", f"{radius['overTime']} s"))
        if radius.get("nasIp"):
            rows.append(("NAS IP", _flatten(radius["nasIp"])))
        if radius.get("defaultGroup"):
            group = str(radius["defaultGroup"])
            rows.append(("Default User Group", group_names.get(group, group)))
    ldap = s.get("LDAPSetting", s.get("ldapSetting"))
    if auth == 2 and isinstance(ldap, dict):
        rows.append(("LDAP Profile", _flatten(ldap.get("LDAPProfile", ldap.get("ldapProfile", "")))))
        if ldap.get("defaultGroup"):
            group = str(ldap["defaultGroup"])
            rows.append(("Default User Group", group_names.get(group, group)))
    rows.append(("Username Lockout", _ssl_lock(s.get("nameLockSetting"))))
    rows.append(("IP Lockout", _ssl_lock(s.get("ipLockSetting"))))
    if "exitAtIdle" in s:
        idle = _enabled(s["exitAtIdle"])
        if s["exitAtIdle"] and s.get("exitTime") is not None:
            idle += f" ({s['exitTime']} s)"
        rows.append(("Idle Logout", idle))
    return [{"Setting": k, "Value": v} for k, v in rows if v != ""]


def _ssl_resource_ports(r: dict[str, Any]) -> str:
    proto = r.get("protocol")
    if proto == 4:
        parts = [f"{label} {r[key]}" for key, label in (("icmpType", "Type"), ("icmpCode", "Code"))
                 if r.get(key) is not None]
        return ", ".join(parts)
    if proto == 5:
        return f"Protocol {r['otherProtocol']}" if r.get("otherProtocol") is not None else ""
    parts = []
    for prefix, label in (("src", "Source"), ("dst", "Destination")):
        start, end = r.get(f"{prefix}PortStart"), r.get(f"{prefix}PortEnd")
        if start is None and end is None:
            continue
        rng = str(start) if end in (None, start) else f"{start}–{end}"
        parts.append(f"{label} {rng}")
    return ", ".join(parts)


def _ssl_vpn_details(
    data: Any, context: dict[str, Any] | None = None,
) -> list[tuple[str, list[dict[str, Any]]]]:
    if not isinstance(data, dict):
        return []
    sections: list[tuple[str, list[dict[str, Any]]]] = []

    groups = [
        {
            "Name": _flatten(g.get("name", "")),
            "Users": ", ".join(str(u) for u in g.get("userList") or [])
            or _flatten(g.get("userNumber", "")),
            "Resource Groups": _brief_names(g.get("resourceGroupList")),
            "RADIUS Attribute": _flatten(g.get("radiusAttribute", "")),
            "LDAP Attribute": _flatten(g.get("ldapAttribute", "")),
        }
        for g in data.get("userGroups") or [] if isinstance(g, dict)
    ]
    users = [
        {
            "Name": _flatten(u.get("name", "")),
            "Group": _flatten(u.get("groupName") or u.get("groupId", "")),
            "Status": _enabled(u.get("status")),
            "Validity": _flatten(u.get("validity", "")),
            "Concurrent Logins": _flatten(u.get("concurrentNumber", "")),
            "Password": _secret_state(u.get("password")),
        }
        for u in data.get("users") or [] if isinstance(u, dict)
    ]
    resources = []
    for r in data.get("resources") or []:
        if not isinstance(r, dict):
            continue
        if r.get("type") == 1:
            target = _flatten(r.get("domain", ""))
        else:
            target = f"{r.get('ip', '')}/{r['mask']}" if r.get("mask") else _flatten(r.get("ip", ""))
        resources.append({
            "Name": _flatten(r.get("name", "")),
            "Type": _profile_code(r.get("type", ""), _SSL_RESOURCE_TYPE_MAP),
            "Destination": target,
            "Protocol": _profile_code(r.get("protocol", ""), _SSL_RESOURCE_PROTOCOL_MAP),
            "Ports / ICMP": _ssl_resource_ports(r),
            "Resource Groups": _brief_names(r.get("resourceGroupList")),
        })
    resource_groups = [
        {"Name": _flatten(g.get("name", "")), "Resources": _brief_names(g.get("resourcesList"))}
        for g in data.get("resourceGroups") or [] if isinstance(g, dict)
    ]
    for title, rows in (
        ("User Groups", groups), ("Users", users),
        ("Resources", resources), ("Resource Groups", resource_groups),
    ):
        sections.append((title, sorted(rows, key=lambda r: str(r.get("Name", "")).lower())))
    return sections


# EoGRE -------------------------------------------------------------------------

def _eogre_rows(data: Any) -> list[dict[str, Any]]:
    if not isinstance(data, dict) or not data:
        return []
    rows: list[tuple[str, str]] = []
    if "greEnable" in data:
        rows.append(("EoGRE Tunnel", _enabled(data["greEnable"])))
    for key, label, suffix in (
        ("tunnelMtu", "MTU", ""),
        ("interval", "Keepalive Interval", " s"),
        ("maxCount", "Max Missed Keepalives", ""),
        ("primaryAddress", "Primary Gateway", ""),
        ("secondaryAddress", "Secondary Gateway", ""),
    ):
        if data.get(key) not in (None, ""):
            rows.append((label, f"{data[key]}{suffix}"))
    return [{"Setting": k, "Value": v} for k, v in rows]


# IPsec failover ------------------------------------------------------------------

_IPSEC_STATE_MAP: dict[int, str] = {0: "Active", 1: "Standby", 2: "Disconnected"}


def _ipsec_ref(info: Any) -> str:
    if not isinstance(info, dict):
        return _flatten(info)
    name = _flatten(info.get("name") or info.get("id", ""))
    if isinstance(info.get("status"), int):
        return f"{name} ({_IPSEC_STATE_MAP.get(info['status'], info['status'])})"
    return name


def _ipsec_failover_rows(data: Any) -> list[dict[str, Any]]:
    items = data if isinstance(data, list) else []
    rows = []
    for f in items:
        if not isinstance(f, dict):
            continue
        if f.get("failBack"):
            failback = "Enabled"
            if f.get("failBackTime") is not None:
                failback += f" (after {f['failBackTime']})"
        else:
            failback = "Disabled"
        rows.append({
            "Name": _flatten(f.get("name", "")),
            "Primary Tunnel": _ipsec_ref(f.get("primary")),
            "Candidates": " → ".join(_ipsec_ref(c) for c in f.get("candidates") or []),
            "Failback": failback,
        })
    return rows


# --- WAN failover / load balancing ------------------------------------------------

_BACKUP_MODE_MAP: dict[int, str] = {
    0: "Stay on backup until it fails (no automatic switch-back)",
    1: "Return to primary when it recovers",
}
_BACKUP_TRIGGER_MAP: dict[int, str] = {
    0: "When any primary WAN fails",
    1: "When all primary WANs fail",
    2: "On schedule",
}


def _port_number(port_id: Any) -> tuple[int, str]:
    prefix = str(port_id).split("_", 1)[0]
    return (int(prefix), str(port_id)) if prefix.isdigit() else (10**6, str(port_id))


def _wan_failover_names(data: dict[str, Any], context: dict[str, Any] | None) -> dict[str, str]:
    names = dict(_wan_port_names(context))
    internet = data.get("internet") if isinstance(data.get("internet"), dict) else {}
    for port in internet.get("portList") or []:
        if isinstance(port, dict) and port.get("portId"):
            names.setdefault(str(port["portId"]), _flatten(port.get("portName") or port["portId"]))
    return names


def _wan_failover_rows(data: Any, context: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    if not isinstance(data, dict) or not data:
        return []
    names = _wan_failover_names(data, context)
    lb = data.get("loadBalance") if isinstance(data.get("loadBalance"), dict) else {}
    internet = data.get("internet") if isinstance(data.get("internet"), dict) else {}
    rows: list[tuple[str, str]] = []
    if "interval" in internet:
        interval = internet["interval"]
        rows.append(("Health Check (Online Detection)",
                     "Disabled" if interval == 0 else f"Every {interval} s"))
    if lb:
        rows.append(("Link Backup (Failover)", _enabled(lb.get("linkBackup"))))
        if lb.get("linkBackup"):
            rows.append(("Primary WANs", _nat_interfaces(lb.get("primaryWans"), names)))
            if lb.get("backupWan"):
                rows.append(("Backup WAN", names.get(str(lb["backupWan"]), str(lb["backupWan"]))))
            if lb.get("mode") is not None:
                trigger = _profile_code(lb["mode"], _BACKUP_TRIGGER_MAP)
                if lb["mode"] == 2 and lb.get("timeRangeId"):
                    schedule = _ssid_lookups(context)["schedule"].get(str(lb["timeRangeId"]), lb["timeRangeId"])
                    trigger += f" ({schedule})"
                rows.append(("Backup Trigger", trigger))
            if lb.get("backupMode") is not None:
                rows.append(("Backup Mode", _profile_code(lb["backupMode"], _BACKUP_MODE_MAP)))
            if lb.get("method"):
                rows.append(("Backup Method", _flatten(lb["method"])))
        if "appOptRouting" in lb:
            rows.append(("Application Optimized Routing", _enabled(lb["appOptRouting"])))
        weights = lb.get("weights")
        if isinstance(weights, list) and weights:
            wan_ports = sorted(
                (str(p["portId"]) for p in internet.get("portList") or []
                 if isinstance(p, dict) and p.get("portId") and p.get("portMode", 0) == 0),
                key=_port_number,
            )
            if len(wan_ports) == len(weights):
                text = ", ".join(f"{names.get(pid, pid)}: {w}" for pid, w in zip(wan_ports, weights))
            else:
                text = ", ".join(str(w) for w in weights)
            rows.append(("Load Balancing Weights", text))
        vw = [
            f"{_flatten(v.get('name') or v.get('virtualWanId', ''))}: {v.get('weight', '')}"
            for v in lb.get("virtualWanWeights") or [] if isinstance(v, dict)
        ]
        if vw:
            rows.append(("Virtual WAN Weights", ", ".join(vw)))
    return [{"Setting": k, "Value": v} for k, v in rows if v != ""]


def _wan_failover_details(
    data: Any, context: dict[str, Any] | None = None,
) -> list[tuple[str, list[dict[str, Any]]]]:
    if not isinstance(data, dict):
        return []
    health = []
    for h in data.get("wanHealth") or []:
        if not isinstance(h, dict):
            continue
        mode = h.get("mode")
        if mode == 1:  # LAN-mode port: no WAN health to report
            continue
        speed = _profile_code(h.get("speed", ""), _STATUS_SPEED_MAP) if h.get("speed") else ""
        health.append({
            "Gateway": _flatten(h.get("gatewayName", "")),
            "WAN": _flatten(h.get("name", "")),
            "Link": ("Connected" if h.get("status") == 1 else "Disconnected") if "status" in h else "",
            "Internet": ("Online" if h.get("internetState") == 1 else "Offline") if "internetState" in h else "",
            "Online Detection": ("Online" if h.get("onlineDetection") == 1 else "Offline")
            if "onlineDetection" in h else "",
            "IP": _flatten(h.get("ip", "")),
            "Connection": _flatten(h.get("proto", "")),
            "Speed": speed,
            "Latency": f"{h['latency']} ms" if h.get("latency") is not None else "",
            "Packet Loss": f"{h['loss']}%" if h.get("loss") is not None else "",
            "Health Level": _flatten(h.get("healthLevel", "")),
        })
    return [("WAN Health (status at export time)", health)] if health else []


# --- DNS ----------------------------------------------------------------------------

_DNS_PROXY_TYPE_MAP: dict[int, str] = {0: "DNSSEC", 1: "DNS over HTTPS", 2: "DNS over TLS", 3: "DNS Override"}
_DOH_SERVER_MAP: dict[int, str] = {0: "Google", 1: "Cloudflare", 4: "CleanBrowsing", 5: "Quad9 (1)", 6: "Quad9 (2)"}
_DOT_SERVER_MAP: dict[int, str] = {0: "Google", 1: "Cloudflare", 2: "OpenDNS", 3: "Quad9", 4: "CleanBrowsing"}
_BOGUS_REPLY_MAP: dict[int, str] = {0: "Pass", 1: "Drop"}
_LAN_DNS_TYPE_MAP: dict[int, str] = {0: "IP", 1: "CNAME", 2: "Forward"}
_DDNS_SERVICE_MAP: dict[int, str] = {
    0: "DynDNS", 1: "NO-IP", 2: "Peanuthull", 3: "Comexe", 4: "Custom", 5: "TP-Link DDNS",
}


def _dns_custom_servers(servers: Any, key: str) -> list[str]:
    out = []
    for srv in servers or []:
        if isinstance(srv, dict) and srv.get("enable", True):
            target = srv.get(key)
            target = ", ".join(str(t) for t in target) if isinstance(target, list) else _flatten(target)
            out.append(f"{srv.get('name', 'Custom')} ({target})" if target else _flatten(srv.get("name", "")))
    return out


def _dns_settings_rows(data: Any, context: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    if not isinstance(data, dict) or not data:
        return []
    lookup = _build_id_lookup(context)
    rows: list[tuple[str, str]] = []
    proxy = data.get("dnsProxy") if isinstance(data.get("dnsProxy"), dict) else None
    if proxy is not None:
        rows.append(("DNS Proxy", _enabled(proxy.get("enable"))))
        if proxy.get("enable"):
            kind = proxy.get("type")
            rows.append(("DNS Proxy Type", _profile_code(kind, _DNS_PROXY_TYPE_MAP) if kind is not None else ""))
            if kind == 0 and isinstance(proxy.get("dnsSecSetting"), dict):
                sec = proxy["dnsSecSetting"]
                rows.append(("DNSSEC Servers", ", ".join(str(x) for x in sec.get("servers") or [])))
                if sec.get("replyPolicy") is not None:
                    rows.append(("Bogus Reply Policy", _profile_code(sec["replyPolicy"], _BOGUS_REPLY_MAP)))
            for k, key, smap, ckey in ((1, "dohSetting", _DOH_SERVER_MAP, "server"),
                                       (2, "dotSetting", _DOT_SERVER_MAP, "servers")):
                if kind == k and isinstance(proxy.get(key), dict):
                    cfg = proxy[key]
                    servers = [_profile_code(x, smap) for x in cfg.get("defaultServers") or []]
                    servers += _dns_custom_servers(cfg.get("customizedServers"), ckey)
                    rows.append(("Upstream Servers", ", ".join(servers)))
            if kind == 3 and isinstance(proxy.get("dnsOverrideSetting"), dict):
                ov = proxy["dnsOverrideSetting"]
                rows.append(("Override Servers", ", ".join(
                    str(x) for x in (ov.get("primaryDnsServer"), ov.get("secondaryDnsServer")) if x)))
                rows.append(("Override Applies To", _resolve_ids(ov.get("applyNetwork") or [], lookup)))
    cache = data.get("dnsCache") if isinstance(data.get("dnsCache"), dict) else None
    if cache is not None:
        text = _enabled(cache.get("enable"))
        if cache.get("enable") and cache.get("ttl") is not None:
            text += f" (TTL {cache['ttl']} s)"
        rows.append(("DNS Cache", text))
    if isinstance(data.get("lanDns"), list):
        rows.append(("LAN DNS Records", str(len(data["lanDns"]))))
    if isinstance(data.get("ddns"), list):
        rows.append(("Dynamic DNS Entries", str(len(data["ddns"]))))
    return [{"Setting": k, "Value": v} for k, v in rows if v != ""]


def _dns_settings_details(
    data: Any, context: dict[str, Any] | None = None,
) -> list[tuple[str, list[dict[str, Any]]]]:
    if not isinstance(data, dict):
        return []
    lookup = _build_id_lookup(context)
    wan_names = _wan_port_names(context)
    records = []
    for r in data.get("lanDns") or []:
        if not isinstance(r, dict):
            continue
        kind = r.get("type")
        if kind == 1:
            answer = _flatten(r.get("cname", ""))
        elif kind == 2:
            answer = "Forward to " + ", ".join(str(x) for x in r.get("dnsServers") or [])
        else:
            answer = ", ".join(str(x) for x in (r.get("ipAddresses") or []) + (r.get("ipv6Addresses") or []))
        records.append({
            "Name": _flatten(r.get("name", "")),
            "Status": _enabled(r.get("enable")),
            "Domain": _flatten(r.get("domain", "")),
            "Aliases": ", ".join(str(a) for a in r.get("aliases") or []),
            "Type": _profile_code(kind, _LAN_DNS_TYPE_MAP) if kind is not None else "",
            "Answer": answer,
            "Networks": _resolve_ids(r.get("lanNetworkIds") or [], lookup),
            "TTL": f"{r['ttl']} s" if r.get("customTtl") and r.get("ttl") is not None else "Default (3600 s)",
        })
    ddns = []
    for r in data.get("ddns") or []:
        if not isinstance(r, dict):
            continue
        if r.get("customInterval"):
            interval = f"{r['customInterval']} min"
        else:
            interval = f"{r['updateInterval']} h" if r.get("updateInterval") is not None else ""
        ddns.append({
            "Service": _profile_code(r.get("service", ""), _DDNS_SERVICE_MAP),
            "Status": _enabled(r.get("status")),
            "Domain": _flatten(r.get("domainName", "")),
            "Interface": wan_names.get(str(r.get("interfacePortId", "")), _flatten(r.get("interfacePortId", ""))),
            "Username": _flatten(r.get("username", "")),
            "Password": _secret_state(r.get("password")),
            "Update Interval": interval,
            "Update URL": _flatten(r.get("updateUrl", "")),
        })
    sections = []
    if records:
        sections.append(("LAN DNS Records", sorted(records, key=lambda x: str(x["Domain"]).lower())))
    if ddns:
        sections.append(("Dynamic DNS", ddns))
    return sections


# --- Time / NTP ---------------------------------------------------------------------

_DST_MODE_MAP: dict[int, str] = {0: "Disabled", 1: "Automatic", 2: "Manual"}


def _time_settings_rows(data: Any) -> list[dict[str, Any]]:
    if not isinstance(data, dict) or not data:
        return []
    rows: list[tuple[str, str]] = []
    site = data.get("site") if isinstance(data.get("site"), dict) else {}
    if site.get("timeZone"):
        rows.append(("Time Zone", _flatten(site["timeZone"])))
    if site.get("region"):
        rows.append(("Region", _flatten(site["region"])))
    if "ntpServers" in site:
        rows.append(("NTP Servers", ", ".join(str(n) for n in site.get("ntpServers") or []) or "Default"))
    dst = data.get("dst") if isinstance(data.get("dst"), dict) else {}
    if dst:
        if "mode" in dst:
            mode = _profile_code(dst["mode"], _DST_MODE_MAP)
        else:
            mode = _enabled(dst.get("enable"))
        rows.append(("Daylight Saving Time", mode))
        if dst.get("enable") and dst.get("offset"):
            rows.append(("DST Offset", f"{int(dst['offset']) // 60000} min"))
        if dst.get("mode") == 2:
            for key, label in (("start", "DST Start"), ("end", "DST End")):
                if isinstance(dst.get(key), dict):
                    rows.append((label, ", ".join(f"{k}={v}" for k, v in dst[key].items())))
    ntp = data.get("ntpStatus")
    if isinstance(ntp, dict) and ntp:
        rows.append(("NTP Status", ", ".join(f"{k}={_flatten(v)}" for k, v in ntp.items())))
    elif ntp not in (None, "", {}):
        rows.append(("NTP Status", _flatten(ntp)))
    return [{"Setting": k, "Value": v} for k, v in rows if v != ""]


# --- Multicast / Bonjour ----------------------------------------------------------------

_IPTV_MODE_MAP: dict[int, str] = {0: "Bridge", 1: "Custom"}
_IPTV_PORT_TYPE_MAP: dict[int, str] = {1: "Internet", 2: "IPTV", 3: "IP Phone"}
_MDNS_TYPE_MAP: dict[int, str] = {0: "By VLAN ID", 1: "By Network"}
_SNOOP_PROTOCOL_MAP: dict[int, str] = {0: "IGMP Snooping", 1: "MLD Snooping"}
_UNKNOWN_MCAST_MAP: dict[int, str] = {0: "Forward", 1: "Discard", 2: "Router port first"}


def _multicast_services_rows(data: Any, context: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    if not isinstance(data, dict) or not data:
        return []
    lookup = _build_id_lookup(context)
    wan_names = _wan_port_names(context)
    rows: list[tuple[str, str, str]] = []

    def wan(port_id: Any) -> str:
        return wan_names.get(str(port_id), str(port_id)) if port_id else ""

    for key, label, versions in (("igmp", "IGMP Proxy", {2: "v2", 3: "v3"}), ("mld", "MLD Proxy", {1: "v1", 2: "v2"})):
        cfg = data.get(key)
        if isinstance(cfg, dict) and cfg:
            text = _enabled(cfg.get("enable"))
            if cfg.get("enable"):
                extras = [versions.get(cfg.get("version"), str(cfg.get("version", "")))]
                upstream = wan(cfg.get("wanPortId")) or (
                    f"Virtual WAN {cfg['virtualWanId']}" if cfg.get("virtualWanId") else "")
                if upstream:
                    extras.append(f"upstream {upstream}")
                text += f" ({', '.join(e for e in extras if e)})"
            rows.append(("Multicast", label, text))
    iptv = data.get("iptv")
    if isinstance(iptv, dict) and iptv:
        text = _enabled(iptv.get("enable"))
        if iptv.get("enable"):
            text += f" ({_profile_code(iptv.get('mode', ''), _IPTV_MODE_MAP)}"
            text += f", WAN {wan(iptv.get('wanPortId'))})" if iptv.get("wanPortId") else ")"
        rows.append(("Multicast", "IPTV", text))
        custom = iptv.get("customConfig") if isinstance(iptv.get("customConfig"), dict) else {}
        if iptv.get("enable") and iptv.get("mode") == 1 and custom:
            rows.append(("Multicast", "IPTV VLAN",
                         f"{custom.get('iptvVlanId', '')} (priority {custom.get('iptvVlanPriority', '')})"))
            rows.append(("Multicast", "IP Phone VLAN",
                         f"{custom.get('ipPhoneVlanId', '')} (priority {custom.get('ipPhoneVlanPriority', '')})"))
        ports = [
            f"{p.get('name') or p.get('portId', '')}: {_profile_code(p.get('type', ''), _IPTV_PORT_TYPE_MAP)}"
            for p in iptv.get("portConfig") or [] if isinstance(p, dict)
        ]
        if iptv.get("enable") and ports:
            rows.append(("Multicast", "IPTV Port Roles", ", ".join(ports)))
    upnp = data.get("upnp")
    if isinstance(upnp, dict) and upnp:
        text = _enabled(upnp.get("enable"))
        if upnp.get("enable"):
            parts = []
            if upnp.get("wanPortIds"):
                parts.append("WAN " + _nat_interfaces(upnp["wanPortIds"], wan_names))
            if upnp.get("networkIds"):
                parts.append("LAN " + _resolve_ids(upnp["networkIds"], lookup))
            if parts:
                text += f" ({'; '.join(parts)})"
        rows.append(("Services", "UPnP", text))
    if isinstance(data.get("mdnsRules"), list):
        enabled = sum(1 for r in data["mdnsRules"] if isinstance(r, dict) and r.get("status"))
        rows.append(("Bonjour / mDNS", "mDNS Rules", f"{len(data['mdnsRules'])} ({enabled} enabled)"))
    if isinstance(data.get("bonjourServices"), list):
        rows.append(("Bonjour / mDNS", "Bonjour Service Profiles", str(len(data["bonjourServices"]))))
    if isinstance(data.get("lanMulticasts"), list):
        rows.append(("Multicast", "Multicast Snooping Configs", str(len(data["lanMulticasts"]))))
    return [{"Category": c, "Setting": s, "Value": v} for c, s, v in rows]


def _multicast_services_details(
    data: Any, context: dict[str, Any] | None = None,
) -> list[tuple[str, list[dict[str, Any]]]]:
    if not isinstance(data, dict):
        return []
    lookup = _build_id_lookup(context)
    profiles = {
        str(b["id"]): _flatten(b.get("name") or b["id"])
        for b in data.get("bonjourServices") or [] if isinstance(b, dict) and b.get("id")
    }
    rules = []
    for r in data.get("mdnsRules") or []:
        if not isinstance(r, dict):
            continue
        if r.get("type") == 1:
            osg = r.get("osg") if isinstance(r.get("osg"), dict) else {}
            service = _resolve_ids(osg.get("serviceNetworks") or [], lookup)
            client = _resolve_ids(osg.get("clientNetworks") or [], lookup)
        else:
            ap = r.get("ap") if isinstance(r.get("ap"), dict) else {}
            service = f"VLAN {ap['serviceVlan']}" if ap.get("serviceVlan") else ""
            client = f"VLAN {ap['clientVlan']}" if ap.get("clientVlan") else ""
        rules.append({
            "Name": _flatten(r.get("name", "")),
            "Status": _enabled(r.get("status")),
            "Services": ", ".join(profiles.get(str(i), str(i)) for i in r.get("profileIds") or []),
            "Mode": _profile_code(r.get("type", ""), _MDNS_TYPE_MAP),
            "Service Networks": service,
            "Client Networks": client,
        })
    bonjour = [
        {
            "Name": _flatten(b.get("name", "")),
            "Service IDs": ", ".join(str(s) for s in b.get("serviceIds") or []),
            "Built-in": "Yes" if b.get("defaultProfile") else "No",
        }
        for b in data.get("bonjourServices") or [] if isinstance(b, dict)
    ]
    snooping = []
    for m in data.get("lanMulticasts") or []:
        if not isinstance(m, dict):
            continue
        nets = []
        for n in m.get("networks") or []:
            if isinstance(n, dict):
                nets.append(_flatten(n.get("name") or lookup.get(str(n.get("id", "")), n.get("id", ""))))
            else:
                nets.append(lookup.get(str(n), str(n)))
        snoop = m.get("snoopConfig") if isinstance(m.get("snoopConfig"), dict) else {}
        snooping.append({
            "Name": _flatten(m.get("name", "")),
            "Protocol": _profile_code(m.get("protocol", ""), _SNOOP_PROTOCOL_MAP),
            "Networks": ", ".join(x for x in nets if x),
            "Unknown Multicast": _profile_code(m.get("unknownMulticastRule", ""), _UNKNOWN_MCAST_MAP)
            if m.get("unknownMulticastRule") is not None else "",
            "Querier": _enabled(m.get("querierEnable")),
            "Flood Known": _enabled(m.get("floodKnownEnable")),
            "Manual Router Ports": _enabled(m.get("routerPortEnable")),
            "Report Suppression": _enabled(snoop["reportSuppressionEnable"])
            if "reportSuppressionEnable" in snoop else "",
            "Leave Time": f"{snoop['leaveTime']} s" if snoop.get("leaveTime") is not None else "",
        })
    sections = []
    if rules:
        sections.append(("mDNS (Bonjour) Rules", rules))
    if bonjour:
        sections.append(("Bonjour Service Profiles", sorted(bonjour, key=lambda b: str(b["Name"]).lower())))
    if snooping:
        sections.append(("Multicast Snooping", snooping))
    return sections


# --- Link aggregation (LAGs) ---------------------------------------------------------

_LAG_TYPE_MAP: dict[int, str] = {1: "Static", 2: "LACP", 3: "LACP (Active)", 4: "LACP (Passive)"}
_LAG_HASH_MAP: dict[int, str] = {
    0: "Source MAC", 1: "Destination MAC", 2: "Source + Destination MAC",
    3: "Source IP", 4: "Destination IP", 5: "Source + Destination IP",
}
# OswLagStatusVO.linkSpeed codes (differ from the port-status speed codes).
_LAG_SPEED_MAP: dict[int, str] = {0: "Auto", 1: "10M", 2: "100M", 3: "1000M", 4: "2.5G", 5: "10G"}
_MLAG_STATUS_MAP: dict[int, str] = {
    0: "Normal", 1: "Peer error", 2: "DAD error", 3: "Abnormal",
    4: "Configuration unsynchronized", 5: "Members incompatible", 6: "Members mismatch",
}


def _lag_label(lag: dict[str, Any]) -> str:
    return f"LAG {lag['lagId']}" if lag.get("lagId") is not None else "LAG (group unknown)"


def _stand_ports(ports: Any) -> str:
    """Stack ports as ``unit/slot/port``."""
    return ", ".join(
        f"{sp.get('unit', '')}/{sp.get('slot', 0)}/{sp.get('port', '')}"
        for sp in ports or [] if isinstance(sp, dict)
    )


def _lag_members(lag: dict[str, Any]) -> str:
    stand = _stand_ports(lag.get("standardPorts") or lag.get("standPorts") or lag.get("stPorts"))
    return stand or ", ".join(str(p) for p in lag.get("memberPorts") or lag.get("ports") or [])


def _lag_link(lag: dict[str, Any]) -> str:
    status = lag.get("lagStatus") if isinstance(lag.get("lagStatus"), dict) else None
    if status and "linkStatus" in status:
        if status["linkStatus"] != 1:
            return "Down"
        speed = _profile_code(status.get("linkSpeed"), _LAG_SPEED_MAP) if status.get("linkSpeed") else ""
        return f"Up ({speed})" if speed else "Up"
    members = [m for m in lag.get("members") or [] if isinstance(m, dict)]
    if not members:
        return ""
    up = sum(1 for m in members if _port_connection({"deviceType": "switch", **m}).startswith("Connected"))
    return f"{up}/{len(members)} members up"


def _lag_rows(data: Any) -> list[dict[str, Any]]:
    lags = data.get("lags") if isinstance(data, dict) else data
    rows = []
    for lag in lags if isinstance(lags, list) else []:
        if not isinstance(lag, dict):
            continue
        mlag = ""
        if lag.get("mlagEnable"):
            mlag = _flatten(lag.get("mlagName") or "Enabled")
        rows.append({
            "Device": _flatten(lag.get("deviceName", "")),
            "LAG": _lag_label(lag),
            "Name": _flatten(lag.get("name", "")),
            "Mode": _profile_code(lag["lagType"], _LAG_TYPE_MAP) if lag.get("lagType") is not None else "",
            "Member Ports": _lag_members(lag),
            "Link": _lag_link(lag),
            "Profile": _flatten(lag.get("profileName", "")),
            "M-LAG": mlag,
        })
    return rows


def _lag_details(
    data: Any, context: dict[str, Any] | None = None,
) -> list[tuple[str, list[dict[str, Any]]]]:
    if not isinstance(data, dict):
        return []
    sections: list[tuple[str, list[dict[str, Any]]]] = []
    for lag in data.get("lags") or []:
        if not isinstance(lag, dict) or not lag.get("members"):
            continue
        members = [
            {
                "Port": _flatten(m.get("port", "")),
                "Name": _flatten(m.get("portName", m.get("name", ""))),
                "Connection": _port_connection({"deviceType": "switch", **m}),
                "Profile": _flatten(m.get("profileName", "")),
            }
            for m in lag["members"] if isinstance(m, dict)
        ]
        sections.append((f"{_flatten(lag.get('deviceName', ''))} {_lag_label(lag)} members", members))
    mlag = []
    for group in data.get("mlagGroups") or []:
        if not isinstance(group, dict):
            continue
        members = group.get("members") or []
        mlag.append({
            "Name": _flatten(group.get("name", "")),
            "Status": _profile_code(group["status"], _MLAG_STATUS_MAP) if group.get("status") is not None else "",
            "Members": ", ".join(
                f"{_flatten(m.get('name') or m.get('mac', ''))}" + (f" ({m['role']})" if m.get("role") else "")
                for m in members if isinstance(m, dict)
            ),
            "Peer Link Ports": "; ".join(
                f"{_flatten(m.get('name') or m.get('mac', ''))}: {_flatten(m.get('peerLinkPorts'))}"
                for m in members if isinstance(m, dict) and m.get("peerLinkPorts")
            ),
        })
    if mlag:
        sections.append(("M-LAG Groups", mlag))
    hash_alg = data.get("hashAlgorithm")
    if isinstance(hash_alg, dict) and hash_alg.get("type") is not None:
        sections.append(("Site LAG Settings", [
            {"Setting": "Hash Algorithm", "Value": _profile_code(hash_alg["type"], _LAG_HASH_MAP)},
        ]))
    return sections


# --- Switch-wide settings ---------------------------------------------------------------

_LED_MAP: dict[int, str] = {0: "Off", 1: "On", 2: "Site setting"}
_SNMP_TYPE_MAP: dict[int, str] = {0: "Site setting", 1: "Custom"}
_SWITCH_STP_NOTE = (
    "Not exposed by the Open API (switch-wide STP mode / bridge priority); "
    "see RPVST instances and per-port STP below"
)


def _site_jumbo(data: dict[str, Any]) -> Any:
    jumbo = (data.get("site") or {}).get("jumbo") if isinstance(data.get("site"), dict) else None
    return jumbo.get("size") if isinstance(jumbo, dict) else None


def _switch_jumbo(general: dict[str, Any], site_size: Any) -> str:
    if not general:
        return ""
    if general.get("jumboFollowSite", True):
        return f"Site setting ({site_size} bytes)" if site_size else "Site setting"
    return f"{general.get('jumbo', '')} bytes (custom)"


def _switch_ip(ip: Any) -> str:
    """Switch VLAN-interface addressing: ``Static 10.0.0.2 255.255.255.0 (gw 10.0.0.1)`` / ``DHCP``."""
    if not isinstance(ip, dict) or not ip:
        return ""
    if ip.get("mode") == 1:
        text = "DHCP"
        if ip.get("useFixedAddr") and ip.get("dhcpIp"):
            text += f" (reserved {ip['dhcpIp']})"
        if ip.get("fallback") and ip.get("fallbackIp"):
            text += f", fallback {ip['fallbackIp']}"
        return text
    text = " ".join(str(x) for x in (ip.get("ip"), ip.get("netmask")) if x)
    if ip.get("mode") == 0:
        text = f"Static {text}".strip()
    if ip.get("gateway"):
        text += f" (gw {ip['gateway']})"
    return text


def _switch_mgmt_vlan(networks: Any) -> str:
    for n in networks if isinstance(networks, list) else []:
        if isinstance(n, dict) and n.get("mvlan"):
            name = _flatten(n.get("name", ""))
            text = f"VLAN {n.get('vlan', '')}" + (f" ({name})" if name else "")
            addressing = _switch_ip(n.get("ip"))
            return f"{text}, {addressing}" if addressing else text
    return ""


def _rpvst_instances(raw: Any) -> list[dict[str, Any]]:
    """RPVST instances; the spec leaves the shape untyped, so accept common wrappers."""
    if isinstance(raw, dict):
        for key in ("data", "instances", "rpvstInstances", "list"):
            if isinstance(raw.get(key), list):
                raw = raw[key]
                break
    return [i for i in raw if isinstance(i, dict)] if isinstance(raw, list) else []


def _switch_port_protection(mac: Any, context: dict[str, Any] | None) -> dict[str, Any]:
    """Loop-prevention coverage of a switch's ports, via each port's profile."""
    ctx = context or {}
    profiles = {
        str(pr.get("id")): pr for pr in ctx.get("switch_port_profiles") or []
        if isinstance(pr, dict) and pr.get("id")
    }
    by_name = {str(pr.get("name")): pr for pr in profiles.values() if pr.get("name")}
    totals = {"ports": 0, "loopback": 0, "loopbackVlan": 0, "stp": 0, "unknown": 0, "overridden": 0}
    for port in ctx.get("device_ports") or []:
        if not isinstance(port, dict) or str(port.get("deviceMac", "")).upper() != str(mac).upper():
            continue
        if port.get("deviceType") not in (None, "switch"):
            continue
        totals["ports"] += 1
        if port.get("profileOverrideEnable"):
            totals["overridden"] += 1
        profile = profiles.get(str(port.get("profileId", ""))) or by_name.get(str(port.get("profileName", "")))
        if profile is None:
            totals["unknown"] += 1
            continue
        totals["loopback"] += bool(profile.get("loopbackDetectEnable"))
        totals["loopbackVlan"] += bool(profile.get("loopbackDetectVlanBasedEnable"))
        totals["stp"] += bool(profile.get("spanningTreeEnable"))
    return totals


def _protection_text(t: dict[str, Any], key: str) -> str:
    if not t["ports"]:
        return ""
    known = t["ports"] - t["unknown"]
    text = f"{t[key]}/{known} ports"
    if t["unknown"]:
        text += f" ({t['unknown']} with unknown profile)"
    return text


def _switch_settings_rows(data: Any, context: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    if not isinstance(data, dict):
        return []
    site_size = _site_jumbo(data)
    rows = []
    for sw in data.get("switches") or []:
        if not isinstance(sw, dict):
            continue
        general = sw.get("general") if isinstance(sw.get("general"), dict) else {}
        protection = _switch_port_protection(sw.get("deviceMac", ""), context)
        rpvst = [i for i in _rpvst_instances(sw.get("rpvst")) if i.get("enable", True)]
        stp = _protection_text(protection, "stp")
        if rpvst:
            stp = (stp + "; " if stp else "") + f"RPVST: {len(rpvst)} VLAN instance(s)"
        rows.append({
            "Switch": _flatten(sw.get("deviceName", "")),
            "Model": _flatten(sw.get("deviceModel", "")),
            "Management VLAN": _switch_mgmt_vlan(sw.get("networks")),
            "Jumbo Frames": _switch_jumbo(general, site_size),
            "STP (ports)": stp,
            "Loopback Detection (ports)": _protection_text(protection, "loopback"),
            "LAG Hash": (
                "Site setting" if general.get("lagHashAlgFollowSite", True)
                else _profile_code(general.get("lagHashAlg", ""), _LAG_HASH_MAP)
            ) if general else "",
            "LED": _profile_code(general["ledSetting"], _LED_MAP) if general.get("ledSetting") is not None else "",
        })
    return rows


def _switch_settings_details(
    data: Any, context: dict[str, Any] | None = None,
) -> list[tuple[str, list[dict[str, Any]]]]:
    if not isinstance(data, dict):
        return []
    sections: list[tuple[str, list[dict[str, Any]]]] = []

    site_rows: list[tuple[str, str]] = []
    size = _site_jumbo(data)
    if size:
        site_rows.append(("Jumbo Frame Size", f"{size} bytes"))
    lldp = (data.get("site") or {}).get("lldp") if isinstance(data.get("site"), dict) else None
    if isinstance(lldp, dict):
        inner = lldp.get("lldp") if isinstance(lldp.get("lldp"), dict) else lldp
        if "enable" in inner:
            site_rows.append(("LLDP", _enabled(inner["enable"])))
    site_rows.append(("Switch-wide STP Mode / Priority", _SWITCH_STP_NOTE))
    snooping = [
        f"{_flatten(n.get('name', ''))}: {_enabled(n.get('igmpSnoopEnable'))}"
        for n in (context or {}).get("networks") or []
        if isinstance(n, dict) and "igmpSnoopEnable" in n
    ]
    if snooping:
        site_rows.append(("IGMP Snooping (per network)", "; ".join(snooping)))
    sections.append(("Site Switch Settings", [{"Setting": k, "Value": v} for k, v in site_rows]))

    for sw in data.get("switches") or []:
        if not isinstance(sw, dict):
            continue
        name = _flatten(sw.get("deviceName", "")) or _flatten(sw.get("deviceMac", ""))
        general = sw.get("general") if isinstance(sw.get("general"), dict) else {}
        protection = _switch_port_protection(sw.get("deviceMac", ""), context)
        rows: list[tuple[str, str, str]] = [
            ("General", "Management VLAN", _switch_mgmt_vlan(sw.get("networks")) or "Not identified"),
            ("General", "Jumbo Frames", _switch_jumbo(general, size)),
        ]
        if general.get("ledSetting") is not None:
            rows.append(("General", "LED", _profile_code(general["ledSetting"], _LED_MAP)))
        snmp = general.get("snmp") if isinstance(general.get("snmp"), dict) else {}
        if snmp:
            if snmp.get("type") == 1:
                rows.append(("General", "SNMP", f"Custom (location {snmp.get('location', '')!s}, "
                                                f"contact {snmp.get('contact', '')!s})"))
            else:
                rows.append(("General", "SNMP", "Site setting"))
        sdm = general.get("sdm") if isinstance(general.get("sdm"), dict) else {}
        if sdm.get("inUse"):
            rows.append(("General", "SDM Template", _flatten(sdm["inUse"])))
        if general:
            rows.append(("General", "LAG Hash Algorithm",
                         "Site setting" if general.get("lagHashAlgFollowSite", True)
                         else _profile_code(general.get("lagHashAlg", ""), _LAG_HASH_MAP)))
        rows.append(("Loop Prevention", "STP Enabled", _protection_text(protection, "stp")))
        rows.append(("Loop Prevention", "Loopback Detection (port based)", _protection_text(protection, "loopback")))
        rows.append(("Loop Prevention", "Loopback Detection (VLAN based)",
                     _protection_text(protection, "loopbackVlan")))
        if protection["overridden"]:
            rows.append(("Loop Prevention", "Ports with Profile Override",
                         f"{protection['overridden']} (their own settings may differ from the profile)"))
        rows.append(("Spanning Tree", "Switch-wide Mode / Priority", _SWITCH_STP_NOTE))
        rows = [r for r in rows if r[2] != ""]
        sections.append((name, _detail_rows(rows)))

        interfaces = []
        for n in sw.get("networks") if isinstance(sw.get("networks"), list) else []:
            if not isinstance(n, dict):
                continue
            interfaces.append({
                "VLAN": _flatten(n.get("vlan", "")),
                "Name": _flatten(n.get("name", "")),
                "Management": "Yes" if n.get("mvlan") else "No",
                "IP": _switch_ip(n.get("ip")),
                "MTU": _flatten(n.get("mtu", "")),
                "DHCP": _profile_code(n["mode"], _SWITCH_DHCP_MODE_MAP) if n.get("mode") is not None else "",
                "IPv6": _enabled(n["ipv6Enable"]) if "ipv6Enable" in n else "",
            })
        if interfaces:
            sections.append((f"{name} VLAN interfaces", interfaces))
        rpvst = _rpvst_instances(sw.get("rpvst"))
        if rpvst:
            sections.append((f"{name} RPVST instances", [
                {
                    "VLAN": _flatten(i.get("vlan", "")),
                    "Priority": _flatten(i.get("priority", "")),
                    "Enabled": _enabled(i["enable"]) if "enable" in i else "",
                }
                for i in rpvst
            ]))
    return sections


# --- Per-port overrides (port config vs. assigned profile) ----------------------------

# OswPortVO codes for port-level settings that have no profile equivalent.
_PORT_CFG_SPEED_MAP: dict[int, str] = {0: "Auto", 1: "10M", 2: "100M", 3: "1000M", 4: "10G"}
_PORT_CFG_DUPLEX_MAP: dict[int, str] = {0: "Auto", 1: "Half", 2: "Full"}
_PORT_POE_MAP: dict[int, str] = {0: "Off", 1: "On"}


def _ctrl_text(value: Any) -> str:
    if not isinstance(value, dict) or not value:
        return ""
    return ", ".join(f"{k}={_flatten(v)}" for k, v in sorted(value.items()) if v not in (None, ""))


def _relay_text(value: Any) -> str:
    if not isinstance(value, dict):
        return _flatten(value)
    text = _enabled(value.get("enable"))
    if value.get("enable") and value.get("format") is not None:
        text += f" ({_profile_code(value['format'], _RELAY_FORMAT_MAP)})"
    return text


# (key, label, kind): kind is "bool", "net", "nets", "ctrl", "relay", a code map, or None (raw).
_OVERRIDE_FIELDS: tuple[tuple[str, str, Any], ...] = (
    ("poe", "PoE", _PORT_POE_MAP),
    ("dot1x", "802.1X", _DOT1X_MAP),
    ("bandWidthCtrlType", "Bandwidth Control", _BANDWIDTH_CTRL_MAP),
    ("bandCtrl", "Rate Limit", "ctrl"),
    ("stormCtrl", "Storm Control", "ctrl"),
    ("portIsolationEnable", "Port Isolation", "bool"),
    ("voiceNetworkEnable", "Voice Network", "bool"),
    ("voiceNetworkId", "Voice Network VLAN", "net"),
    ("voiceDscpEnable", "Voice DSCP", "bool"),
    ("voiceDscp", "Voice DSCP Value", None),
    ("loopbackDetectEnable", "Loopback Detection", "bool"),
    ("loopbackDetectVlanBasedEnable", "Loopback Detection (VLAN based)", "bool"),
    ("spanningTreeEnable", "Spanning Tree", "bool"),
    ("lldpMedEnable", "LLDP-MED", "bool"),
    ("topoNotifyEnable", "Topology Change Notification", "bool"),
    ("eeeEnable", "EEE", "bool"),
    ("flowControlEnable", "Flow Control", "bool"),
    ("fastLeaveEnable", "IGMP Snooping Fast Leave", "bool"),
    ("igmpFastLeaveEnable", "IGMP Fast Leave", "bool"),
    ("mldFastLeaveEnable", "MLD Fast Leave", "bool"),
    ("dhcpL2RelaySettings", "DHCP L2 Relay", "relay"),
    ("dot1pPriority", "802.1p Priority", None),
    ("trustMode", "Trust Mode", _TRUST_MODE_MAP),
    ("networkTagsSetting", "Network Tags Setting", _NETWORK_TAGS_MAP),
    ("nativeNetworkId", "Native Network", "net"),
    ("untagNetworkIds", "Untagged Networks", "nets"),
    ("tagNetworkIds", "Tagged Networks", "nets"),
)


def _override_value(value: Any, kind: Any, lookup: dict[str, str]) -> str:
    if kind == "bool":
        return _enabled(value)
    if kind == "net":
        return lookup.get(str(value), str(value)) if value else "None"
    if kind == "nets":
        return _resolve_ids(sorted(value or [], key=lambda i: lookup.get(str(i), str(i))), lookup) or "None"
    if kind == "ctrl":
        return _ctrl_text(value)
    if kind == "relay":
        return _relay_text(value)
    if isinstance(kind, dict):
        return _profile_code(value, kind)
    return _flatten(value)


def _override_equal(port_value: Any, profile_value: Any, kind: Any) -> bool:
    if kind == "nets":
        return {str(v) for v in port_value or []} == {str(v) for v in profile_value or []}
    if kind == "bool":
        return bool(port_value) == bool(profile_value)
    if kind in ("ctrl", "relay"):
        if not isinstance(port_value, dict) or not isinstance(profile_value, dict):
            return port_value == profile_value
        common = set(port_value) & set(profile_value)
        return all(port_value[k] == profile_value[k] for k in common)
    if kind == "net":
        return (port_value or None) == (profile_value or None)
    return port_value == profile_value


def _port_profile(p: dict[str, Any], context: dict[str, Any] | None) -> dict[str, Any] | None:
    profiles = [pr for pr in (context or {}).get("switch_port_profiles") or [] if isinstance(pr, dict)]
    for pr in profiles:
        if p.get("profileId") and str(pr.get("id")) == str(p["profileId"]):
            return pr
    for pr in profiles:
        if p.get("profileName") and str(pr.get("name")) == str(p["profileName"]):
            return pr
    return None


def _port_overrides(p: dict[str, Any], context: dict[str, Any] | None) -> list[tuple[str, str, str]]:
    """Settings where a switch port differs from its profile, or is set per port.

    Returns ``(setting, port value, profile value)``; port-level settings with
    no profile equivalent use ``"(port-level)"`` as the profile value.
    """
    if p.get("deviceType") not in (None, "switch"):
        return []
    lookup = _build_id_lookup(context)
    diffs: list[tuple[str, str, str]] = []
    profile = _port_profile(p, context)
    if profile is not None:
        port_bw = p.get("bandWidthCtrlType")
        for key, label, kind in _OVERRIDE_FIELDS:
            if key not in p or key not in profile:
                continue
            if key == "poe" and profile.get("poe") == 2:  # profile: use device setting
                continue
            if key == "bandCtrl" and not (port_bw == 1 and profile.get("bandWidthCtrlType") == 1):
                continue
            if key == "stormCtrl" and not (port_bw == 2 and profile.get("bandWidthCtrlType") == 2):
                continue
            if not _override_equal(p[key], profile[key], kind):
                diffs.append((label, _override_value(p[key], kind, lookup),
                              _override_value(profile[key], kind, lookup)))
    if p.get("linkSpeed") not in (None, 0):
        diffs.append(("Speed", _profile_code(p["linkSpeed"], _PORT_CFG_SPEED_MAP), "(port-level)"))
    if p.get("duplex") not in (None, 0):
        diffs.append(("Duplex", _profile_code(p["duplex"], _PORT_CFG_DUPLEX_MAP), "(port-level)"))
    if str(p.get("operation", "")).upper() == "MIRRORING":
        mirrored = ", ".join(str(m) for m in p.get("mirroredPorts") or [])
        diffs.append(("Operation", f"Mirroring{f' ports {mirrored}' if mirrored else ''}", "(port-level)"))
    if p.get("disable") is True:
        diffs.append(("Port", "Disabled", "(port-level)"))
    for key, label in (("poeSchedules", "PoE Schedule"), ("portSchedules", "Port Schedule")):
        if p.get(key):
            diffs.append((label, ", ".join(str(n) for n in p[key]), "(port-level)"))
    if p.get("networkConflict"):
        diffs.append(("VLAN Conflict", "Port VLANs differ from the profile", "(reported by controller)"))
    return diffs


def _device_port_details(
    data: Any, context: dict[str, Any] | None = None,
) -> list[tuple[str, list[dict[str, Any]]]]:
    items = data if isinstance(data, list) else []
    rows = []
    for p in items:
        if not isinstance(p, dict):
            continue
        mode = []
        if p.get("profileOverrideEnable"):
            mode.append("custom port settings")
        if p.get("profileVlanOverrideEnable"):
            mode.append("custom VLANs")
        for setting, port_value, profile_value in _port_overrides(p, context):
            rows.append({
                "Device": _flatten(p.get("deviceName", "")),
                "Port": _flatten(p.get("port", "")),
                "Name": _flatten(p.get("name", p.get("portName", ""))),
                "Profile": _flatten(p.get("profileName", "")),
                "Override Mode": ", ".join(mode) or "Follow profile",
                "Setting": setting,
                "Port Value": port_value,
                "Profile Value": profile_value,
            })
    if not rows:
        return []
    return [("Ports differing from their profile", rows)]


# --- PoE and port schedules ---------------------------------------------------------------

def _schedule_ports(ports_map: Any, context: dict[str, Any] | None) -> str:
    names = {
        str(d.get("mac", "")).upper().replace(":", "-"): _flatten(d.get("name") or d.get("mac"))
        for d in (context or {}).get("devices") or [] if isinstance(d, dict) and d.get("mac")
    }
    parts = []
    for mac, ports in (ports_map or {}).items() if isinstance(ports_map, dict) else []:
        label = names.get(str(mac).upper().replace(":", "-"), str(mac))
        parts.append(f"{label}: {', '.join(str(x) for x in sorted(ports or []))}")
    return "; ".join(parts)


def _port_schedule_rows(data: Any, context: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    if not isinstance(data, dict):
        return []
    time_ranges = _ssid_lookups(context)["schedule"]
    rows = []
    for kind, label, map_key in (("poeSchedules", "PoE", "poePortsMap"), ("portSchedules", "Port", "portsMap")):
        for sched in data.get(kind) or []:
            if not isinstance(sched, dict):
                continue
            tr = sched.get("turnOnTime")
            rows.append({
                "Type": label,
                "Name": _flatten(sched.get("name", "")),
                "Status": _enabled(sched.get("status")),
                "On During": time_ranges.get(str(tr), _flatten(tr)) if tr else "",
                "Ports": _schedule_ports(sched.get(map_key), context),
            })
    return rows


# --- Uplinks and stacks ------------------------------------------------------------------

_STACK_STATUS_MAP: dict[int, str] = {0: "Normal", 1: "Abnormal", 2: "Not ready"}
_STACK_ROLE_MAP: dict[int, str] = {
    0: "Master", 1: "Member", 2: "Not initialized", 3: "License overdue", 4: "License inactive",
}


def _link_port(link: dict[str, Any]) -> str:
    """A link's port as ``LAG 1``, ``1/0/24`` (stack) or ``24``."""
    if link.get("lagId") is not None:
        return f"LAG {link['lagId']}"
    return _flatten(link.get("stPort") or link.get("port", ""))


def _link_device(link: dict[str, Any]) -> str:
    name = _flatten(link.get("stackName") or link.get("name") or link.get("mac", ""))
    kind = _flatten(link.get("type", ""))
    return f"{name} ({kind})" if kind and name else name


def _link_speed(link: dict[str, Any]) -> str:
    speed = link.get("linkSpeed")
    return _profile_code(speed, _STATUS_SPEED_MAP) if speed not in (None, 0) else ""


def _peer_port(link: dict[str, Any]) -> str:
    peer = link.get("linkPeerPortInfo") if isinstance(link.get("linkPeerPortInfo"), dict) else {}
    return _link_port(peer) if peer else ""


def _stack_label(msg: Any) -> str:
    if not isinstance(msg, dict) or not msg.get("stackId"):
        return ""
    text = f"{_flatten(msg.get('stackName') or msg['stackId'])} unit {msg.get('unit', '?')}"
    if msg.get("priority") is not None:
        text += f" (priority {msg['priority']})"
    return text


def _uplink_rows(data: Any, context: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    if not isinstance(data, dict):
        return []
    rows = []
    for sw in data.get("switches") or []:
        if not isinstance(sw, dict):
            continue
        up = sw.get("uplink") if isinstance(sw.get("uplink"), dict) else {}
        peer = _peer_port(up)
        rows.append({
            "Switch": _flatten(sw.get("deviceName", "")),
            "Model": _flatten(sw.get("deviceModel", "")),
            "Uplink Port": _link_port(up) if up else "",
            "Uplink To": (_link_device(up) + (f" port {peer}" if peer else "")) if up else "",
            "Speed": _link_speed(up) if up else "",
            "Downlinks": str(len(sw.get("downlinks") or [])),
            "Stack": _stack_label(sw.get("stackMsg")),
        })
    return rows


def _uplink_details(
    data: Any, context: dict[str, Any] | None = None,
) -> list[tuple[str, list[dict[str, Any]]]]:
    if not isinstance(data, dict):
        return []
    sections: list[tuple[str, list[dict[str, Any]]]] = []
    lags = (context or {}).get("lags")
    lag_list = lags.get("lags") if isinstance(lags, dict) else []
    checklist = []

    for sw in data.get("switches") or []:
        if not isinstance(sw, dict):
            continue
        name = _flatten(sw.get("deviceName", "")) or _flatten(sw.get("deviceMac", ""))
        model = _flatten(sw.get("deviceModel", ""))
        downlinks = [
            {
                "Local Port": _link_port(d),
                "Device": _link_device(d),
                "Model": _flatten(d.get("model", "")),
                "Peer Port": _peer_port(d),
                "Speed": _link_speed(d),
            }
            for d in sw.get("downlinks") or [] if isinstance(d, dict)
        ]
        if downlinks:
            sections.append((f"{name} downlinks", downlinks))

        up = sw.get("uplink") if isinstance(sw.get("uplink"), dict) else {}
        if up:
            checklist.append({"Switch": name, "Model": model, "Port": _link_port(up),
                              "Role": f"Uplink to {_link_device(up)}"
                                      + (f" port {_peer_port(up)}" if _peer_port(up) else "")})
        for d in downlinks:
            checklist.append({"Switch": name, "Model": model, "Port": d["Local Port"],
                              "Role": f"Downlink to {d['Device']}"})
        msg = sw.get("stackMsg") if isinstance(sw.get("stackMsg"), dict) else {}
        for group in msg.get("stackPorts") or []:
            if isinstance(group, dict):
                ports = ", ".join(_flatten(x) for x in group.get("ports") or [])
                checklist.append({"Switch": name, "Model": model, "Port": ports,
                                  "Role": f"Stack port group {_flatten(group.get('name') or group.get('ID', ''))}"})
        for lag in lag_list or []:
            if isinstance(lag, dict) and str(lag.get("deviceMac", "")).upper() == str(sw.get("deviceMac", "")).upper():
                checklist.append({"Switch": name, "Model": model, "Port": _lag_members(lag),
                                  "Role": f"{_lag_label(lag)} member"})

    for st in data.get("stacks") or []:
        if not isinstance(st, dict):
            continue
        members = []
        for m in st.get("members") or []:
            if not isinstance(m, dict):
                continue
            groups = "; ".join(
                f"{_flatten(g.get('name') or g.get('ID', ''))}: {', '.join(_flatten(x) for x in g.get('ports') or [])}"
                for g in m.get("stackPorts") or [] if isinstance(g, dict)
            )
            up = m.get("uplink") if isinstance(m.get("uplink"), dict) else {}
            members.append({
                "Unit": _flatten(m.get("unit", "")),
                "Member": _flatten(m.get("name") or m.get("mac", "")),
                "Model": _flatten(m.get("showModel") or m.get("model", "")),
                "Role": _profile_code(m["memberStatus"], _STACK_ROLE_MAP) if m.get("memberStatus") is not None else "",
                "Priority": _flatten(m.get("priority", "")),
                "Stack Ports": groups,
                "Uplink": (f"{_link_port(up)} → {_link_device(up)}" if up else ""),
            })
            if groups:
                checklist.append({"Switch": _flatten(m.get("name") or m.get("mac", "")),
                                  "Model": _flatten(m.get("showModel") or m.get("model", "")),
                                  "Port": groups, "Role": f"Stack {_flatten(st.get('name', ''))} unit "
                                                          f"{_flatten(m.get('unit', ''))} stacking"})
        status = _profile_code(st["status"], _STACK_STATUS_MAP) if st.get("status") is not None else ""
        title = f"Stack {_flatten(st.get('name', ''))}" + (f" ({status})" if status else "")
        sections.append((title, members))

    if checklist:
        sections.append(("Remapping checklist (model-specific ports)", checklist))
    return sections


# --- Switch port sheets (manual reconfiguration of a replacement switch) --------------

def _is_default_port_name(name: Any, port: Any) -> bool:
    text = str(name or "").strip().lower().replace(" ", "")
    return text in ("", f"port{port}")


def _sheet_links(mac: Any, context: dict[str, Any] | None) -> dict[Any, str]:
    """Local port -> what it connects to, from the ``uplinks`` resource."""
    uplinks = (context or {}).get("uplinks")
    links: dict[Any, str] = {}
    switches = uplinks.get("switches") or [] if isinstance(uplinks, dict) else []
    for sw in switches:
        if not isinstance(sw, dict) or str(sw.get("deviceMac", "")).upper() != str(mac).upper():
            continue
        up = sw.get("uplink") if isinstance(sw.get("uplink"), dict) else {}
        if up:
            peer = _peer_port(up)
            target = f"Uplink → {_link_device(up)}" + (f" port {peer}" if peer else "")
            if up.get("port") is not None:
                links[up["port"]] = target
            if up.get("lagId") is not None:
                links[f"lag{up['lagId']}"] = target
        for d in sw.get("downlinks") or []:
            if isinstance(d, dict):
                peer = _peer_port(d)
                target = f"{_link_device(d)}" + (f" port {peer}" if peer else "")
                if d.get("port") is not None:
                    links[d["port"]] = target
                if d.get("lagId") is not None:
                    links[f"lag{d['lagId']}"] = target
    return links


def _sheet_port_row(p: dict[str, Any], context: dict[str, Any] | None,
                    links: dict[Any, str],
                    rule_refs: dict[tuple[str, Any], list[str]] | None = None) -> dict[str, Any]:
    by_id, by_vlan = _network_lookups(context)
    lookup = _build_id_lookup(context)
    profile = _port_profile(p, context) or {}

    def effective(key: str) -> Any:
        return p[key] if key in p else profile.get(key)

    lag = p.get("lagSetting") if isinstance(p.get("lagSetting"), dict) else {}
    lag_id = lag.get("lagId")
    lag_text = f"LAG {lag_id}" if lag_id is not None else (
        "LAG (group unknown)" if str(p.get("operation", "")).upper() == "AGGREGATING" or p.get("lagPort") else "")
    connected_to = links.get(p.get("port")) or (links.get(f"lag{lag_id}") if lag_id is not None else "") or ""

    native = effective("nativeNetworkId")
    tags_setting = effective("networkTagsSetting")
    if tags_setting == 0:
        tagged = "All"
    elif tags_setting == 1:
        tagged = "None (blocked)"
    else:
        tagged = _override_value(effective("tagNetworkIds") or [], "nets", lookup)
    untagged = _override_value(effective("untagNetworkIds") or [], "nets", lookup)

    poe = p.get("poe")
    if p.get("supportPoe") is False or p.get("poeDisplayType") == -1:
        poe_text = "n/a"
    else:
        poe_text = _profile_code(poe, _PORT_POE_MAP) if poe is not None else ""

    speed = p.get("linkSpeed")
    duplex = p.get("duplex")
    speed_text = "Auto" if speed in (None, 0) else _profile_code(speed, _PORT_CFG_SPEED_MAP)
    if duplex not in (None, 0):
        speed_text += f" / {_profile_code(duplex, _PORT_CFG_DUPLEX_MAP)}"

    overrides = _port_overrides(p, context)
    custom = "; ".join(f"{setting}: {value}" for setting, value, _ in overrides)
    rules = (rule_refs or {}).get((str(p.get("deviceMac", "")).upper().replace(":", "-"), p.get("port")), [])

    connection = _port_connection({"deviceType": "switch", **p})
    name = _flatten(p.get("name") or p.get("portName") or "")
    label = _flatten(p.get("tagName", ""))
    reasons = []
    if connection.startswith("Connected"):
        reasons.append("connected")
    if connected_to.startswith("Uplink"):
        reasons.append("uplink")
    elif connected_to:
        reasons.append("downlink")
    if lag_text:
        reasons.append(lag_text)
    if overrides:
        reasons.append("custom settings")
    if rules:
        reasons.append("port rules")
    if not _is_default_port_name(name, p.get("port")) or label:
        reasons.append("named")
    return {
        "Port": _flatten(p.get("port", "")),
        "Name": name,
        "Label": label,
        "Type": _map_code(p.get("type", ""), _SWITCH_PORT_TYPE_MAP) if p.get("type") is not None else "",
        "Connection": connection,
        "Connected To": connected_to,
        "Profile": _flatten(p.get("profileName", "")),
        "Native VLAN": (by_id.get(str(native), str(native)) if native else ""),
        "Untagged": untagged if untagged != "None" else "",
        "Tagged": tagged if tagged != "None" else "",
        "PoE": poe_text,
        "Speed / Duplex": speed_text,
        "LAG": lag_text,
        "Set Manually (differs from profile)": custom,
        "Port-Bound Rules": "; ".join(rules),
        "Carry Over": ", ".join(reasons) if reasons else "No (unused, default)",
    }


def _switch_sheet_ports(sw: dict[str, Any], context: dict[str, Any] | None) -> list[dict[str, Any]]:
    mac = str(sw.get("deviceMac", "")).upper()
    ports = [
        p for p in (context or {}).get("device_ports") or []
        if isinstance(p, dict) and str(p.get("deviceMac", "")).upper() == mac
        and p.get("deviceType") in (None, "switch")
    ]
    return sorted(ports, key=lambda p: (0, p["port"]) if isinstance(p.get("port"), int) else (1, str(p.get("port"))))


def _switch_port_sheet_rows(data: Any, context: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """One summary row per switch: how many ports must move to the new switch."""
    refs = _port_rule_refs(context)
    rows = []
    for sw in data if isinstance(data, list) else []:
        if not isinstance(sw, dict):
            continue
        links = _sheet_links(sw.get("deviceMac", ""), context)
        sheet = [_sheet_port_row(p, context, links, refs) for p in _switch_sheet_ports(sw, context)]
        carry = [r for r in sheet if not r["Carry Over"].startswith("No")]
        sfp = sum(1 for r in carry if r["Type"] in ("SFP", "Combo"))
        poe = sum(1 for r in carry if r["PoE"] == "On" and r["Connection"].startswith("Connected"))
        rows.append({
            "Switch": _flatten(sw.get("deviceName", "")),
            "Model": _flatten(sw.get("deviceModel", "")),
            "Ports": str(len(sheet)),
            "Connected": str(sum(1 for r in sheet if r["Connection"].startswith("Connected"))),
            "Custom Settings": str(sum(1 for r in sheet if r["Set Manually (differs from profile)"])),
            "Must Carry Over": str(len(carry)),
            "…of which SFP / Combo": str(sfp),
            "…of which powering PoE": str(poe),
        })
    return rows


def _switch_port_sheet_details(
    data: Any, context: dict[str, Any] | None = None,
) -> list[tuple[str, list[dict[str, Any]]]]:
    refs = _port_rule_refs(context)
    sections = []
    for sw in data if isinstance(data, list) else []:
        if not isinstance(sw, dict):
            continue
        links = _sheet_links(sw.get("deviceMac", ""), context)
        rows = [_sheet_port_row(p, context, links, refs) for p in _switch_sheet_ports(sw, context)]
        title = f"{_flatten(sw.get('deviceName', ''))} ({_flatten(sw.get('deviceModel', ''))})"
        sections.append((title, rows))
    return sections


# --- Gateway port sheets (replacing the router with another model) -------------------

_GW_CAPABILITY_MAP: dict[int, str] = {0: "WAN only", 1: "WAN or LAN", 2: "LAN only"}
_GW_SPEED_MAP: dict[int, str] = {0: "Auto", 1: "10M", 2: "100M", 3: "1000M", 4: "2500M", 5: "10G", 6: "5G"}
_GW_MIRROR_MODE_MAP: dict[int, str] = {0: "ingress", 1: "egress", 2: "ingress and egress"}
_IPV6_PROTO_MAP: dict[int, str] = {0: "Static", 1: "Dynamic", 2: "PPPoE", 3: "6to4 Tunnel", 4: "Bridge"}
_PPP_CONNECT_MAP: dict[int, str] = {0: "connect automatically", 1: "connect manually", 2: "time-based"}


def _gw_port_of(port_id: Any) -> Any:
    """Gateway port IDs are ``<port number>_<uuid>``; return the port number."""
    number, _ = _port_number(port_id)
    return number if number < 10**6 else None


def _gw_port_names(context: dict[str, Any] | None) -> dict[Any, str]:
    """Gateway port number -> port name (``WAN``, ``WAN/LAN1`` ...)."""
    names: dict[Any, str] = {}
    ctx = context or {}
    for p in ctx.get("device_ports") or []:
        if isinstance(p, dict) and p.get("deviceType") == "gateway" and p.get("name") and p.get("port") is not None:
            names.setdefault(p["port"], _flatten(p["name"]))
    for pid, name in _wan_port_names(context).items():
        if _gw_port_of(pid) is not None:
            names.setdefault(_gw_port_of(pid), name)
    failover = ctx.get("wan_failover") if isinstance(ctx.get("wan_failover"), dict) else {}
    for pid, name in _wan_failover_names(failover, None).items():
        if _gw_port_of(pid) is not None:
            names.setdefault(_gw_port_of(pid), name)
    return names


def _gw_wan_configs(context: dict[str, Any] | None) -> dict[Any, dict[str, Any]]:
    """Gateway port number -> its WAN connection config from ``gateway_settings``."""
    configs: dict[Any, dict[str, Any]] = {}
    settings = (context or {}).get("gateway_settings")
    for item in settings if isinstance(settings, list) else [settings]:
        if isinstance(item, dict):
            for wan in item.get("wanPortsConfig") or []:
                if isinstance(wan, dict) and _gw_port_of(wan.get("portId")) is not None:
                    configs[_gw_port_of(wan["portId"])] = wan
    return configs


def _wan_connection(wan: dict[str, Any]) -> str:
    """Summarize one WAN port's connection: type, addressing, VLAN, MAC, IPv6."""
    ipv4 = wan.get("wanPortIpv4Setting") if isinstance(wan.get("wanPortIpv4Setting"), dict) else {}
    proto = ipv4.get("protoType")
    if proto is None:
        return ""
    parts = [_profile_code(proto, _PROTO_TYPE_MAP)]
    detail = {0: "ipv4Static", 1: "ipv4Dhcp", 2: "ipv4Pppoe", 3: "ipv4L2tp", 4: "ipv4Pptp"}.get(proto, "")
    cfg = ipv4.get(detail) if isinstance(ipv4.get(detail), dict) else {}
    if proto == 0:
        addr = _flatten(cfg.get("ipAddress", ""))
        if cfg.get("subnetMask"):
            addr += f"/{cfg['subnetMask']}"
        if addr:
            parts.append(addr)
        if cfg.get("defaultGateway"):
            parts.append(f"gateway {cfg['defaultGateway']}")
    if proto in (2, 3, 4):
        if cfg.get("userName"):
            parts.append(f"user {cfg['userName']}")
        if "password" in cfg:
            parts.append(f"password {_secret_state(cfg.get('password')).lower()}")
        if cfg.get("serviceName"):
            parts.append(f"service {cfg['serviceName']}")
        if cfg.get("connectionMode") is not None:
            parts.append(_profile_code(cfg["connectionMode"], _PPP_CONNECT_MAP))
    if proto == 1 and cfg.get("hostname"):
        parts.append(f"hostname {cfg['hostname']}")
    dns = [str(cfg[k]) for k in ("primaryDns", "secondaryDns") if cfg.get(k)]
    if dns:
        parts.append("DNS " + ", ".join(dns))
    if cfg.get("mtu"):
        parts.append(f"MTU {cfg['mtu']}")
    if cfg.get("wanMultipleIps"):
        parts.append(f"{len(cfg['wanMultipleIps'])} extra IPs")
    if ipv4.get("vlanId"):
        priority = f" priority {ipv4.get('vlanPriority', 0)}" if ipv4.get("qosTagEnable") else ""
        parts.append(f"VLAN {ipv4['vlanId']}{priority}")
    mac = wan.get("wanPortMacSetting") if isinstance(wan.get("wanPortMacSetting"), dict) else {}
    if mac.get("method") == 1 and mac.get("mac"):
        parts.append(f"cloned MAC {mac['mac']}")
    ipv6 = wan.get("wanPortIpv6Setting") if isinstance(wan.get("wanPortIpv6Setting"), dict) else {}
    if ipv6.get("enable"):
        parts.append("IPv6 " + (_profile_code(ipv6["protoType"], _IPV6_PROTO_MAP)
                                if ipv6.get("protoType") is not None else "enabled"))
    return ", ".join(p for p in parts if p)


def _rule_status(value: Any) -> str:
    return "" if value is None else _enabled(value)


def _gw_port_refs(context: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Every site setting that names a gateway port by ID (WAN or LAN).

    Returns rows with ``port`` (number, or ``None`` when the ID has no port
    prefix), ``resource``, ``rule``, ``setting`` and ``status``.  These IDs are
    tied to the physical ports of this gateway model.
    """
    ctx = context or {}
    refs: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()

    def ids(value: Any) -> list[Any]:
        if value in (None, "", []):
            return []
        return list(value) if isinstance(value, (list, tuple)) else [value]

    def add(port_ids: Any, resource: str, rule: Any, setting: str, status: Any = None) -> None:
        for pid in ids(port_ids):
            row = {"port": _gw_port_of(pid), "portId": str(pid), "resource": resource,
                   "rule": _flatten(rule), "setting": setting, "status": _rule_status(status)}
            key = tuple(row.values())
            if key not in seen:
                seen.add(key)
                refs.append(row)

    def items(name: str) -> list[dict[str, Any]]:
        value = ctx.get(name)
        return [r for r in value if isinstance(r, dict)] if isinstance(value, list) else []

    def part(name: str) -> dict[str, Any]:
        value = ctx.get(name)
        return value if isinstance(value, dict) else {}

    nets_by_port_id: dict[str, list[str]] = {}
    for net in items("networks"):
        for pid in ids(net.get("interfaceIds")):
            nets_by_port_id.setdefault(str(pid), []).append(_flatten(net.get("name", "")))
    lan_count = sum(1 for net in items("networks") if ids(net.get("interfaceIds")))
    for pid, net_names in nets_by_port_id.items():
        text = f"All {lan_count} LAN networks" if len(net_names) == lan_count > 1 else ", ".join(net_names)
        add(pid, "networks", text, "LAN networks on this port")
    for r in items("port_forwarding"):
        add(r.get("interfaceWanPortId"), "port_forwarding", r.get("name", ""), "Interface", r.get("status"))
        for w in r.get("wanIps") or []:
            if isinstance(w, dict):
                add(w.get("wanId"), "port_forwarding", r.get("name", ""), f"WAN IP {w.get('ip', '')}",
                    r.get("status"))
    for r in items("one_to_one_nat"):
        add(r.get("interfaceIds"), "one_to_one_nat", r.get("name", ""), "Interface", r.get("status"))
    for r in items("static_routes"):
        if r.get("routeSource") != "switch" and r.get("interfaceType") == 0:
            add(r.get("interfaceId"), "static_routes", r.get("name", ""), "Interface", r.get("status"))
    for r in items("policy_routes"):
        if r.get("interfaceType") == 0:
            add(r.get("interfaceId"), "policy_routes", r.get("name", ""), "WAN binding", r.get("status"))
        add(r.get("wanPortIds"), "policy_routes", r.get("name", ""), "WAN binding", r.get("status"))
    for name in ("site_to_site_vpns", "remote_access_vpns"):
        for v in items(name):
            add(v.get("wan"), name, v.get("name", ""), "WAN", v.get("status"))
            add(v.get("wans"), name, v.get("name", ""), "WAN", v.get("status"))
    ssl = part("ssl_vpn").get("setting")
    if isinstance(ssl, dict):
        add(ssl.get("wanPort"), "ssl_vpn", "SSL VPN server", "WAN port", ssl.get("status"))
    for f in items("ipsec_failover"):
        add(f.get("backupWan"), "ipsec_failover", f.get("name", ""), "Backup WAN")

    failover = part("wan_failover")
    lb = failover.get("loadBalance") if isinstance(failover.get("loadBalance"), dict) else {}
    if lb.get("linkBackup"):
        add(lb.get("primaryWans"), "wan_failover", "Link backup", "Primary WAN")
        add(lb.get("backupWan"), "wan_failover", "Link backup", "Backup WAN")
    internet = failover.get("internet") if isinstance(failover.get("internet"), dict) else {}
    weights = lb.get("weights")
    wan_ports = sorted(
        (str(x["portId"]) for x in internet.get("portList") or []
         if isinstance(x, dict) and x.get("portId") and x.get("portMode", 0) == 0),
        key=_port_number,
    )
    if isinstance(weights, list) and len(weights) == len(wan_ports) > 1:
        for pid, weight in zip(wan_ports, weights):
            add(pid, "wan_failover", "Load balancing", f"Weight {weight}")
    for v in lb.get("virtualWanWeights") or []:
        if isinstance(v, dict):
            add(v.get("physicalWanId"), "wan_failover", f"Virtual WAN {v.get('name') or v.get('virtualWanId', '')}",
                f"Weight {v.get('weight', '')}")

    for r in part("dns_settings").get("ddns") or []:
        if isinstance(r, dict):
            add(r.get("interfacePortId"), "dns_settings",
                f"Dynamic DNS {r.get('domainName', '')}".strip(), "Interface", r.get("status"))
    mcast = part("multicast_services")
    for key, label in (("igmp", "IGMP proxy"), ("mld", "MLD proxy")):
        cfg = mcast.get(key) if isinstance(mcast.get(key), dict) else {}
        if cfg.get("enable"):
            add(cfg.get("wanPortId"), "multicast_services", label, "Upstream WAN")
    iptv = mcast.get("iptv") if isinstance(mcast.get("iptv"), dict) else {}
    if iptv.get("enable"):
        add(iptv.get("wanPortId"), "multicast_services", "IPTV", "WAN")
        for x in iptv.get("portConfig") or []:
            if isinstance(x, dict):
                add(x.get("portId"), "multicast_services", "IPTV",
                    f"Port role {_profile_code(x.get('type', ''), _IPTV_PORT_TYPE_MAP)}")
    upnp = mcast.get("upnp") if isinstance(mcast.get("upnp"), dict) else {}
    if upnp.get("enable"):
        add(upnp.get("wanPortIds"), "multicast_services", "UPnP", "WAN")

    security = part("switch_security")
    imb = security.get("ipMacBind") if isinstance(security.get("ipMacBind"), dict) else {}
    if imb.get("enable"):
        add(imb.get("wanIds"), "switch_security", "IP-MAC binding", "WAN")
    for b in security.get("ipMacBinds") or []:
        if isinstance(b, dict) and b.get("interfaceType") == 0:
            add(b.get("interfaceId"), "switch_security", f"IP-MAC binding {b.get('ip', '')} / {b.get('mac', '')}",
                "WAN", b.get("status"))
    return refs


def _gw_links(mac: Any, context: dict[str, Any] | None) -> tuple[dict[Any, str], list[dict[str, Any]]]:
    """Switches uplinked to this gateway, from the ``uplinks`` resource.

    Returns (gateway port -> "<switch> port <n>", one row per such switch).
    The gateway-side port is known only when the controller reports the link
    peer (``linkPeerPortInfo``).
    """
    uplinks = (context or {}).get("uplinks")
    links: dict[Any, str] = {}
    rows: list[dict[str, Any]] = []
    target = str(mac).upper().replace(":", "-")
    for sw in (uplinks.get("switches") or []) if isinstance(uplinks, dict) else []:
        up = sw.get("uplink") if isinstance(sw, dict) and isinstance(sw.get("uplink"), dict) else {}
        if not up or str(up.get("mac", "")).upper().replace(":", "-") != target:
            continue
        gw_port = _peer_port(up)
        local = _link_port(up)
        text = f"{_flatten(sw.get('deviceName', ''))} port {local}" if local else _flatten(sw.get("deviceName", ""))
        if gw_port:
            links[_port_num(gw_port)] = text
        rows.append({
            "Device": _flatten(sw.get("deviceName", "")),
            "Model": _flatten(sw.get("deviceModel", "")),
            "Its Port": local,
            "Gateway Port": gw_port or "Not reported (check the cabling)",
            "Link Speed": _link_speed(up),
        })
    return links, rows


def _gateway_ports(gw: dict[str, Any], context: dict[str, Any] | None) -> list[dict[str, Any]]:
    mac = str(gw.get("deviceMac", "")).upper()
    ports = [
        p for p in (context or {}).get("device_ports") or []
        if isinstance(p, dict) and str(p.get("deviceMac", "")).upper() == mac and p.get("deviceType") == "gateway"
    ]
    return sorted(ports, key=lambda p: (0, p["port"]) if isinstance(p.get("port"), int) else (1, str(p.get("port"))))


def _gateway_sheet_row(p: dict[str, Any], context: dict[str, Any] | None, names: dict[Any, str],
                       wans: dict[Any, dict[str, Any]], refs: list[dict[str, Any]],
                       links: dict[Any, str]) -> dict[str, Any]:
    _, by_vlan = _network_lookups(context)
    port = p.get("port")
    mode = p.get("mode")
    is_wan = mode == 0
    port_refs = [r for r in refs if r["port"] == port]
    rule_refs = [r for r in port_refs if r["resource"] not in ("networks",)]
    networks = ", ".join(r["rule"] for r in port_refs if r["resource"] == "networks")
    connected_to = links.get(port, "")

    speed, duplex = p.get("linkSpeed"), p.get("duplex")
    speed_text = "Auto" if speed in (None, 0) else _profile_code(speed, _GW_SPEED_MAP)
    if duplex not in (None, 0):
        speed_text += f" / {_profile_code(duplex, _PORT_CFG_DUPLEX_MAP)}"
    mirror = ""
    if p.get("mirrorEnable"):
        mirrored = ", ".join(str(m) for m in p.get("mirroredPorts") or [])
        mode_text = _profile_code(p["mirrorMode"], _GW_MIRROR_MODE_MAP) if p.get("mirrorMode") is not None else ""
        mirror = f"Mirrors port {mirrored}" + (f" ({mode_text})" if mode_text else "")
    pvid = p.get("pvid")
    native = by_vlan.get(str(pvid), f"VLAN {pvid}") if pvid is not None and not is_wan else ""

    connection = _port_connection({**p, "deviceType": "gateway"})
    reasons = []
    if is_wan:
        reasons.append("WAN")
    if connection.startswith("Connected"):
        reasons.append("connected")
    if connected_to:
        reasons.append("downlink")
    if rule_refs:
        reasons.append(f"{len(rule_refs)} rule{'s' if len(rule_refs) != 1 else ''}")
    if speed_text != "Auto":
        reasons.append("fixed speed")
    if mirror:
        reasons.append("mirroring")
    if pvid not in (None, 1) and not is_wan:
        reasons.append(f"PVID {pvid}")
    if p.get("status") == 0:
        reasons.append("disabled")
    return {
        "Port": _flatten(port),
        "Name": _flatten(p.get("name") or names.get(port, "")),
        "Capability": _map_code(p["type"], _GW_CAPABILITY_MAP) if p.get("type") is not None else "",
        "Mode": "Mirroring" if p.get("mirrorEnable") else (
            _map_code(mode, _GATEWAY_PORT_MODE_MAP) if mode is not None else ""),
        "Connection": connection,
        "Connected To": connected_to,
        "WAN Connection": _wan_connection(wans[port]) if is_wan and port in wans else "",
        "LAN Networks": networks,
        "PVID (Native VLAN)": native,
        "Speed / Duplex": speed_text,
        "Mirroring": mirror,
        "Rules Bound": str(len(rule_refs)) if rule_refs else "",
        "Carry Over": ", ".join(reasons) if reasons else "No (unused, default)",
    }


def _gateway_sheet(gw: dict[str, Any], context: dict[str, Any] | None,
                   refs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    names = _gw_port_names(context)
    wans = _gw_wan_configs(context)
    links, _ = _gw_links(gw.get("deviceMac", ""), context)
    return [_gateway_sheet_row(p, context, names, wans, refs, links) for p in _gateway_ports(gw, context)]


def _gateway_port_sheet_rows(data: Any, context: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """One summary row per gateway: WAN ports, connected ports, rules tied to ports."""
    refs = _gw_port_refs(context)
    rows = []
    for gw in data if isinstance(data, list) else []:
        if not isinstance(gw, dict):
            continue
        sheet = _gateway_sheet(gw, context, refs)
        rows.append({
            "Gateway": _flatten(gw.get("deviceName", "")),
            "Model": _flatten(gw.get("deviceModel", "")),
            "Ports": str(len(sheet)),
            "WAN Ports": ", ".join(r["Name"] or r["Port"] for r in sheet if r["Mode"] == "WAN"),
            "Connected": str(sum(1 for r in sheet if r["Connection"].startswith("Connected"))),
            "Port-Bound Rules": str(sum(1 for r in refs if r["resource"] != "networks")),
            "Must Carry Over": str(sum(1 for r in sheet if not r["Carry Over"].startswith("No"))),
        })
    return rows


def _gateway_port_sheet_details(
    data: Any, context: dict[str, Any] | None = None,
) -> list[tuple[str, list[dict[str, Any]]]]:
    refs = _gw_port_refs(context)
    names = _gw_port_names(context)
    titles = {d.name: d.title for d in RESOURCES}
    sections = []
    for gw in data if isinstance(data, list) else []:
        if not isinstance(gw, dict):
            continue
        title = f"{_flatten(gw.get('deviceName', ''))} ({_flatten(gw.get('deviceModel', ''))})"
        sections.append((title, _gateway_sheet(gw, context, refs)))
        _, switches = _gw_links(gw.get("deviceMac", ""), context)
        if switches:
            sections.append((f"{title} connected switches", switches))
    checklist = [
        {
            "Port": _flatten(r["port"]) if r["port"] is not None else "?",
            "Port Name": names.get(r["port"], ""),
            "Used By": f"{titles.get(r['resource'], r['resource'])} ({r['resource']}.md)",
            "Rule / Setting": r["rule"],
            "Reference": r["setting"],
            "Status": r["status"],
        }
        for r in sorted(refs, key=lambda r: ((0, r["port"]) if isinstance(r["port"], int) else (1, 0),
                                             r["resource"] == "networks", r["resource"], r["rule"].lower()))
    ]
    if checklist:
        sections.append(("Port reference checklist (re-point these on the new gateway)", checklist))
    return sections


# --- Access point sheets (replacing an AP with another model) -----------------------

_AP_SITE_SETTING_MAP: dict[int, str] = {0: "Off", 1: "On", 2: "Use site settings"}
_AP_POWER_SAVING_MAP: dict[int, str] = {0: "Off", 1: "Standard", 2: "Smart", 3: "Deep power saving"}
_AP_TRUNK_MODE_MAP: dict[int, str] = {0: "SRC MAC + DST MAC", 1: "DST MAC", 2: "SRC MAC"}
_AP_POE_IN_MAP: dict[int, str] = {0: "Off", 1: "802.3bt", 2: "802.3at", 3: "802.3af"}
_MGMT_SSID_SECURITY_MAP: dict[int, str] = {0: "None", 2: "WPA-Enterprise", 3: "WPA-Personal"}
_AP_BAND_KEYS: tuple[tuple[str, str], ...] = (("2g", "2.4 GHz"), ("5g", "5 GHz"), ("5g2", "5 GHz-2"), ("6g", "6 GHz"))


_AP_PART_LABELS: dict[str, str] = {
    "general": "General (LED, name)",
    "ipSetting": "IP setting",
    "managementVlan": "Management VLAN",
    "managementWlan": "Management SSID",
    "uplinkConfig": "Uplink port selection",
    "wiredUplink": "Wired uplink",
    "wiredDownlinks": "Wired downlinks",
    "lanPorts": "LAN ports",
    "portVlans": "Port VLANs",
    "trunk": "Link aggregation (trunk)",
    "loadBalance": "Load balancing",
    "lldp": "LLDP",
    "powerSaving": "Power saving",
    "qos": "QoS (U-APSD)",
    "bridge": "Point-to-point bridge",
}


def _ap_part(ap: dict[str, Any], key: str) -> dict[str, Any]:
    value = ap.get(key)
    return value if isinstance(value, dict) else {}


def _ap_unavailable_rows(ap: dict[str, Any]) -> list[dict[str, Any]]:
    """Setting parts the controller didn't return for this AP."""
    rows = []
    for u in ap.get("unavailableParts") or []:
        if isinstance(u, dict):
            part = str(u.get("part", ""))
            rows.append({
                "Setting Part": _AP_PART_LABELS.get(part, part),
                "Endpoint": f"`{_flatten(u.get('path', ''))}`",
                "Reason": _flatten(u.get("reason", "")),
                "What To Do": "Check this on the old AP in the controller UI before the swap",
            })
    return rows


def _ap_radios(ap: dict[str, Any], context: dict[str, Any] | None) -> dict[str, Any]:
    mac = str(ap.get("deviceMac", "")).upper()
    for r in (context or {}).get("ap_radios") or []:
        if isinstance(r, dict) and str(r.get("deviceMac", "")).upper() == mac:
            return r.get("radios") if isinstance(r.get("radios"), dict) else {}
    return {}


def _ap_ssid_overrides(ap: dict[str, Any], context: dict[str, Any] | None) -> list[tuple[str, str]]:
    mac = str(ap.get("deviceMac", "")).upper().replace(":", "-")
    out = []
    for s in (context or {}).get("ssids") or []:
        if not isinstance(s, dict):
            continue
        for o in s.get("apOverrides") or []:
            if not isinstance(o, dict) or str(o.get("mac", "")).upper().replace(":", "-") != mac:
                continue
            parts = []
            if o.get("ssidEnable") is False:
                parts.append("SSID off on this AP")
            if o.get("overrideName"):
                parts.append(f"name {o['overrideName']}")
            if o.get("overrideVlan") not in (None, ""):
                parts.append(f"VLAN {o['overrideVlan']}")
            if o.get("overridePassword"):
                parts.append(f"password {_secret_state(o['overridePassword']).lower()}")
            out.append((_flatten(s.get("name", "")), ", ".join(parts) or "Override set"))
    return out


def _ap_ip_text(ip: dict[str, Any]) -> tuple[str, bool]:
    """(text, set by hand) for the AP's IP setting."""
    mode = str(ip.get("mode", ""))
    if mode.lower() == "static":
        st = ip.get("staticIpSetting") if isinstance(ip.get("staticIpSetting"), dict) else {}
        text = f"Static {st.get('configIp', '')}" + (f"/{st['configMask']}" if st.get("configMask") else "")
        if st.get("configGate"):
            text += f", gateway {st['configGate']}"
        dns = [str(st[k]) for k in ("preferredDNS", "alternateDNS") if st.get(k)]
        if dns:
            text += ", DNS " + ", ".join(dns)
        return text, True
    if not mode:
        return "", False
    dh = ip.get("dhcpIpSetting") if isinstance(ip.get("dhcpIpSetting"), dict) else {}
    text, manual = "DHCP", False
    if dh.get("useFixedAddr") and dh.get("dhcpIp"):
        text += f", reserved {dh['dhcpIp']}"
        manual = True
    if dh.get("fallback"):
        text += f", fallback {dh.get('fallbackIp', '')}" + (f"/{dh['fallbackMask']}" if dh.get("fallbackMask") else "")
        manual = True
    return text, manual


def _ap_mgmt_vlan(vlan: dict[str, Any], context: dict[str, Any] | None) -> tuple[str, bool]:
    if not vlan:
        return "", False
    if vlan.get("mode") != 1:
        return "Default", False
    by_id, _ = _network_lookups(context)
    if vlan.get("lanNetworkId"):
        return by_id.get(str(vlan["lanNetworkId"]), str(vlan["lanNetworkId"])), True
    return (f"VLAN {vlan['bridgeVlan']}" if vlan.get("bridgeVlan") is not None else "Custom"), True


def _ap_uplink(ap: dict[str, Any]) -> str:
    up = _ap_part(ap, "wiredUplink")
    if not up:
        return ""
    text = _flatten(up.get("name") or up.get("uplinkMac", ""))
    if up.get("uplinkPort") not in (None, ""):
        text += f" port {up['uplinkPort']}"
    if up.get("port") not in (None, ""):
        text += f" (AP port {up['port']})"
    if up.get("rate") not in (None, "", "0", 0):
        text += f", {up['rate']} Mbps"
    return text


def _ap_settings(ap: dict[str, Any], context: dict[str, Any] | None) -> list[tuple[str, str, str, bool]]:
    """(category, setting, value, carry over) rows for one AP."""
    rows: list[tuple[str, str, str, bool]] = []
    radios = _ap_radios(ap, context)
    if radios:
        bands = [_RADIO_BAND_LABELS.get(b, b) for b in sorted(
            radios, key=lambda b: list(_RADIO_BAND_LABELS).index(b) if b in _RADIO_BAND_LABELS else 99)]
        rows.append(("Hardware", "Radio bands", ", ".join(bands), False))
    uplink = _ap_uplink(ap)
    if uplink:
        rows.append(("Uplink", "Wired uplink", uplink, True))
    uplink_cfg = ap.get("uplinkConfig")
    if isinstance(uplink_cfg, list) and uplink_cfg:
        manual = [str(u.get("port", "")) for u in uplink_cfg if isinstance(u, dict) and u.get("auto") is False]
        rows.append(("Uplink", "Uplink port selection", f"Fixed: {', '.join(manual)}" if manual else "Auto",
                     bool(manual)))
    trunk = _ap_part(ap, "trunk")
    if trunk.get("supportTrunkSetting"):
        text = _enabled(trunk.get("enable"))
        if trunk.get("enable") and trunk.get("mode") is not None:
            text += f" ({_profile_code(trunk['mode'], _AP_TRUNK_MODE_MAP)})"
        rows.append(("Uplink", "Link aggregation (trunk)", text, bool(trunk.get("enable"))))
    bridge = _ap_part(ap, "bridge")
    if bridge.get("bridgeSsidName") or bridge.get("hwSwitch"):
        text = f"SSID {bridge.get('bridgeSsidName', '')}"
        if "bridgeSsidPassword" in bridge:
            text += f", password {_secret_state(bridge.get('bridgeSsidPassword')).lower()}"
        if bridge.get("hwSwitch") is not None:
            text += f", DIP switch {'on' if bridge['hwSwitch'] else 'off'}"
        rows.append(("Uplink", "P2P bridge", text, True))

    ip_text, ip_manual = _ap_ip_text(_ap_part(ap, "ipSetting"))
    if ip_text:
        rows.append(("Management", "IP address", ip_text, ip_manual))
    vlan_text, vlan_manual = _ap_mgmt_vlan(_ap_part(ap, "managementVlan"), context)
    if vlan_text:
        rows.append(("Management", "Management VLAN", vlan_text, vlan_manual))
    mw = _ap_part(ap, "managementWlan")
    if mw:
        text = _enabled(mw.get("status"))
        if mw.get("status"):
            text += f": {mw.get('name', '')}"
            if mw.get("security") is not None:
                text += f", {_profile_code(mw['security'], _MGMT_SSID_SECURITY_MAP)}"
            psk = mw.get("pskSetting") if isinstance(mw.get("pskSetting"), dict) else {}
            if "securityKey" in psk:
                text += f", key {_secret_state(psk.get('securityKey')).lower()}"
            vs = mw.get("vlanSetting") if isinstance(mw.get("vlanSetting"), dict) else {}
            custom = vs.get("customConfig") if isinstance(vs.get("customConfig"), dict) else {}
            if vs.get("mode") == 1:
                by_id, _ = _network_lookups(context)
                net = custom.get("lanNetworkId")
                text += ", VLAN " + (by_id.get(str(net), str(net)) if net else _flatten(custom.get("vlanId", "")))
        rows.append(("Management", "Management SSID", text, bool(mw.get("status"))))

    for band, r in sorted(radios.items(), key=lambda kv: list(_RADIO_BAND_LABELS).index(kv[0])
                          if kv[0] in _RADIO_BAND_LABELS else 99):
        if not isinstance(r, dict):
            continue
        name = _RADIO_BAND_LABELS.get(band, band)
        if r.get("radioEnable") is False:
            rows.append(("Radio", name, "Disabled", True))
            continue
        row = _ap_radio_rows([{"radios": {band: r}}])
        if not row:
            continue
        rr = row[0]
        text = ", ".join(t for t in (
            f"channel {rr['Channel']}" if rr["Channel"] else "", rr["Channel Width"],
            f"power {rr['Tx Power']}" if rr["Tx Power"] else "",
            f"mode {rr['Wireless Mode']}" if rr["Wireless Mode"] else "",
            "channel limit" if rr["Channel Limit"] == "Enabled" else "") if t)
        # Channel and power are per AP; anything but Auto must be set again by hand.
        fixed = (rr["Channel"] not in ("", "Auto") or r.get("txPowerLevel") not in (None, 4)
                 or rr["Channel Limit"] == "Enabled")
        rows.append(("Radio", name, text, fixed))

    for ssid, text in _ap_ssid_overrides(ap, context):
        rows.append(("SSID override", ssid, text, True))

    general = _ap_part(ap, "general")
    if general.get("ledSetting") is not None:
        rows.append(("General", "LED", _profile_code(general["ledSetting"], _AP_SITE_SETTING_MAP),
                     general["ledSetting"] != 2))
    lldp = _ap_part(ap, "lldp")
    if lldp.get("supportLldp") is not False and lldp.get("lldpEnable") is not None:
        rows.append(("General", "LLDP", _profile_code(lldp["lldpEnable"], _AP_SITE_SETTING_MAP),
                     lldp["lldpEnable"] != 2))
    ps = _ap_part(ap, "powerSaving")
    if ps.get("supportPowerSaving") is not False and ps.get("mode") is not None:
        text = _profile_code(ps["mode"], _AP_POWER_SAVING_MAP)
        if ps.get("timeEnable"):
            text += (f", {ps.get('startTimeH', 0):02}:{ps.get('startTimeM', 0):02}–"
                     f"{ps.get('endTimeH', 0):02}:{ps.get('endTimeM', 0):02}")
        if ps.get("bandEnable"):
            band_names = {0: "2.4 GHz", 1: "5 GHz", 2: "5 GHz-2", 3: "6 GHz"}
            text += ", bands " + ", ".join(band_names.get(b, str(b)) for b in ps.get("bands") or [])
        rows.append(("General", "Power saving", text, ps["mode"] != 0))
    lb = _ap_part(ap, "loadBalance")
    for suffix, label in (("2g", "2.4 GHz"), ("5g", "5 GHz"), ("5g2", "5 GHz-2"), ("6g", "6 GHz")):
        parts = []
        if lb.get(f"maxClientsEnable{suffix}"):
            parts.append(f"max {lb.get(f'maxClients{suffix}', '')} clients")
        if lb.get(f"rssiEnable{suffix}"):
            parts.append(f"RSSI threshold {lb.get(f'threshold{suffix}', '')} dBm")
        if parts:
            rows.append(("Load balancing", label, ", ".join(parts), True))
    qos = _ap_part(ap, "qos")
    off = [label for suffix, label in _AP_BAND_KEYS
           if qos.get(f"support{suffix}") and qos.get(f"deliveryEnable{suffix}") is False]
    if off:
        rows.append(("QoS", "U-APSD disabled on", ", ".join(off), True))
    return rows


def _ap_lan_port_rows(ap: dict[str, Any], context: dict[str, Any] | None) -> list[dict[str, Any]]:
    ports = [p for p in ap.get("lanPorts") or [] if isinstance(p, dict)]
    if not ports:
        return []
    by_id, by_vlan = _network_lookups(context)
    lookup = _build_id_lookup(context)
    downs = {}
    for d in ap.get("wiredDownlinks") or []:
        if isinstance(d, dict) and d.get("port") not in (None, ""):
            downs[str(d["port"])] = d
    rows = []
    for p in sorted(ports, key=lambda p: (0, p["port"]) if isinstance(p.get("port"), int) else (1, str(p.get("port")))):
        lan_port = _flatten(p.get("lanPort", ""))
        link = p.get("linkStatus")
        connection = "" if link is None else ("Connected" if link == 1 else "Disconnected")
        if link == 1:
            detail = _link_detail(p)
            connection += f" ({detail})" if detail else ""
        if p.get("status") is False:
            connection = "Disabled"
        down = downs.get(lan_port) or downs.get(str(p.get("port")))
        device = ""
        if down:
            device = _flatten(down.get("deviceName") or down.get("mac", ""))
            if down.get("downLinkPort"):
                device += f" port {down['downLinkPort']}"
        if p.get("custom"):
            untagged = _resolve_ids(p.get("untaggedNetworkId") or [], lookup) or _flatten(p.get("untagged", ""))
            tagged = _resolve_ids(p.get("taggedNetworkId") or [], lookup) or _flatten(p.get("tagged", ""))
            vlan = f"Custom: untagged {untagged or 'none'}; tagged {tagged or 'none'}"
        elif p.get("localVlanEnable"):
            net = p.get("localVlanNetworkId")
            vid = p.get("localVlanId")
            vlan = by_id.get(str(net)) if net else None
            vlan = vlan or by_vlan.get(str(vid)) or (f"VLAN {vid}" if vid is not None else "Enabled")
        elif p.get("supportVlan") is False:
            vlan = "n/a"
        else:
            vlan = "Default (management network)"
        if p.get("supportPoe"):
            poe = _enabled(p.get("poeOutEnable"))
        else:
            poe = "n/a"
        rate = ""
        if p.get("supportBandwidthControl") and p.get("bandwidthControlEnable"):
            limits = []
            for key, label in (("ingressRateLimit", "in"), ("egressRateLimit", "out")):
                lim = p.get(key) if isinstance(p.get(key), dict) else {}
                if lim.get("status"):
                    limits.append(f"{label} {lim.get('rate', '')}")
            rate = ", ".join(limits) or "Enabled"
        uplink = p.get("uplinkPort") or p.get("logicUplinkPort")
        reasons = []
        if uplink:
            reasons.append("uplink")
        if link == 1:
            reasons.append("connected")
        if p.get("custom") or p.get("localVlanEnable"):
            reasons.append("VLAN")
        if p.get("supportPoe") and p.get("poeOutEnable"):
            reasons.append("PoE out")
        if rate:
            reasons.append("rate limit")
        if p.get("status") is False:
            reasons.append("disabled")
        if not _is_default_port_name(p.get("name"), p.get("port")) and p.get("name") not in (None, "", lan_port):
            reasons.append("named")
        rows.append({
            "Port": lan_port or _flatten(p.get("port", "")),
            "Name": _flatten(p.get("name") or ""),
            "Role": "Uplink" if uplink else "LAN",
            "Connection": connection,
            "Connected Device": device,
            "VLAN": vlan,
            "PoE Out": poe,
            "Rate Limit (Kbps)": rate,
            "Carry Over": ", ".join(reasons) if reasons else "No (unused, default)",
        })
    return rows


def _ap_vlan_rows(ap: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for v in ap.get("portVlans") or []:
        if not isinstance(v, dict):
            continue
        rows.append({
            "VLAN": _flatten(v.get("localVlanId", "")),
            "Network": _flatten(v.get("name", "")),
            "Native Ports": ", ".join(str(x) for x in v.get("nativePort") or []),
            "Untagged Ports": ", ".join(str(x) for x in v.get("untagPort") or []),
            "Tagged Ports": ", ".join(str(x) for x in v.get("tagPort") or []),
        })
    return rows


def _ap_sheet_rows(data: Any, context: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """One summary row per AP: what is set on this AP specifically."""
    rows = []
    for ap in data if isinstance(data, list) else []:
        if not isinstance(ap, dict):
            continue
        settings = _ap_settings(ap, context)
        values = {(c, k): v for c, k, v, _ in settings}
        lan = _ap_lan_port_rows(ap, context)
        lan_ports = [r for r in lan if r["Role"] != "Uplink"]
        rows.append({
            "AP": _flatten(ap.get("deviceName", "")),
            "Model": _flatten(ap.get("deviceModel", "")),
            "Bands": values.get(("Hardware", "Radio bands"), ""),
            "IP": values.get(("Management", "IP address"), ""),
            "Management VLAN": values.get(("Management", "Management VLAN"), ""),
            "Uplink": values.get(("Uplink", "Wired uplink"), ""),
            "LAN Ports": (f"{len(lan_ports)} ({sum(1 for r in lan_ports if not r['Carry Over'].startswith('No'))}"
                          " to carry over)") if lan_ports else "",
            "SSID Overrides": str(sum(1 for c, *_ in settings if c == "SSID override")),
            "Settings to Carry Over": str(sum(1 for *_, carry in settings if carry)),
            "Not Exported": str(len(_ap_unavailable_rows(ap))) if ap.get("unavailableParts") else "",
        })
    return rows


def _ap_sheet_details(
    data: Any, context: dict[str, Any] | None = None,
) -> list[tuple[str, list[dict[str, Any]]]]:
    sections = []
    for ap in data if isinstance(data, list) else []:
        if not isinstance(ap, dict):
            continue
        title = f"{_flatten(ap.get('deviceName', ''))} ({_flatten(ap.get('deviceModel', ''))})"
        settings = [
            {"Category": c, "Setting": k, "Value": v, "Carry Over": "Yes" if carry else ""}
            for c, k, v, carry in _ap_settings(ap, context)
        ]
        if settings:
            sections.append((title, settings))
        lan = _ap_lan_port_rows(ap, context)
        if lan:
            sections.append((f"{title} LAN ports", lan))
        vlans = _ap_vlan_rows(ap)
        if vlans:
            sections.append((f"{title} port VLANs (effective)", vlans))
        missing = _ap_unavailable_rows(ap)
        if missing:
            # The model may not have the feature, or the call failed: either
            # way this sheet is incomplete for these parts.
            sections.append((f"{title} settings not exported (sheet incomplete)", missing))
    return sections


# --- Switch security, OUI VLANs, QoS, port labels ----------------------------------------

_DOT1X_AUTH_MODE_MAP: dict[int, str] = {0: "PAP", 1: "EAP"}
_DOT1X_AUTH_TYPE_MAP: dict[int, str] = {0: "Port based", 1: "MAC based"}
_MAC_FORMAT_MAP: dict[int, str] = {
    0: "aabbccddeeff", 1: "aa-bb-cc-dd-ee-ff", 2: "aa:bb:cc:dd:ee:ff",
    3: "AABBCCDDEEFF", 4: "AA-BB-CC-DD-EE-FF", 5: "AA:BB:CC:DD:EE:FF",
}
_IMB_INTERFACE_MAP: dict[int, str] = {0: "WAN", 1: "LAN"}
_OUI_MODE_MAP: dict[int, str] = {0: "All device ports", 1: "Custom ports"}
_QOS_MODE_MAP: dict[int, str] = {0: "QoS profiles (legacy)", 1: "QoS rules"}
_QOS_RULE_TYPE_MAP: dict[int, str] = {0: "Network", 1: "Port", 2: "Custom"}
_QOS_BIND_MAP: dict[int, str] = {0: "All switch ports", 1: "Custom ports"}


def _port_num(value: Any) -> Any:
    """``5`` / ``"5"`` / ``"1/0/5"`` / ``{"port": 5}`` -> ``5`` (stack unit/slot dropped)."""
    if isinstance(value, dict):
        value = value.get("port", value.get("standardPort"))
    if isinstance(value, int):
        return value
    text = str(value or "").split("/")[-1]
    return int(text) if text.isdigit() else value


def _lag_ports(mac: str, lag_id: Any, context: dict[str, Any] | None) -> list[Any]:
    lags = (context or {}).get("lags")
    for lag in (lags.get("lags") if isinstance(lags, dict) else None) or []:
        if (isinstance(lag, dict) and str(lag.get("deviceMac", "")).upper() == mac
                and str(lag.get("lagId")) == str(lag_id)):
            return list(lag.get("memberPorts") or [])
    return []


def _port_rule_refs(context: dict[str, Any] | None) -> dict[tuple[str, Any], list[str]]:
    """``(MAC, port)`` -> rules bound to that specific port.

    Covers DHCP snooping / ARP detection port selections, and OUI-VLAN and
    QoS rules bound to custom ports (LAGs expanded to their members).  Rules
    applying to *all* ports of a switch are not repeated per port.
    """
    refs: dict[tuple[str, Any], list[str]] = {}

    def add(mac: Any, port: Any, text: str) -> None:
        key = (str(mac).upper().replace(":", "-"), _port_num(port))
        if text not in refs.setdefault(key, []):
            refs[key].append(text)

    ctx = context or {}
    security = ctx.get("switch_security") if isinstance(ctx.get("switch_security"), dict) else {}
    for key, label in (("dhcpSnoops", "DHCP snooping"), ("arpDetects", "ARP detection")):
        for entry in security.get(key) or []:
            if isinstance(entry, dict) and entry.get("mac"):
                mac = str(entry["mac"]).upper().replace(":", "-")
                for port in entry.get("ports") or []:
                    if isinstance(port, dict) and port.get("lagId") is not None and port.get("port") is None:
                        for member in _lag_ports(mac, port["lagId"], context):
                            add(mac, member, label)
                    else:
                        add(mac, port, label)

    oui = ctx.get("oui_vlans") if isinstance(ctx.get("oui_vlans"), dict) else {}
    for rule in oui.get("rules") or []:
        if not isinstance(rule, dict) or rule.get("mode") != 1:
            continue
        label = f"OUI VLAN: {_flatten(rule.get('name', ''))}" + ("" if rule.get("enable", True) else " (disabled)")
        for dev in rule.get("deviceList") or []:
            if not isinstance(dev, dict) or not dev.get("deviceMac"):
                continue
            mac = str(dev["deviceMac"]).upper().replace(":", "-")
            for port in dev.get("portList") or []:
                add(mac, port, label)
            lag_members = {str(li.get("lag")): li.get("ports") or [] for li in dev.get("lagInfo") or []
                           if isinstance(li, dict)}
            for lag_id in dev.get("lagList") or []:
                for member in lag_members.get(str(lag_id)) or _lag_ports(mac, lag_id, context):
                    add(mac, member, label)

    qos = ctx.get("switch_qos") if isinstance(ctx.get("switch_qos"), dict) else {}
    for rule in qos.get("rules") or []:
        if not isinstance(rule, dict) or rule.get("bindType") != 1:
            continue
        label = f"QoS: {_flatten(rule.get('name', ''))}" + ("" if rule.get("status", True) else " (disabled)")
        for dev in rule.get("deviceList") or []:
            if not isinstance(dev, dict) or not dev.get("mac"):
                continue
            mac = str(dev["mac"]).upper().replace(":", "-")
            for port in dev.get("portList") or []:
                add(mac, port, label)
            for lag_id in dev.get("lagList") or []:
                for member in _lag_ports(mac, lag_id, context):
                    add(mac, member, label)
    return refs


def _device_label(mac: Any, context: dict[str, Any] | None) -> str:
    for d in (context or {}).get("devices") or []:
        if isinstance(d, dict) and str(d.get("mac", "")).upper() == str(mac).upper():
            return _flatten(d.get("name") or mac)
    return _flatten(mac)


def _selected_ports(ports: Any) -> str:
    out = []
    for p in ports or []:
        if isinstance(p, dict) and p.get("lagId") is not None and p.get("port") is None:
            out.append(f"LAG {p['lagId']}")
        else:
            out.append(_flatten(p.get("standardPort") or p.get("port")) if isinstance(p, dict) else _flatten(p))
    return ", ".join(out)


def _switch_security_rows(data: Any, context: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    if not isinstance(data, dict) or not data:
        return []
    radius = _ssid_lookups(context)["radius"]
    _, by_vlan = _network_lookups(context)
    rows: list[tuple[str, str, str]] = []

    d = data.get("dot1x") if isinstance(data.get("dot1x"), dict) else None
    if d is not None:
        rows.append(("802.1X (switches)", "Enabled", _enabled(d.get("enable"))))
        if d.get("enable"):
            prof = d.get("radiusProfileId")
            rows.append(("802.1X (switches)", "RADIUS Profile", radius.get(str(prof), _flatten(prof)) if prof else ""))
            for key, label, mapping in (("authMode", "Auth Protocol", _DOT1X_AUTH_MODE_MAP),
                                        ("authType", "Auth Type", _DOT1X_AUTH_TYPE_MAP),
                                        ("macFormat", "MAC Format", _MAC_FORMAT_MAP)):
                if d.get(key) is not None:
                    rows.append(("802.1X (switches)", label, _profile_code(d[key], mapping)))
            for key, label in (("vlanAssign", "VLAN Assignment"), ("mab", "MAB")):
                if key in d:
                    rows.append(("802.1X (switches)", label, _enabled(d[key])))
            if d.get("nasId"):
                rows.append(("802.1X (switches)", "NAS ID", _flatten(d["nasId"])))
            if d.get("guestVlan"):
                name = by_vlan.get(str(d["guestVlan"]))
                rows.append(("802.1X (switches)", "Guest VLAN",
                             f"{d['guestVlan']} ({name})" if name else _flatten(d["guestVlan"])))
        rows.append(("802.1X (switches)", "Per-port 802.1X mode", "See device_ports / switch_port_sheets"))

    m = data.get("macAuth") if isinstance(data.get("macAuth"), dict) else None
    if m is not None:
        rows.append(("MAC-Based Auth (wireless)", "Enabled", _enabled(m.get("enable"))))
        if m.get("enable"):
            ssids = ", ".join(_flatten(x.get("ssidName") or x.get("id", "")) for x in m.get("ssids") or []
                              if isinstance(x, dict))
            rows.append(("MAC-Based Auth (wireless)", "SSIDs", ssids))
            prof = m.get("radiusProfileId")
            rows.append(("MAC-Based Auth (wireless)", "RADIUS Profile",
                         radius.get(str(prof), _flatten(prof)) if prof else ""))
            if m.get("macFormat") is not None:
                rows.append(("MAC-Based Auth (wireless)", "MAC Format", _profile_code(m["macFormat"], _MAC_FORMAT_MAP)))
            for key, label in (("mabEnable", "MAB"), ("emptyPwdEnable", "Empty Password")):
                if key in m:
                    rows.append(("MAC-Based Auth (wireless)", label, _enabled(m[key])))

    status = data.get("dhcpSnoopStatus") if isinstance(data.get("dhcpSnoopStatus"), dict) else None
    if status is not None:
        rows.append(("DHCP Snooping", "Enabled", _enabled(status.get("dhcpSnoopEnable"))))
    if isinstance(data.get("dhcpSnoops"), list):
        rows.append(("DHCP Snooping", "Switches Configured", str(len(data["dhcpSnoops"]))))

    status = data.get("arpDetectStatus") if isinstance(data.get("arpDetectStatus"), dict) else None
    if status is not None:
        rows.append(("ARP Detection", "Enabled", _enabled(status.get("arpDetectEnable"))))
        if "snoopForEntryEnable" in status:
            rows.append(("ARP Detection", "Use DHCP Snooping Entries", _enabled(status["snoopForEntryEnable"])))
    if isinstance(data.get("arpDetects"), list):
        rows.append(("ARP Detection", "Switches Configured", str(len(data["arpDetects"]))))

    imb = data.get("ipMacBind") if isinstance(data.get("ipMacBind"), dict) else None
    if imb is not None:
        lookup = _build_id_lookup(context)
        wan_names = _wan_port_names(context)
        rows.append(("IP-MAC Binding", "Enabled", _enabled(imb.get("enable"))))
        if imb.get("enable"):
            rows.append(("IP-MAC Binding", "LANs", _resolve_ids(imb.get("lanIds") or [], lookup)))
            rows.append(("IP-MAC Binding", "WANs", _nat_interfaces(imb.get("wanIds"), wan_names)))
            if "imbPass" in imb:
                rows.append(("IP-MAC Binding", "IMB Pass", _enabled(imb["imbPass"])))
            if "garp" in imb:
                text = _enabled(imb["garp"])
                if imb["garp"] and imb.get("interval") is not None:
                    text += f" (every {imb['interval']})"
                rows.append(("IP-MAC Binding", "Gratuitous ARP", text))
    if isinstance(data.get("ipMacBinds"), list):
        rows.append(("IP-MAC Binding", "Bindings", str(len(data["ipMacBinds"]))))
    return [{"Category": c, "Setting": k, "Value": v} for c, k, v in rows if v != ""]


def _switch_security_details(
    data: Any, context: dict[str, Any] | None = None,
) -> list[tuple[str, list[dict[str, Any]]]]:
    if not isinstance(data, dict):
        return []
    sections = []
    for key, title in (("dhcpSnoops", "DHCP Snooping per switch"), ("arpDetects", "ARP Detection per switch")):
        rows = [
            {
                "Switch": _flatten(e.get("deviceName") or e.get("stackName") or _device_label(e.get("mac"), context)),
                "Model": _flatten(e.get("showModel") or e.get("deviceModel", "")),
                "Selected Ports": _selected_ports(e.get("ports")),
                **({"IP-MAC Bindings": str(len(e.get("impbs") or []))} if key == "arpDetects" else {}),
            }
            for e in data.get(key) or [] if isinstance(e, dict)
        ]
        if rows:
            sections.append((title, rows))
    lookup = _build_id_lookup(context)
    wan_names = _wan_port_names(context)
    binds = []
    for b in data.get("ipMacBinds") or []:
        if not isinstance(b, dict):
            continue
        iface_id = str(b.get("interfaceId", ""))
        iface = wan_names.get(iface_id) or lookup.get(iface_id) or iface_id
        kind = _profile_code(b["interfaceType"], _IMB_INTERFACE_MAP) if b.get("interfaceType") is not None else ""
        binds.append({
            "IP": _flatten(b.get("ip", "")), "MAC": _flatten(b.get("mac", "")),
            "Interface": f"{kind}: {iface}" if kind and iface else (kind or iface),
            "Status": _enabled(b.get("status")), "Description": _flatten(b.get("description", "")),
        })
    if binds:
        sections.append(("IP-MAC Bindings", sorted(binds, key=lambda r: _ip_sort_key(r["IP"]))))
    return sections


def _rule_targets(devices: Any, mac_key: str, context: dict[str, Any] | None) -> str:
    parts = []
    for dev in devices or []:
        if not isinstance(dev, dict):
            continue
        name = _flatten(dev.get("deviceName") or _device_label(dev.get(mac_key, ""), context))
        ports = [str(_port_num(x)) for x in dev.get("portList") or []]
        ports += [f"LAG {x}" for x in dev.get("lagList") or []]
        parts.append(f"{name}: {', '.join(ports)}" if ports else name)
    return "; ".join(parts)


def _oui_vlan_rows(data: Any, context: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    rules = data.get("rules") if isinstance(data, dict) else None
    _, by_vlan = _network_lookups(context)
    rows = []
    for r in rules if isinstance(rules, list) else []:
        if not isinstance(r, dict):
            continue
        combos = []
        for c in r.get("ruleCombine") or []:
            if isinstance(c, dict):
                vlan = c.get("vlanId")
                net = by_vlan.get(str(vlan))
                combos.append(f"{_flatten(c.get('ouiProfileName') or c.get('ouiProfileId', ''))} → VLAN {vlan}"
                              + (f" ({net})" if net else "") + f", priority {c.get('priority', '')}")
        rows.append({
            "Name": _flatten(r.get("name", "")),
            "Status": _enabled(r.get("enable")),
            "Applies To": _profile_code(r["mode"], _OUI_MODE_MAP) if r.get("mode") is not None else "",
            "Switch Ports": _rule_targets(r.get("deviceList"), "deviceMac", context),
            "OUI → VLAN": "; ".join(combos),
        })
    return rows


def _oui_vlan_details(
    data: Any, context: dict[str, Any] | None = None,
) -> list[tuple[str, list[dict[str, Any]]]]:
    profiles = data.get("profiles") if isinstance(data, dict) else None
    rows = [
        {
            "Profile": _flatten(p.get("name", "")),
            "OUIs": ", ".join(
                f"{o.get('oui', '')}" + (f" ({o['description']})" if o.get("description") else "")
                for o in p.get("ouiCombine") or [] if isinstance(o, dict)
            ),
        }
        for p in profiles if isinstance(p, dict)
    ] if isinstance(profiles, list) else []
    return [("OUI Profiles", rows)] if rows else []


def _switch_qos_rows(data: Any, context: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    rules = data.get("rules") if isinstance(data, dict) else None
    lookup = _build_id_lookup(context)
    items = sorted((r for r in rules or [] if isinstance(r, dict)),
                   key=lambda r: r["index"] if isinstance(r.get("index"), int) else 10**6) \
        if isinstance(rules, list) else []
    rows = []
    for r in items:
        match = []
        nets = [lookup.get(str(e.get("networkId")), f"VLAN {e.get('vlanId')}")
                for e in r.get("lanNetworkEntries") or [] if isinstance(e, dict)]
        if nets:
            match.append("Networks " + ", ".join(nets))
        if r.get("protocol") is not None:
            match.append(f"Protocol {_format_protocols(r['protocol'])}")
        if r.get("dscp") is not None:
            match.append(f"DSCP {r['dscp']}")
        for key, label in (("sPort", "Src port"), ("dPort", "Dst port")):
            if r.get(key) is not None:
                match.append(f"{label} {r[key]}")
        remark = ""
        if r.get("dscpReEnable"):
            remark = "Auto" if r.get("dscpRe") == 64 else _flatten(r.get("dscpRe"))
        rows.append({
            "Index": _flatten(r.get("index", "")),
            "Name": _flatten(r.get("name", "")),
            "Status": _enabled(r.get("status")),
            "Type": _profile_code(r["type"], _QOS_RULE_TYPE_MAP) if r.get("type") is not None else "",
            "Match": "; ".join(match),
            "Queue": _flatten(r.get("queue", "")),
            "DSCP Remark": remark,
            "Applies To": (_profile_code(r["bindType"], _QOS_BIND_MAP) if r.get("bindType") is not None else "")
            + (f" — {_rule_targets(r.get('deviceList'), 'mac', context)}" if r.get("bindType") == 1 else ""),
        })
    return rows


def _switch_qos_details(
    data: Any, context: dict[str, Any] | None = None,
) -> list[tuple[str, list[dict[str, Any]]]]:
    if not isinstance(data, dict):
        return []
    sections = []
    mode = data.get("mode") if isinstance(data.get("mode"), dict) else None
    if mode is not None and mode.get("qosMode") is not None:
        sections.append(("QoS Mode", [{"Setting": "Switch QoS Mode",
                                       "Value": _profile_code(mode["qosMode"], _QOS_MODE_MAP)}]))
    dscp = data.get("dscpMapping") if isinstance(data.get("dscpMapping"), dict) else {}
    mapping = dscp.get("mapping") if isinstance(dscp.get("mapping"), dict) else {}
    if mapping:
        sections.append(("DSCP to Queue Mapping", [
            {"Queue": str(q), "DSCP Values": ", ".join(str(v) for v in values or [])}
            for q, values in sorted(mapping.items(), key=lambda kv: int(kv[0]) if str(kv[0]).isdigit() else 99)
        ]))
    sched = data.get("schedulerMapping")
    entries = sched if isinstance(sched, list) else [sched] if isinstance(sched, dict) else []
    rows = []
    for e in entries:
        if isinstance(e, dict):
            for q in e.get("mapping") or []:
                if isinstance(q, dict):
                    rows.append({"Scheduler": _flatten(e.get("name", "")), "Queue": _flatten(q.get("queue", "")),
                                 "Type": _flatten(q.get("type", "")), "Weight": _flatten(q.get("weight", ""))})
    if rows:
        sections.append(("Queue Scheduler", rows))
    return sections


def _port_label_rows(data: Any) -> list[dict[str, Any]]:
    return [
        {"Label": _flatten(t.get("name", "")), "Label ID": _flatten(t.get("tagId", ""))}
        for t in (data if isinstance(data, list) else []) if isinstance(t, dict)
    ]


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

# SSID ``security`` codes, per the Open API SsidDetailOpenApiVO schema.  The
# WPA version lives in pskSetting / entSetting (see _ssid_security).
_SECURITY_MAP: dict[int, str] = {
    0: "Open",
    2: "WPA-Enterprise",
    3: "WPA-Personal",
    4: "PPSK",
    5: "PPSK + RADIUS",
}
_PSK_VERSION_MAP: dict[int, str] = {
    1: "WPA-PSK", 2: "WPA2-PSK", 3: "WPA/WPA2-PSK", 4: "WPA2-PSK/WPA3-SAE",
}
_ENT_VERSION_MAP: dict[int, str] = {
    1: "WPA-Enterprise", 2: "WPA2-Enterprise", 3: "WPA/WPA2-Enterprise", 4: "WPA3-Enterprise",
}
_WPA_ENCRYPTION_MAP: dict[int, str] = {1: "Auto", 3: "AES", 4: "AES-GCM 256", 5: "AES-CNSA", 6: "CCMP-128"}
_REKEY_UNIT_MAP: dict[int, str] = {0: "s", 1: "min", 2: "h"}
_PMF_MAP: dict[int, str] = {1: "Mandatory", 2: "Capable", 3: "Disabled"}
_NAS_ID_MODE_MAP: dict[int, str] = {0: "Default (MAC address)", 1: "Device name", 2: "Custom"}
_SSID_BAND_STEER_MAP: dict[int, str] = {0: "Disabled", 1: "Prefer 5GHz/6GHz", 2: "Balance", 3: "Use site setting"}
_SITE_BAND_STEER_MAP: dict[int, str] = {0: "Disabled", 1: "Prefer 5GHz/6GHz", 2: "Balance"}
_SCHEDULE_ACTION_MAP: dict[int, str] = {0: "Radio off during schedule", 1: "Radio on during schedule"}
_MAC_FILTER_POLICY_MAP: dict[int, str] = {0: "Deny List", 1: "Allow List"}
_RATE_UNIT_KM_MAP: dict[int, str] = {0: "Kbps", 1: "Mbps"}
_HOTSPOT2_NETWORK_MAP: dict[int, str] = {
    0: "Private", 1: "Private with guest access", 2: "Chargeable public", 3: "Free public",
    4: "Personal device", 5: "Emergency services only", 14: "Test or experimental", 15: "Wildcard",
}


def _ssid_lookups(context: dict[str, Any] | None) -> dict[str, dict[str, str]]:
    """ID → name maps for the profiles an SSID references."""
    ctx = context or {}

    def names(resource: str, *id_keys: str) -> dict[str, str]:
        out: dict[str, str] = {}
        for item in ctx.get(resource) or []:
            if isinstance(item, dict):
                for key in id_keys:
                    if item.get(key):
                        out[str(item[key])] = _flatten(item.get("name") or item[key])
        return out

    portals_by_ssid: dict[str, str] = {}
    for portal in ctx.get("portals") or []:
        if isinstance(portal, dict):
            for ssid_id in portal.get("ssidList") or []:
                portals_by_ssid.setdefault(str(ssid_id), _flatten(portal.get("name", "")))
    return {
        "radius": names("radius_profiles", "radiusProfileId", "id"),
        "rate": names("rate_limit_profiles", "profileId", "id"),
        "schedule": names("time_range_profiles", "profileId", "id"),
        "network": names("networks", "id"),
        "portal_by_ssid": portals_by_ssid,
    }


def _ssid_security(s: dict[str, Any], lookups: dict[str, dict[str, str]]) -> str:
    sec = s.get("security")
    psk = s.get("pskSetting") if isinstance(s.get("pskSetting"), dict) else {}
    ent = s.get("entSetting") if isinstance(s.get("entSetting"), dict) else {}
    if sec == 3 and psk.get("versionPsk") is not None:
        text = _profile_code(psk["versionPsk"], _PSK_VERSION_MAP)
        if psk.get("encryptionPsk") is not None:
            text += f" ({_profile_code(psk['encryptionPsk'], _WPA_ENCRYPTION_MAP)})"
        return text
    if sec == 2 and ent.get("versionEnt") is not None:
        text = _profile_code(ent["versionEnt"], _ENT_VERSION_MAP)
        radius = ent.get("radiusProfileId")
        if radius:
            text += f" (RADIUS: {lookups['radius'].get(str(radius), radius)})"
        return text
    if sec == 0 and s.get("oweEnable"):
        return "Open (OWE)"
    return _profile_code(sec, _SECURITY_MAP) if sec is not None else ""


def _ssid_vlan(s: dict[str, Any], lookups: dict[str, dict[str, str]]) -> str:
    vs = s.get("vlanSetting")
    if isinstance(vs, dict) and vs.get("mode") == 1 and isinstance(vs.get("customConfig"), dict):
        cfg = vs["customConfig"]
        if cfg.get("customMode") == 0 and cfg.get("lanNetworkId"):
            return lookups["network"].get(str(cfg["lanNetworkId"]), str(cfg["lanNetworkId"]))
        if cfg.get("vlanId") is not None:
            return f"VLAN {cfg['vlanId']}"
        if cfg.get("vlanPoolIds"):
            return f"VLAN pool {cfg['vlanPoolIds']}"
    if s.get("vlanEnable") and s.get("vlanId") is not None:
        return _flatten(s["vlanId"])
    if isinstance(vs, dict) and vs.get("mode") == 0:
        return "Default"
    return _flatten(s.get("vlanId", "")) if s.get("vlanEnable") else ""


def _rate_limit_text(setting: Any, lookups: dict[str, dict[str, str]]) -> str:
    """``profile name`` or ``Down 50 Mbps / Up 10 Mbps`` for a rate-limit setting."""
    if not isinstance(setting, dict):
        return ""
    if setting.get("profileId"):
        return lookups["rate"].get(str(setting["profileId"]), str(setting["profileId"]))
    custom = setting.get("customSetting")
    if not isinstance(custom, dict):
        return ""
    parts = []
    for prefix, label in (("down", "Down"), ("up", "Up")):
        if custom.get(f"{prefix}LimitEnable"):
            unit = _profile_code(custom.get(f"{prefix}LimitType", 0), _RATE_UNIT_KM_MAP)
            parts.append(f"{label} {custom.get(f'{prefix}Limit', '')} {unit}")
    return " / ".join(parts) if parts else "Unlimited"


def _ssid_schedule(s: dict[str, Any], lookups: dict[str, dict[str, str]]) -> str:
    sched = s.get("wlanSchedule")
    if not isinstance(sched, dict) or not sched.get("wlanScheduleEnable"):
        return "" if not isinstance(sched, dict) else "None"
    name = lookups["schedule"].get(str(sched.get("scheduleId", "")), _flatten(sched.get("scheduleId", "")))
    action = _profile_code(sched.get("action", ""), _SCHEDULE_ACTION_MAP)
    return f"{name} ({action})" if action else name


def _ssid_band_steer(s: dict[str, Any]) -> str:
    # The spec types the SSID band-steer setting under a field named
    # ``ssidDhcpOption``; accept that and a plain ``bandSteer``.
    for key in ("bandSteer", "ssidDhcpOption"):
        value = s.get(key)
        if isinstance(value, dict) and "mode" in value:
            return _profile_code(value["mode"], _SSID_BAND_STEER_MAP)
    return ""


def _ssid_rows(data: Any, context: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    items = data if isinstance(data, list) else []
    lookups = _ssid_lookups(context)
    rows = []
    for s in items:
        if not isinstance(s, dict):
            continue
        ssid_id = str(s.get("id", s.get("ssidId", "")))
        rows.append({
            "WLAN": s.get("wlanName", ""),
            "SSID": s.get("name", s.get("ssid", "")),
            "Security": _ssid_security(s, lookups),
            "Band": _BAND_MAP.get(s.get("band"), str(s.get("band", ""))),
            "Broadcast": "Yes" if s.get("broadcast", True) else "No",
            "VLAN": _ssid_vlan(s, lookups),
            "Guest": "Yes" if s.get("guestNetEnable") else "No",
            "Portal": lookups["portal_by_ssid"].get(ssid_id, ""),
            "Client Rate Limit": _rate_limit_text(s.get("clientRateLimit"), lookups),
            "Schedule": _ssid_schedule(s, lookups),
            "Band Steering": _ssid_band_steer(s),
        })
    return rows


def _ssid_details(
    data: Any, context: dict[str, Any] | None = None,
) -> list[tuple[str, list[dict[str, Any]]]]:
    items = data if isinstance(data, list) else []
    lookups = _ssid_lookups(context)
    details: list[tuple[str, list[dict[str, Any]]]] = []
    for s in items:
        if not isinstance(s, dict):
            continue
        ssid_id = str(s.get("id", s.get("ssidId", "")))
        rows: list[tuple[str, str, str]] = []

        def add(category: str, setting: str, value: Any) -> None:
            if value not in (None, ""):
                rows.append((category, setting, value if isinstance(value, str) else _flatten(value)))

        def flag(category: str, setting: str, obj: dict[str, Any], key: str) -> None:
            if key in obj:
                rows.append((category, setting, _enabled(obj[key])))

        add("General", "WLAN", s.get("wlanName"))
        add("General", "Band", _BAND_MAP.get(s.get("band"), s.get("band")))
        flag("General", "SSID Enabled", s, "ssidEnable")
        if "broadcast" in s:
            add("General", "Broadcast", "Yes" if s["broadcast"] else "No")
        if isinstance(s.get("deviceType"), int):
            kinds = [n for bit, n in ((1, "EAP"), (2, "Gateway")) if s["deviceType"] & bit]
            add("General", "Applies To", ", ".join(kinds))
        if "chooseDevices" in s:
            add("General", "Device Scope", "All devices" if s["chooseDevices"] == 0 else "Selected devices")
        if s.get("apGroupIds"):
            add("General", "AP Groups", ", ".join(str(g) for g in s["apGroupIds"]))

        add("Security", "Security", _ssid_security(s, lookups))
        psk = s.get("pskSetting") if isinstance(s.get("pskSetting"), dict) else {}
        ent = s.get("entSetting") if isinstance(s.get("entSetting"), dict) else {}
        ppsk = s.get("ppskSetting") if isinstance(s.get("ppskSetting"), dict) else {}
        if s.get("security") == 3 and psk:
            add("Security", "Passphrase", _secret_state(psk.get("securityKey")))
            if psk.get("gikRekeyPskEnable"):
                unit = _profile_code(psk.get("intervalPskType", 0), _REKEY_UNIT_MAP)
                add("Security", "Group Key Update", f"Every {psk.get('rekeyPskInterval', '')} {unit}")
        if s.get("security") == 2 and ent:
            radius = ent.get("radiusProfileId")
            add("Security", "RADIUS Profile", lookups["radius"].get(str(radius), radius) if radius else "")
            add("Security", "Encryption", _profile_code(ent.get("encryptionEnt"), _WPA_ENCRYPTION_MAP)
                if ent.get("encryptionEnt") is not None else "")
            if "nasIdMode" in ent:
                nas = _profile_code(ent["nasIdMode"], _NAS_ID_MODE_MAP)
                add("Security", "NAS ID", f"{nas}: {ent['nasId']}" if ent.get("nasId") else nas)
            if ent.get("gikRekeyEntEnable"):
                unit = _profile_code(ent.get("intervalEntType", 0), _REKEY_UNIT_MAP)
                add("Security", "Group Key Update", f"Every {ent.get('rekeyEntInterval', '')} {unit}")
        if s.get("security") in (4, 5) and ppsk:
            add("Security", "PPSK Profile", ppsk.get("ppskProfileId"))
            radius = ppsk.get("radiusProfileId")
            add("Security", "RADIUS Profile", lookups["radius"].get(str(radius), radius) if radius else "")
            add("Security", "NAS ID", ppsk.get("nasId"))
        flag("Security", "OWE (Enhanced Open)", s, "oweEnable")
        if s.get("pmfMode") is not None:
            add("Security", "PMF", _profile_code(s["pmfMode"], _PMF_MAP))
        flag("Security", "802.11r Fast Transition", s, "enable11r")
        flag("Security", "MLO", s, "mloEnable")
        flag("Security", "Prohibit Wi-Fi Sharing", s, "prohibitWifiShare")

        add("VLAN", "VLAN", _ssid_vlan(s, lookups) or "Default")

        if "guestNetEnable" in s:
            add("Guest / Portal", "Guest Network", "Yes" if s["guestNetEnable"] else "No")
        add("Guest / Portal", "Portal", lookups["portal_by_ssid"].get(ssid_id, "None"))

        add("Rate Limits", "Client Rate Limit", _rate_limit_text(s.get("clientRateLimit"), lookups))
        add("Rate Limits", "SSID Rate Limit", _rate_limit_text(s.get("ssidRateLimit"), lookups))

        add("Schedule", "WLAN Schedule", _ssid_schedule(s, lookups))
        add("Band Steering", "Band Steering", _ssid_band_steer(s))

        rc = s.get("rateControl") if isinstance(s.get("rateControl"), dict) else {}
        for band, beacon in (("2g", "1 Mbps"), ("5g", "6 Mbps")):
            label = "2.4 GHz" if band == "2g" else "5 GHz"
            if rc.get(f"rate{band}CtrlEnable"):
                text = f"Minimum {rc.get(f'lowerDensity{band}', '')} Mbps"
                if rc.get(f"clientRatesRequire{band}"):
                    text += ", required for clients"
                if rc.get(f"sendBeacons{band}"):
                    text += f", beacons at {beacon}"
                if band == "2g" and rc.get("cckRatesDisable"):
                    text += ", CCK rates disabled"
                add("Rate Control", f"{label} Data Rate", text)
            elif f"rate{band}CtrlEnable" in rc:
                add("Rate Control", f"{label} Data Rate", "Disabled")
            if rc.get(f"manageRateControl{band}Enable"):
                add("Rate Control", f"{label} Management Rate", f"{rc.get(f'manageRateControl{band}', '')} Mbps")

        mf = s.get("macFilter") if isinstance(s.get("macFilter"), dict) else {}
        if "macFilterEnable" in mf:
            text = _enabled(mf["macFilterEnable"])
            if mf["macFilterEnable"]:
                text += f" ({_profile_code(mf.get('policy', ''), _MAC_FILTER_POLICY_MAP)}"
                text += f", MAC group {mf.get('macFilterId', '')})" if mf.get("macFilterId") else ")"
            add("MAC Filter", "MAC Filter", text)

        mc = s.get("multiCast") if isinstance(s.get("multiCast"), dict) else {}
        flag("Multicast", "Multicast to Unicast", mc, "multiCastEnable")
        flag("Multicast", "IPv6 Multicast to Unicast", mc, "ipv6CastEnable")
        flag("Multicast", "ARP to Unicast", mc, "arpCastEnable")
        if mc.get("channelUtil") is not None:
            add("Multicast", "Channel Utilization Threshold", f"{mc['channelUtil']}%")
        flag("Multicast", "Multicast Filter", mc, "filterEnable")

        opt82 = s.get("dhcpOption82") if isinstance(s.get("dhcpOption82"), dict) else {}
        flag("DHCP", "DHCP Option 82", opt82, "dhcpEnable")

        hs2 = s.get("hotspotV2Setting") if isinstance(s.get("hotspotV2Setting"), dict) else {}
        if "hotspotV2Enable" in hs2:
            text = _enabled(hs2["hotspotV2Enable"])
            if hs2["hotspotV2Enable"] and hs2.get("networkType") is not None:
                text += f" ({_profile_code(hs2['networkType'], _HOTSPOT2_NETWORK_MAP)} network)"
            add("Hotspot 2.0", "Hotspot 2.0", text)
            if hs2.get("hotspotV2Enable"):
                add("Hotspot 2.0", "Operator Domain", hs2.get("operatorDomain"))
                add("Hotspot 2.0", "Operator Name", hs2.get("operatorFriendly"))
        flag("Other", "Wi-Fi Calling", s, "wifiCallingEnable")
        flag("Other", "Enhanced IoT Connectivity", s, "enhancedIotConnectivity")

        title = _flatten(s.get("name", "")) or ssid_id
        details.append((title, _detail_rows(rows)))

        overrides = [
            {
                "AP": _flatten(o.get("name", "")),
                "AP MAC": _flatten(o.get("mac", "")),
                "SSID Enabled": _enabled(o.get("ssidEnable")) if "ssidEnable" in o else "",
                "Override SSID Name": _flatten(o.get("overrideName", "")),
                "Override VLAN": _flatten(o.get("overrideVlan", "")),
                "Override Password": _secret_state(o.get("overridePassword")) if "overridePassword" in o else "",
            }
            for o in s.get("apOverrides") or [] if isinstance(o, dict)
        ]
        if overrides:
            details.append((f"{title} AP overrides", overrides))
    return details


# RADIUS profiles ---------------------------------------------------------------

def _radius_servers(servers: Any, ip_key: str, port_key: str, pwd_key: str) -> str:
    parts = []
    for srv in servers or []:
        if not isinstance(srv, dict):
            continue
        host = _flatten(srv.get(ip_key, ""))
        text = f"{host}:{srv[port_key]}" if srv.get(port_key) is not None else host
        extras = []
        if srv.get("radSecEnable"):
            extras.append("RadSec")
        if pwd_key in srv:
            state = _secret_state(srv[pwd_key])
            extras.append(f"secret {state.lower() if state in ('Configured', 'Not set') else state}")
        parts.append(f"{text} ({', '.join(extras)})" if extras else text)
    return "; ".join(parts)


def _radius_profile_rows(data: Any) -> list[dict[str, Any]]:
    items = data if isinstance(data, list) else []
    rows = []
    for r in items:
        if not isinstance(r, dict):
            continue
        if r.get("builtInServer"):
            servers = "Built-in server"
            if "serverEnable" in r:
                servers += f" ({_enabled(r['serverEnable']).lower()})"
            if r.get("ipType") == 1 and r.get("customIp"):
                servers += f", IP {r['customIp']}"
        else:
            servers = _radius_servers(r.get("authServer"), "radiusServerIp", "radiusPort", "radiusPwd")
        if r.get("radiusAccountingEnable"):
            accounting = _radius_servers(r.get("acctServer"), "accountingServerIp",
                                         "accountingServerPort", "accountingServerPwd") or "Enabled"
            if r.get("interimUpdateEnable") and r.get("interimUpdateInterval") is not None:
                accounting += f"; interim update {r['interimUpdateInterval']} s"
        else:
            accounting = "Disabled"
        rows.append({
            "Name": _flatten(r.get("name", "")),
            "Type": "Built-in" if r.get("builtInServer") else "External",
            "Authentication Servers": servers,
            "Accounting": accounting,
            "VLAN Assignment": _enabled(r.get("wirelessVlanAssignment")),
            "CoA": _enabled(r.get("coaEnable")),
            "Message-Authenticator": "Required" if r.get("requireMessageAuthenticator") else "Not required",
        })
    return rows


# Portals -------------------------------------------------------------------------

_PORTAL_AUTH_MAP: dict[int, str] = {
    0: "No Authentication", 1: "Simple Password", 2: "External RADIUS", 4: "External Portal Server",
    11: "Hotspot", 15: "LDAP", 16: "Social Login",
}
_HOTSPOT_TYPE_MAP: dict[int, str] = {3: "Voucher", 5: "Local User", 6: "SMS", 8: "RADIUS", 12: "Form Auth"}
_SOCIAL_LOGIN_MAP: dict[int, str] = {17: "Google"}
_AUTH_TIMEOUT_MAP: dict[int, str] = {
    1: "30 minutes", 2: "1 hour", 3: "2 hours", 4: "4 hours", 5: "8 hours", 6: "1 day", 7: "7 days",
}
_TIMEOUT_UNIT_MAP: dict[int, str] = {1: "min", 2: "hours", 3: "days"}
_PAP_CHAP_MAP: dict[int, str] = {1: "PAP", 2: "CHAP"}
_LANDING_PAGE_MAP: dict[int, str] = {1: "Original URL", 2: "Promotional URL"}
_PORTAL_CUSTOM_MAP: dict[int, str] = {1: "Local Web Portal", 2: "External Web Portal"}


def _portal_timeout(value: Any) -> str:
    if not isinstance(value, dict):
        return _flatten(value)
    if value.get("authTimeout") == 0:
        unit = _profile_code(value.get("customTimeoutUnit", ""), _TIMEOUT_UNIT_MAP)
        return f"{value.get('customTimeout', '')} {unit}".strip()
    return _profile_code(value.get("authTimeout", ""), _AUTH_TIMEOUT_MAP)


def _portal_auth(p: dict[str, Any]) -> str:
    text = _profile_code(p.get("authType", ""), _PORTAL_AUTH_MAP)
    types = (p.get("hotspot") or {}).get("enabledTypes") if isinstance(p.get("hotspot"), dict) else None
    types = types or p.get("hotspotTypes")
    if p.get("authType") == 11 and types:
        text += f" ({', '.join(_profile_code(t, _HOTSPOT_TYPE_MAP) for t in types)})"
    social = (p.get("socialLogin") or {}).get("enabledTypes") if isinstance(p.get("socialLogin"), dict) else None
    social = social or p.get("socialLoginTypes")
    if p.get("authType") == 16 and social:
        text += f" ({', '.join(_profile_code(t, _SOCIAL_LOGIN_MAP) for t in social)})"
    return text


def _portal_ssid_names(p: dict[str, Any], context: dict[str, Any] | None) -> str:
    names = {
        str(s.get("id", s.get("ssidId", ""))): _flatten(s.get("name", ""))
        for s in (context or {}).get("ssids") or [] if isinstance(s, dict)
    }
    return ", ".join(names.get(str(i), str(i)) for i in p.get("ssidList") or [])


def _portal_rows(data: Any, context: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    items = data if isinstance(data, list) else []
    lookup = _build_id_lookup(context)
    return [
        {
            "Name": _flatten(p.get("name", "")),
            "Status": _enabled(p.get("enable")),
            "Authentication": _portal_auth(p),
            "SSIDs": _portal_ssid_names(p, context),
            "Networks": _resolve_ids(p.get("networkList") or [], lookup),
            "Auth Timeout": _portal_timeout(p.get("authTimeout")),
            "Landing Page": (
                f"{_profile_code(p['landingPage'], _LANDING_PAGE_MAP)}"
                + (f" ({p.get('landingUrlScheme', 'http')}://{p['landingUrl']})" if p.get("landingUrl") else "")
            ) if p.get("landingPage") is not None else "",
            "HTTPS Redirect": _enabled(p.get("httpsRedirectEnable")) if "httpsRedirectEnable" in p else "",
        }
        for p in items
        if isinstance(p, dict)
    ]


def _portal_details(
    data: Any, context: dict[str, Any] | None = None,
) -> list[tuple[str, list[dict[str, Any]]]]:
    items = data if isinstance(data, list) else []
    radius_names = _ssid_lookups(context)["radius"]
    details = []
    for p in items:
        if not isinstance(p, dict):
            continue
        rows: list[tuple[str, str, str]] = [("Portal", "Authentication", _portal_auth(p))]
        no_auth = p.get("noAuth")
        if isinstance(no_auth, dict) and "dailyLimitEnable" in no_auth:
            rows.append(("No Authentication", "Once per Day", _enabled(no_auth["dailyLimitEnable"])))
        simple = p.get("simplePassword")
        if isinstance(simple, dict) and "password" in simple:
            rows.append(("Simple Password", "Password", _secret_state(simple["password"])))
        for key, label in (("externalRadius", "External RADIUS"), ("hotspotRadius", "Hotspot RADIUS")):
            rad = p.get(key)
            if not isinstance(rad, dict) or not rad:
                continue
            profile = rad.get("radiusProfileId")
            if profile:
                rows.append((label, "RADIUS Profile", radius_names.get(str(profile), str(profile))))
            if rad.get("authMode") is not None:
                rows.append((label, "Auth Mode", _profile_code(rad["authMode"], _PAP_CHAP_MAP)))
            if rad.get("nasId"):
                rows.append((label, "NAS ID", _flatten(rad["nasId"])))
            if rad.get("portalCustom") is not None:
                rows.append((label, "Portal Page", _profile_code(rad["portalCustom"], _PORTAL_CUSTOM_MAP)))
            if rad.get("externalUrl"):
                rows.append((label, "External URL", f"{rad.get('externalUrlScheme', 'http')}://{rad['externalUrl']}"))
            if "disconnectReq" in rad:
                text = _enabled(rad["disconnectReq"])
                if rad["disconnectReq"] and rad.get("receiverPort") is not None:
                    text += f" (port {rad['receiverPort']})"
                rows.append((label, "Disconnect Requests", text))
        ext = p.get("externalPortal")
        if isinstance(ext, dict) and ext:
            if ext.get("hostType") == 2 and ext.get("serverUrl"):
                server = f"{ext.get('serverUrlScheme', 'http')}://{ext['serverUrl']}"
            else:
                host = _flatten(ext.get("serverIp", ""))
                server = f"{host}:{ext['serverPort']}" if ext.get("serverPort") else host
            rows.append(("External Portal", "Server", server))
        ldap = p.get("ldap")
        if isinstance(ldap, dict) and ldap.get("ldapProfileId"):
            rows.append(("LDAP", "LDAP Profile", _flatten(ldap["ldapProfileId"])))
        google = p.get("google")
        if isinstance(google, dict) and google:
            rows.append(("Google", "Client ID", _flatten(google.get("clientId", ""))))
            rows.append(("Google", "Client Secret", _secret_state(google.get("clientSecret"))))
        sms = p.get("sms")
        if isinstance(sms, dict) and sms:
            rows.append(("SMS (Twilio)", "Account SID", _flatten(sms.get("sid", ""))))
            rows.append(("SMS (Twilio)", "Auth Token", _secret_state(sms.get("authToken"))))
            rows.append(("SMS (Twilio)", "Sender Number", _flatten(sms.get("phoneNum", ""))))
        if p.get("portalFormId"):
            rows.append(("Portal", "Form", _flatten(p["portalFormId"])))
        rows = [r for r in rows if r[2] != ""]
        details.append((_flatten(p.get("name", "")) or _flatten(p.get("id", "")), _detail_rows(rows)))
    return details


# Schedules (time range profiles) and rate limit profiles ------------------------------

_DAY_MODE_MAP: dict[int, str] = {0: "Every day", 1: "Weekdays", 2: "Weekends", 3: "Custom"}
_DAY_NAMES = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")


def _time_range_rows(data: Any) -> list[dict[str, Any]]:
    items = data if isinstance(data, list) else []
    rows = []
    for t in items:
        if not isinstance(t, dict):
            continue
        days = _profile_code(t.get("dayMode", ""), _DAY_MODE_MAP)
        custom = t.get("customDayMode")
        if t.get("dayMode") == 3 and isinstance(custom, dict):
            days = ", ".join(d for d in _DAY_NAMES if custom.get(f"day{d}")) or "None"
        times = []
        for slot in t.get("timeList") or []:
            if not isinstance(slot, dict):
                continue
            span = (f"{slot.get('startTimeH', 0):02d}:{slot.get('startTimeM', 0):02d}–"
                    f"{slot.get('endTimeH', 0):02d}:{slot.get('endTimeM', 0):02d}")
            day = slot.get("dayType")
            times.append(f"{_DAY_NAMES[day - 1]} {span}" if isinstance(day, int) and 1 <= day <= 7 else span)
        rows.append({"Name": _flatten(t.get("name", "")), "Days": days, "Times": ", ".join(times)})
    return rows


def _rate_limit_profile_rows(data: Any) -> list[dict[str, Any]]:
    items = data if isinstance(data, list) else []
    return [
        {
            "Name": _flatten(r.get("name", "")),
            "Download": f"{r.get('downLimit', '')} Kbps" if r.get("downLimitEnable") else "Unlimited",
            "Upload": f"{r.get('upLimit', '')} Kbps" if r.get("upLimitEnable") else "Unlimited",
            "Default": "Yes" if r.get("defaultProfile") else "No",
        }
        for r in items
        if isinstance(r, dict)
    ]


# Site wireless settings ------------------------------------------------------------------

def _unwrap(settings: dict[str, Any], key: str, inner: str) -> dict[str, Any]:
    """Settings arrive wrapped, e.g. ``{"roaming": {"roaming": {...}}}``."""
    value = settings.get(key)
    if isinstance(value, dict) and isinstance(value.get(inner), dict):
        return value[inner]
    return value if isinstance(value, dict) else {}


def _wireless_settings_rows(data: Any) -> list[dict[str, Any]]:
    if not isinstance(data, dict) or not data:
        return []
    rows: list[tuple[str, str, str]] = []
    band = _unwrap(data, "bandSteering", "bandSteeringForMultiBand")
    if "mode" in band:
        rows.append(("Band Steering", "Mode", _profile_code(band["mode"], _SITE_BAND_STEER_MAP)))
    roaming = _unwrap(data, "roaming", "roaming")
    for key, label in (
        ("fastRoamingEnable", "Fast Roaming"), ("aiRoamingEnable", "AI Roaming"),
        ("nonStickRoamingEnable", "Non-Stick Roaming"), ("dualBand11kReportEnable", "802.11k Report"),
        ("forceDisassociationEnable", "Forced Disassociation"),
    ):
        if key in roaming:
            rows.append(("Roaming", label, _enabled(roaming[key])))
    mesh = _unwrap(data, "mesh", "mesh")
    for key, label in (("meshEnable", "Mesh"), ("autoFailoverEnable", "Auto Failover"),
                       ("fullSector", "Full-Sector DFS")):
        if key in mesh:
            rows.append(("Mesh", label, _enabled(mesh[key])))
    if "defGatewayEnable" in mesh:
        rows.append(("Mesh", "Connectivity Detection",
                     "Auto" if mesh["defGatewayEnable"] else f"Custom IP {mesh.get('gateway', '')}".strip()))
    mcast = _unwrap(data, "multicastRateLimit", "mcastRateLimit")
    if "enable" in mcast:
        rows.append(("Multicast Rate Limit", "Multicast Rate Limit", _enabled(mcast["enable"])))
        if mcast["enable"]:
            for proto, label in (("arp", "ARP"), ("nd", "ND"), ("igmp", "IGMP"), ("dhcp", "DHCP"),
                                 ("dhcpv6", "DHCPv6"), ("mdns", "mDNS"), ("otherBcast", "Other Broadcast"),
                                 ("otherMcast", "Other Multicast")):
                if f"{proto}Enable" in mcast:
                    value = f"{mcast.get(f'{proto}Pps', '')} pps" if mcast[f"{proto}Enable"] else "Not limited"
                    rows.append(("Multicast Rate Limit", label, value))
    return [{"Category": c, "Setting": s, "Value": v} for c, s, v in rows]


# AP radios -------------------------------------------------------------------------------

_RADIO_BAND_LABELS: dict[str, str] = {
    "2g": "2.4 GHz", "5g": "5 GHz", "5g1": "5 GHz-1", "5g2": "5 GHz-2", "6g": "6 GHz",
}
_CHANNEL_WIDTH_MAP: dict[int, str] = {
    2: "20 MHz", 3: "40 MHz", 4: "Auto (20/40 MHz)", 5: "80 MHz", 6: "Auto (20/40/80 MHz)",
    7: "160 MHz", 8: "Auto (20/40/80/160 MHz)", 9: "240 MHz", 10: "320 MHz",
}
_TX_POWER_LEVEL_MAP: dict[int, str] = {0: "Low", 1: "Medium", 2: "High", 3: "Custom", 4: "Auto"}
_WIRELESS_MODE_MAP: dict[int, str] = {
    -2: "Auto", 3: "802.11b/g", 4: "802.11b/g/n", 13: "802.11b/g/n/ax", 17: "802.11b/g/n/ax/be",
    7: "802.11a/n", 10: "802.11a/n/ac", 16: "802.11a/n/ac/ax", 18: "802.11a/n/ac/ax/be",
    11: "802.11ax only", 19: "802.11ax/be",
}


def _ap_radio_rows(data: Any) -> list[dict[str, Any]]:
    """One row per AP radio; values are what the AP is configured with."""
    items = data if isinstance(data, list) else []
    rows = []
    for ap in items:
        if not isinstance(ap, dict):
            continue
        radios = ap.get("radios") if isinstance(ap.get("radios"), dict) else {}
        for band in sorted(radios, key=lambda b: list(_RADIO_BAND_LABELS).index(b)
                           if b in _RADIO_BAND_LABELS else 99):
            r = radios[band]
            if not isinstance(r, dict):
                continue
            enabled = r.get("radioEnable")
            width = r.get("channelWidth")
            try:
                width = _CHANNEL_WIDTH_MAP.get(int(width), str(width)) if width not in (None, "") else ""
            except (TypeError, ValueError):
                width = _flatten(width)
            # Per the spec, channel 0 means automatic channel selection.
            channel = "Auto" if str(r.get("channel", "")).strip() == "0" else _flatten(r.get("channel", ""))
            level = r.get("txPowerLevel")
            power = _profile_code(level, _TX_POWER_LEVEL_MAP) if level is not None else ""
            if level == 3 and r.get("txPower") is not None:
                power = f"Custom ({r['txPower']} dBm)"
            rows.append({
                "AP": _flatten(ap.get("deviceName", "")),
                "Model": _flatten(ap.get("deviceModel", "")),
                "Band": _RADIO_BAND_LABELS.get(band, band),
                "Radio": _enabled(enabled) if enabled is not None else "",
                "Channel": channel if enabled is not False else "",
                "Channel Width": width if enabled is not False else "",
                "Tx Power": power if enabled is not False else "",
                "Wireless Mode": _profile_code(r["wirelessMode"], _WIRELESS_MODE_MAP)
                if r.get("wirelessMode") is not None and enabled is not False else "",
                "Channel Limit": _enabled(r["channelLimitEnable"]) if "channelLimitEnable" in r else "",
            })
    return rows


def _dhcp_reservation_rows(data: Any) -> list[dict[str, Any]]:
    """Reservations sorted by network, then numerically by IP."""
    items = [r for r in (data if isinstance(data, list) else []) if isinstance(r, dict)]
    items.sort(key=lambda r: (
        str(r.get("netName", r.get("networkName", ""))).lower(), _ip_sort_key(r.get("ip", "")),
    ))
    rows = []
    for r in items:
        options = "; ".join(
            f"Option {o.get('code', '?')}: {_flatten(o.get('value', ''))}" if isinstance(o, dict) else str(o)
            for o in r.get("options") or []
        )
        rows.append({
            "Network": r.get("netName", r.get("networkName", "")),
            "IP Address": r.get("ip", ""),
            "MAC Address": r.get("mac", ""),
            "Name": r.get("name", r.get("clientName", "")),
            "Description": _flatten(r.get("description", "")),
            "Options": options,
            "Status": "Enabled" if r.get("status") else "Disabled",
            "Server": r.get("serverName", ""),
        })
    return rows


_DHCP_DEVICE_TYPE_MAP: dict[int, str] = {0: "External", 1: "Gateway", 2: "Switch", 3: "None"}
_SWITCH_DHCP_MODE_MAP: dict[int, str] = {0: "None", 1: "DHCP Server", 2: "DHCP Relay"}
_DHCP_GUARD_MODE_MAP: dict[int, str] = {1: "Follow Server", 2: "Custom"}
# The option value-type codes differ between gateway and switch DHCP servers.
_GATEWAY_OPTION_TYPE_MAP: dict[int, str] = {0: "String", 1: "IP Address", 2: "Hex Array"}
_SWITCH_OPTION_TYPE_MAP: dict[int, str] = {0: "Hex Array", 1: "String", 2: "IP Address"}
_DHCP_LEASE_BINDING_MAP: dict[int, str] = {0: "Dynamic", 1: "Static"}
_DHCP_USER_TYPE_MAP: dict[int, str] = {0: "Device", 1: "Client"}


def _ip_sort_key(ip: Any) -> tuple[int, ...]:
    try:
        return tuple(int(part) for part in str(ip).split("."))
    except ValueError:
        return (999,)


def _device_names(context: dict[str, Any] | None) -> dict[str, str]:
    names: dict[str, str] = {}
    for d in (context or {}).get("devices") or []:
        if isinstance(d, dict) and d.get("mac"):
            names[str(d["mac"]).upper()] = _flatten(d.get("name") or d["mac"])
    return names


def _scope_settings(scope: dict[str, Any]) -> dict[str, Any]:
    settings = scope.get("dhcpSettings") or scope.get("dhcpSettingsVO")
    return settings if isinstance(settings, dict) else {}


def _scope_server(scope: dict[str, Any], devices: dict[str, str]) -> str:
    """Who answers DHCP on this network, e.g. ``Gateway (Astoria Gateway)``."""
    settings = _scope_settings(scope)
    device_type = scope.get("deviceType")
    if device_type is None:
        device_type = 1 if settings.get("enable") else 3
    name = devices.get(str(scope.get("deviceMac", "")).upper(), _flatten(scope.get("deviceMac", "")))
    if device_type == 1:
        if not settings.get("enable"):
            return "Disabled"
        return f"Gateway ({name})" if name else "Gateway"
    if device_type == 2:
        mode = _profile_code(scope.get("mode", 0), _SWITCH_DHCP_MODE_MAP)
        label = f"Switch {mode}" if scope.get("mode") in (1, 2) else "Switch (no DHCP)"
        return f"{label} ({name})" if name else label
    return _profile_code(device_type, _DHCP_DEVICE_TYPE_MAP)


def _scope_pools(scope: dict[str, Any]) -> list[str]:
    status = {
        (r.get("startIp"), r.get("endIp")): r.get("availableIpNum")
        for r in scope.get("poolStatus") or [] if isinstance(r, dict)
    }
    ranges: list[tuple[Any, Any]] = []
    if scope.get("deviceType") == 2 and isinstance(scope.get("dhcpServer"), dict):
        server = scope["dhcpServer"]
        for r in server.get("range") or server.get("ipRangePool") or []:
            if isinstance(r, dict):
                ranges.append((r.get("startIp"), r.get("endIp")))
    else:
        settings = _scope_settings(scope)
        for r in settings.get("ipRangePool") or []:
            if isinstance(r, dict):
                ranges.append((r.get("ipaddrStart", r.get("startIp")), r.get("ipaddrEnd", r.get("endIp"))))
        if not ranges and settings.get("ipaddrStart"):
            ranges.append((settings.get("ipaddrStart"), settings.get("ipaddrEnd")))
    pools = []
    for start, end in ranges:
        text = f"{start} – {end}"
        available = status.get((start, end))
        if available is not None:
            text += f" ({available} free)"
        pools.append(text)
    return pools


def _scope_config(scope: dict[str, Any]) -> tuple[dict[str, Any], dict[int, str]]:
    """The active DHCP server config and its option type map."""
    if scope.get("deviceType") == 2 and isinstance(scope.get("dhcpServer"), dict):
        return scope["dhcpServer"], _SWITCH_OPTION_TYPE_MAP
    return _scope_settings(scope), _GATEWAY_OPTION_TYPE_MAP


def _scope_dns(config: dict[str, Any]) -> str:
    servers = ", ".join(str(x) for x in (config.get("priDns"), config.get("sndDns")) if x)
    if config.get("dhcpns") == "auto":
        return "Auto"
    return servers


def _scope_serves(scope: dict[str, Any]) -> bool:
    if scope.get("deviceType") == 2:
        return scope.get("mode") == 1
    return bool(_scope_settings(scope).get("enable"))


def _dhcp_scope_rows(data: Any, context: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    items = data if isinstance(data, list) else []
    devices = _device_names(context)
    rows = []
    for s in items:
        if not isinstance(s, dict):
            continue
        config, _ = _scope_config(s)
        serves = _scope_serves(s)
        relay = s.get("dhcpRelay") if s.get("deviceType") == 2 and s.get("mode") == 2 else None
        rows.append({
            "Network": _flatten(s.get("name", "")),
            "VLAN": _flatten(s.get("vlan", s.get("vlans", ""))),
            "Subnet": _flatten(s.get("gatewaySubnet", "")),
            "DHCP Server": _scope_server(s, devices),
            "Pools": "; ".join(_scope_pools(s)) if serves else "",
            "Lease Time": f"{config['leasetime']} min" if serves and config.get("leasetime") else "",
            "DNS": _scope_dns(config) if serves else "",
            "Gateway": _flatten(config.get("gateway", "")) if serves else "",
            "Domain": _flatten(s.get("domain", "")),
            "Relay To": ", ".join(str(a) for a in relay.get("serverAddrs") or [])
            if isinstance(relay, dict) else "",
            "L2 Relay (Opt 82)": _enabled(s.get("dhcpL2RelayEnable")),
        })
    return rows


def _dhcp_option_rows(config: dict[str, Any], type_map: dict[int, str]) -> list[tuple[str, str, str]]:
    rows = []
    for key, label in (
        ("option60", "Option 60 (Vendor Class)"),
        ("option66", "Option 66 (TFTP Server)"),
        ("option138", "Option 138 (Controller)"),
        ("hostIP", "Controller IP"),
        ("dhcpNextServer", "Next Server (siaddr)"),
    ):
        if config.get(key):
            rows.append(("Options", label, _flatten(config[key])))
    for opt in config.get("options") or []:
        if not isinstance(opt, dict):
            continue
        name = f" {opt['name']}" if opt.get("name") else ""
        kind = _profile_code(opt.get("type", ""), type_map)
        value = _flatten(opt.get("value", ""))
        rows.append(("Options", f"Option {opt.get('code', '?')}{name}", f"{kind}: {value}" if kind else value))
    return rows


def _dhcp_scope_details(
    data: Any, context: dict[str, Any] | None = None,
) -> list[tuple[str, list[dict[str, Any]]]]:
    items = data if isinstance(data, list) else []
    devices = _device_names(context)
    details = []
    for s in items:
        if not isinstance(s, dict):
            continue
        config, type_map = _scope_config(s)
        serves = _scope_serves(s)
        rows: list[tuple[str, str, str]] = [
            ("Server", "DHCP Server", _scope_server(s, devices)),
            ("Server", "Subnet", _flatten(s.get("gatewaySubnet", ""))),
        ]
        if s.get("dhcpServerNum") is not None:
            rows.append(("Server", "Active DHCP Servers", _flatten(s["dhcpServerNum"])))
        if s.get("deviceType") == 2 and isinstance(s.get("dhcpServer"), dict) and s.get("mode") == 1:
            server = s["dhcpServer"]
            if server.get("ip"):
                mask = f"/{server['netmask']}" if server.get("netmask") else ""
                rows.append(("Server", "Switch Interface", f"{server['ip']}{mask}"))
        if serves:
            for i, pool in enumerate(_scope_pools(s), 1):
                rows.append(("Pool", f"Range {i}", pool))
            if config.get("dhcpPoolMask") is not None:
                rows.append(("Pool", "Pool Mask", f"/{config['dhcpPoolMask']}"))
            if config.get("leasetime") is not None:
                rows.append(("Pool", "Lease Time", f"{config['leasetime']} min"))
            if config.get("dhcpns"):
                rows.append(("DNS / Domain", "DNS Mode", str(config["dhcpns"]).title()))
            for key, label in (("priDns", "Primary DNS"), ("sndDns", "Secondary DNS")):
                if config.get(key):
                    rows.append(("DNS / Domain", label, _flatten(config[key])))
        if s.get("domain"):
            rows.append(("DNS / Domain", "Domain Name", _flatten(s["domain"])))
        if serves:
            rows.append(("Options", "Default Gateway (Option 3)", _flatten(config.get("gateway") or "Default")))
            rows += _dhcp_option_rows(config, type_map)
        rows.append(("Relay", "DHCP L2 Relay (Option 82)", _enabled(s.get("dhcpL2RelayEnable"))))
        relay = s.get("dhcpRelay")
        if s.get("deviceType") == 2 and s.get("mode") == 2 and isinstance(relay, dict):
            if relay.get("addr"):
                rows.append(("Relay", "Relay Interface", _flatten(relay["addr"])))
            rows.append(("Relay", "Relay To", ", ".join(str(a) for a in relay.get("serverAddrs") or [])))
        for key, label in (("dhcpGuard", "DHCP Guard"), ("dhcpv6Guard", "DHCPv6 Guard")):
            guard = s.get(key)
            if not isinstance(guard, dict):
                continue
            rows.append(("Guard", label, _enabled(guard.get("enable"))))
            if guard.get("enable"):
                if guard.get("mode") is not None:
                    rows.append(("Guard", f"{label} Mode", _profile_code(guard["mode"], _DHCP_GUARD_MODE_MAP)))
                trusted = [guard.get(k) for k in ("dhcpSvr1", "dhcpSvr2", "dhcpv6Svr1", "dhcpv6Svr2")]
                if any(trusted):
                    rows.append(("Guard", f"{label} Trusted Servers", ", ".join(str(t) for t in trusted if t)))
        rows = [r for r in rows if r[2] != ""]
        details.append((_flatten(s.get("name", "")) or _flatten(s.get("id", "")), _detail_rows(rows)))
    return details


def _dhcp_lease_rows(data: Any) -> list[dict[str, Any]]:
    items = [u for u in (data if isinstance(data, list) else []) if isinstance(u, dict)]
    items.sort(key=lambda u: (str(u.get("netName", "")).lower(), _ip_sort_key(u.get("ipAddress", ""))))
    return [
        {
            "Network": _flatten(u.get("netName", "")),
            "IP Address": _flatten(u.get("ipAddress", "")),
            "MAC Address": _flatten(u.get("macAddress", "")),
            "Name": _flatten(u.get("name", "")),
            "Type": _flatten(u.get("showingType", "")) or _profile_code(u.get("type", ""), _DHCP_USER_TYPE_MAP),
            "Binding": _profile_code(u.get("status", ""), _DHCP_LEASE_BINDING_MAP),
            "Lease Remaining": _flatten(u.get("leftLeaseTime", "")),
            "Server": _flatten(u.get("serverName", "")),
        }
        for u in items
    ]


_SWITCH_PORT_TYPE_MAP: dict[int, str] = {1: "Copper", 2: "Combo", 3: "SFP"}

_GATEWAY_PORT_TYPE_MAP: dict[int, str] = {0: "WAN", 1: "WAN/LAN", 2: "LAN"}

_GATEWAY_PORT_MODE_MAP: dict[int, str] = {0: "WAN", 1: "LAN"}

_SWITCH_CONNECTED_MAP: dict[int, str] = {0: "Connected", 1: "Disconnected", 2: "Disabled"}

# Negotiated speed as reported in port status (not the configured speed).
_STATUS_SPEED_MAP: dict[int, str] = {1: "10M", 2: "100M", 3: "1000M", 4: "10G"}

_STATUS_DUPLEX_MAP: dict[int, str] = {1: "Half Duplex", 2: "Full Duplex"}


def _map_code(value: Any, mapping: dict[int, str]) -> str:
    if isinstance(value, int) and not isinstance(value, bool):
        return mapping.get(value, str(value))
    return _flatten(value)


def _link_detail(status: Any) -> str:
    """Return e.g. ``"1000M Full Duplex"`` from a port-status dict."""
    if not isinstance(status, dict):
        return ""
    parts = [
        _map_code(status[key], mapping)
        for key, mapping in (("linkSpeed", _STATUS_SPEED_MAP), ("duplex", _STATUS_DUPLEX_MAP))
        if status.get(key) not in (None, 0)
    ]
    return " ".join(p for p in parts if p)


def _port_connection(p: dict[str, Any]) -> str:
    """Connection state, with negotiated speed/duplex when connected."""
    status = p.get("portStatus") if isinstance(p.get("portStatus"), dict) else {}
    if p.get("deviceType") == "gateway":
        if p.get("status") == 0:
            return "Disabled"
        link = status.get("linkStatus")
        if link is None:
            return ""
        state = "Connected" if link == 1 else "Disconnected"
    else:
        if p.get("disable") is True:
            return "Disabled"
        if "connectedStatus" in p:
            state = _map_code(p["connectedStatus"], _SWITCH_CONNECTED_MAP)
        elif "linkStatus" in status:
            state = "Connected" if status["linkStatus"] == 1 else "Disconnected"
        elif p.get("status") == 0:
            return "Disabled"
        else:
            return ""
    # Only trust the negotiated speed when portStatus itself reports link up:
    # some controllers return a placeholder block (linkStatus 0, linkSpeed 1)
    # for ports that connectedStatus reports as connected.
    detail = _link_detail(status) if state == "Connected" and status.get("linkStatus") == 1 else ""
    return f"{state} ({detail})" if detail else state


def _port_operation(p: dict[str, Any]) -> str:
    if p.get("deviceType") == "gateway":
        if p.get("mirrorEnable"):
            return "Mirroring"
        return _map_code(p.get("mode", ""), _GATEWAY_PORT_MODE_MAP)
    operation = p.get("operation", "")
    text = str(operation).title() if isinstance(operation, str) else _flatten(operation)
    lag = p.get("lagSetting") if isinstance(p.get("lagSetting"), dict) else {}
    if str(operation).upper() == "AGGREGATING" and lag.get("lagId") is not None:
        text += f" (LAG {lag['lagId']})"
    return text


def _network_lookups(context: dict[str, Any] | None) -> tuple[dict[str, str], dict[str, str]]:
    """Return (network id → name, VLAN id → name) from the networks context."""
    by_id: dict[str, str] = {}
    by_vlan: dict[str, str] = {}
    for net in (context or {}).get("networks") or []:
        if not isinstance(net, dict):
            continue
        name = net.get("name", "")
        if net.get("id"):
            by_id[str(net["id"])] = name or str(net["id"])
        vlan = net.get("vlan", net.get("vlanId"))
        if vlan is not None and name:
            by_vlan.setdefault(str(vlan), name)
    return by_id, by_vlan


def _port_native_network(
    p: dict[str, Any], by_id: dict[str, str], by_vlan: dict[str, str],
) -> str:
    network_id = p.get("nativeNetworkId")
    if network_id:
        return by_id.get(str(network_id), str(network_id))
    # Gateway LAN ports: the PVID is the untagged (native) VLAN.
    pvid = p.get("pvid")
    if p.get("deviceType") == "gateway" and pvid is not None and p.get("mode") != 0:
        return by_vlan.get(str(pvid), f"VLAN {pvid}")
    return ""


def _device_port_rows(data: Any, context: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """One row per switch/gateway port, mirroring the controller's port table."""
    items = data if isinstance(data, list) else []
    by_id, by_vlan = _network_lookups(context)
    rows = []
    for p in items:
        if not isinstance(p, dict):
            continue
        type_map = (
            _GATEWAY_PORT_TYPE_MAP if p.get("deviceType") == "gateway" else _SWITCH_PORT_TYPE_MAP
        )
        rows.append({
            "Device": _flatten(p.get("deviceName", "")),
            "Port": _flatten(p.get("port", "")),
            "Name": _flatten(p.get("name", p.get("portName", ""))),
            "Label": _flatten(p.get("tagName", "")),
            "Connection": _port_connection(p),
            "Type": _map_code(p.get("type", ""), type_map),
            "Operation": _port_operation(p),
            "Profile": _flatten(p.get("profileName", "")),
            "Native Network": _port_native_network(p, by_id, by_vlan),
            "Overrides": ", ".join(dict.fromkeys(d[0] for d in _port_overrides(p, context))),
        })
    return rows


def _device_rows(data: Any) -> list[dict[str, Any]]:
    items = data if isinstance(data, list) else []
    return [
        {
            "Name": _flatten(d.get("name", d.get("deviceName", ""))),
            "Type": _flatten(d.get("type", d.get("deviceType", ""))),
            "Model": _flatten(d.get("model", "")),
            "MAC Address": _flatten(d.get("mac", d.get("deviceMac", ""))),
            "IP Address": _flatten(d.get("ip", d.get("ipAddress", ""))),
            "Status": _flatten(d.get("status", "")),
            "Firmware": _flatten(d.get("firmwareVersion", d.get("version", ""))),
        }
        for d in items
        if isinstance(d, dict)
    ]


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

RESOURCES: list[ResourceDefinition] = [
    ResourceDefinition(
        name="devices",
        title="Devices",
        fetch_method="get_devices",
        row_formatter=_device_rows,
        sort_key="Name",
    ),
    ResourceDefinition(
        name="device_ports",
        title="Device Ports",
        fetch_method="get_device_ports",
        row_formatter=_device_port_rows,
        sort_key="Device",  # stable sort keeps each device's port order
        needs_context=True,
        detail_formatter=_device_port_details,
    ),
    ResourceDefinition(
        name="port_schedules",
        title="PoE & Port Schedules",
        fetch_method="get_port_schedules",
        row_formatter=_port_schedule_rows,
        sort_key="Name",
        needs_context=True,
    ),
    ResourceDefinition(
        name="uplinks",
        title="Uplinks & Stacks",
        fetch_method="get_uplinks",
        row_formatter=_uplink_rows,
        sort_key="Switch",
        needs_context=True,
        detail_formatter=_uplink_details,
    ),
    ResourceDefinition(
        name="switch_port_sheets",
        title="Switch Port Sheets",
        fetch_method="get_switch_port_sheets",
        row_formatter=_switch_port_sheet_rows,
        sort_key="Switch",
        needs_context=True,
        detail_formatter=_switch_port_sheet_details,
    ),
    ResourceDefinition(
        name="gateway_port_sheets",
        title="Gateway Port Sheets",
        fetch_method="get_gateway_port_sheets",
        row_formatter=_gateway_port_sheet_rows,
        sort_key="Gateway",
        needs_context=True,
        detail_formatter=_gateway_port_sheet_details,
    ),
    ResourceDefinition(
        name="ap_sheets",
        title="Access Point Sheets",
        fetch_method="get_ap_sheets",
        row_formatter=_ap_sheet_rows,
        sort_key="AP",
        needs_context=True,
        detail_formatter=_ap_sheet_details,
    ),
    ResourceDefinition(
        name="switch_security",
        title="Switch Security (802.1X, DHCP Snooping, ARP Detection, IP-MAC Binding)",
        fetch_method="get_switch_security",
        row_formatter=_switch_security_rows,
        sort_key="",
        needs_context=True,
        detail_formatter=_switch_security_details,
    ),
    ResourceDefinition(
        name="oui_vlans",
        title="OUI-Based VLANs",
        fetch_method="get_oui_vlans",
        row_formatter=_oui_vlan_rows,
        sort_key="Name",
        needs_context=True,
        detail_formatter=_oui_vlan_details,
    ),
    ResourceDefinition(
        name="switch_qos",
        title="Switch QoS",
        fetch_method="get_switch_qos",
        row_formatter=_switch_qos_rows,
        sort_key="",  # formatter keeps rule order (index)
        needs_context=True,
        detail_formatter=_switch_qos_details,
    ),
    ResourceDefinition(
        name="port_labels",
        title="Switch Port Labels",
        fetch_method="get_port_labels",
        row_formatter=_port_label_rows,
        sort_key="Label",
    ),
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
        detail_formatter=_switch_port_profile_details,
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
        needs_context=True,
        detail_formatter=_ssid_details,
    ),
    ResourceDefinition(
        name="radius_profiles",
        title="RADIUS Profiles",
        fetch_method="get_radius_profiles",
        row_formatter=_radius_profile_rows,
        sort_key="Name",
    ),
    ResourceDefinition(
        name="portals",
        title="Guest Portals",
        fetch_method="get_portals",
        row_formatter=_portal_rows,
        sort_key="Name",
        needs_context=True,
        detail_formatter=_portal_details,
    ),
    ResourceDefinition(
        name="time_range_profiles",
        title="Schedules (Time Range Profiles)",
        fetch_method="get_time_range_profiles",
        row_formatter=_time_range_rows,
        sort_key="Name",
    ),
    ResourceDefinition(
        name="rate_limit_profiles",
        title="Rate Limit Profiles",
        fetch_method="get_rate_limit_profiles",
        row_formatter=_rate_limit_profile_rows,
        sort_key="Name",
    ),
    ResourceDefinition(
        name="wireless_settings",
        title="Wireless Site Settings",
        fetch_method="get_wireless_settings",
        row_formatter=_wireless_settings_rows,
        sort_key="",  # keep the logical grouping
    ),
    ResourceDefinition(
        name="ap_radios",
        title="AP Radio Settings",
        fetch_method="get_ap_radios",
        row_formatter=_ap_radio_rows,
        sort_key="AP",  # stable sort keeps band order within each AP
    ),
    ResourceDefinition(
        name="wan_failover",
        title="WAN Failover & Load Balancing",
        fetch_method="get_wan_failover",
        row_formatter=_wan_failover_rows,
        sort_key="",
        needs_context=True,
        detail_formatter=_wan_failover_details,
    ),
    ResourceDefinition(
        name="dns_settings",
        title="DNS",
        fetch_method="get_dns_settings",
        row_formatter=_dns_settings_rows,
        sort_key="",
        needs_context=True,
        detail_formatter=_dns_settings_details,
    ),
    ResourceDefinition(
        name="time_settings",
        title="Time & NTP",
        fetch_method="get_time_settings",
        row_formatter=_time_settings_rows,
        sort_key="",
    ),
    ResourceDefinition(
        name="multicast_services",
        title="Multicast, Bonjour & UPnP",
        fetch_method="get_multicast_services",
        row_formatter=_multicast_services_rows,
        sort_key="",
        needs_context=True,
        detail_formatter=_multicast_services_details,
    ),
    ResourceDefinition(
        name="lags",
        title="Link Aggregation (LAGs)",
        fetch_method="get_lags",
        row_formatter=_lag_rows,
        sort_key="Device",  # stable sort keeps LAG order within each device
        detail_formatter=_lag_details,
    ),
    ResourceDefinition(
        name="switch_settings",
        title="Switch Settings",
        fetch_method="get_switch_settings",
        row_formatter=_switch_settings_rows,
        sort_key="Switch",
        needs_context=True,
        detail_formatter=_switch_settings_details,
    ),
    ResourceDefinition(
        name="dhcp_reservations",
        title="DHCP Reservations",
        fetch_method="get_dhcp_reservations",
        row_formatter=_dhcp_reservation_rows,
        sort_key="",  # formatter sorts by network, then IP
    ),
    ResourceDefinition(
        name="dhcp_scopes",
        title="DHCP Scopes",
        fetch_method="get_dhcp_scopes",
        row_formatter=_dhcp_scope_rows,
        sort_key="Network",
        needs_context=True,
        detail_formatter=_dhcp_scope_details,
    ),
    ResourceDefinition(
        name="dhcp_leases",
        title="DHCP Leases",
        fetch_method="get_dhcp_leases",
        row_formatter=_dhcp_lease_rows,
        sort_key="",  # formatter sorts by network, then IP
    ),
    ResourceDefinition(
        name="port_forwarding",
        title="Port Forwarding",
        fetch_method="get_port_forwarding",
        row_formatter=_port_forwarding_rows,
        sort_key="Name",
        needs_context=True,
    ),
    ResourceDefinition(
        name="one_to_one_nat",
        title="One-to-One NAT",
        fetch_method="get_one_to_one_nat",
        row_formatter=_one_to_one_nat_rows,
        sort_key="Name",
        needs_context=True,
    ),
    ResourceDefinition(
        name="alg",
        title="ALG",
        fetch_method="get_alg_settings",
        row_formatter=_alg_rows,
        sort_key="",  # keep the logical setting order
    ),
    ResourceDefinition(
        name="static_routes",
        title="Static Routes",
        fetch_method="get_static_routes",
        row_formatter=_static_route_rows,
        sort_key="Name",
        needs_context=True,
    ),
    ResourceDefinition(
        name="policy_routes",
        title="Policy Routes",
        fetch_method="get_policy_routes",
        row_formatter=_policy_route_rows,
        sort_key="",  # formatter keeps evaluation order (index)
        needs_context=True,
    ),
    ResourceDefinition(
        name="site_to_site_vpns",
        title="Site-to-Site VPNs",
        fetch_method="get_site_to_site_vpns",
        row_formatter=_site_to_site_vpn_rows,
        sort_key="Name",
        needs_context=True,
        detail_formatter=_site_to_site_vpn_details,
    ),
    ResourceDefinition(
        name="remote_access_vpns",
        title="Remote-Access VPNs",
        fetch_method="get_remote_access_vpns",
        row_formatter=_remote_access_vpn_rows,
        sort_key="Name",
        needs_context=True,
        detail_formatter=_remote_access_vpn_details,
    ),
    ResourceDefinition(
        name="wireguard",
        title="WireGuard VPN",
        fetch_method="get_wireguard",
        row_formatter=_wireguard_rows,
        sort_key="Name",
        detail_formatter=_wireguard_details,
    ),
    ResourceDefinition(
        name="vpn_users",
        title="VPN Users",
        fetch_method="get_vpn_users",
        row_formatter=_vpn_user_rows,
        sort_key="Username",
    ),
    ResourceDefinition(
        name="ssl_vpn",
        title="SSL VPN Server",
        fetch_method="get_ssl_vpn",
        row_formatter=_ssl_vpn_rows,
        sort_key="",  # keep the logical setting order
        needs_context=True,
        detail_formatter=_ssl_vpn_details,
    ),
    ResourceDefinition(
        name="eogre_tunnel",
        title="EoGRE Tunnel",
        fetch_method="get_eogre_tunnel",
        row_formatter=_eogre_rows,
        sort_key="",
    ),
    ResourceDefinition(
        name="ipsec_failover",
        title="IPsec Failover",
        fetch_method="get_ipsec_failover",
        row_formatter=_ipsec_failover_rows,
        sort_key="Name",
    ),
]

#: Fast lookup by resource name.
REGISTRY: dict[str, ResourceDefinition] = {r.name: r for r in RESOURCES}
