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
    detail = _link_detail(status) if state == "Connected" else ""
    return f"{state} ({detail})" if detail else state


def _port_operation(p: dict[str, Any]) -> str:
    if p.get("deviceType") == "gateway":
        if p.get("mirrorEnable"):
            return "Mirroring"
        return _map_code(p.get("mode", ""), _GATEWAY_PORT_MODE_MAP)
    operation = p.get("operation", "")
    return str(operation).title() if isinstance(operation, str) else _flatten(operation)


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
