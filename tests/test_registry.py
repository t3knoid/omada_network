"""Tests for the resource registry and generate_from_yaml service function."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from omada.registry import REGISTRY, RESOURCES, ResourceDefinition
from omada.service import generate_from_yaml


class TestRegistry:
    def test_all_thirty_six_resources_defined(self) -> None:
        names = {r.name for r in RESOURCES}
        assert names == {
            "acl_rules",
            "devices",
            "device_ports",
            "ip_groups",
            "port_groups",
            "networks",
            "vlans",
            "switch_port_profiles",
            "gateway_settings",
            "ssids",
            "dhcp_reservations",
            "port_forwarding",
            "one_to_one_nat",
            "alg",
            "static_routes",
            "policy_routes",
            "site_to_site_vpns",
            "remote_access_vpns",
            "wireguard",
            "vpn_users",
            "ssl_vpn",
            "eogre_tunnel",
            "ipsec_failover",
            "dhcp_scopes",
            "dhcp_leases",
            "radius_profiles",
            "portals",
            "time_range_profiles",
            "rate_limit_profiles",
            "wireless_settings",
            "ap_radios",
            "wan_failover",
            "dns_settings",
            "time_settings",
            "multicast_services",
            "lags",
        }

    def test_registry_lookup_matches_resources(self) -> None:
        assert len(REGISTRY) == len(RESOURCES)
        for defn in RESOURCES:
            assert REGISTRY[defn.name] is defn

    def test_all_definitions_are_resource_definition(self) -> None:
        for defn in RESOURCES:
            assert isinstance(defn, ResourceDefinition)

    def test_all_row_formatters_callable(self) -> None:
        for defn in RESOURCES:
            assert callable(defn.row_formatter), f"{defn.name} has non-callable row_formatter"

    def test_row_formatters_return_list_for_empty_input(self) -> None:
        for defn in RESOURCES:
            result = defn.row_formatter([])
            assert isinstance(result, list), f"{defn.name} formatter did not return a list"

    def test_row_formatters_return_list_for_dict_input(self) -> None:
        """gateway_settings receives a dict; all formatters must handle dicts."""
        for defn in RESOURCES:
            result = defn.row_formatter({})
            assert isinstance(result, list)

    def test_sort_key_is_string(self) -> None:
        for defn in RESOURCES:
            assert isinstance(defn.sort_key, str)


class TestRowFormatters:
    def test_device_rows(self) -> None:
        from omada.registry import _device_rows

        rows = _device_rows([
            {
                "name": "Office AP",
                "type": "ap",
                "model": "EAP650",
                "mac": "AA-BB-CC-DD-EE-FF",
                "ip": "192.168.1.20",
                "status": "Connected",
                "firmwareVersion": "1.2.3",
            },
        ])

        assert rows[0]["Name"] == "Office AP"
        assert rows[0]["Type"] == "ap"
        assert rows[0]["Model"] == "EAP650"
        assert rows[0]["MAC Address"] == "AA-BB-CC-DD-EE-FF"
        assert rows[0]["IP Address"] == "192.168.1.20"
        assert rows[0]["Status"] == "Connected"
        assert rows[0]["Firmware"] == "1.2.3"
        assert "Ports" not in rows[0]

    def test_device_port_rows_switch(self) -> None:
        from omada.registry import _device_port_rows

        context = {"networks": [{"id": "net-iot", "name": "IoT Devices", "vlan": 40}]}
        rows = _device_port_rows([
            {
                "deviceName": "Main Switch", "deviceType": "switch", "port": 8,
                "portName": "Synology LAN 1", "tagName": "NAS", "connectedStatus": 0,
                "portStatus": {"linkStatus": 1, "linkSpeed": 3, "duplex": 2},
                "type": 1, "operation": "SWITCHING", "profileName": "All",
                "nativeNetworkId": "net-iot",
            },
            {
                "deviceName": "Main Switch", "deviceType": "switch", "port": 25,
                "name": "Port25", "connectedStatus": 1, "type": 3,
                "operation": "AGGREGATING", "nativeNetworkId": "unknown-id",
            },
            {
                "deviceName": "Main Switch", "deviceType": "switch", "port": 3,
                "name": "Port3", "disable": True, "connectedStatus": 2,
            },
        ], context)
        assert rows[0] == {
            "Device": "Main Switch", "Port": "8", "Name": "Synology LAN 1",
            "Label": "NAS", "Connection": "Connected (1000M Full Duplex)",
            "Type": "Copper", "Operation": "Switching", "Profile": "All",
            "Native Network": "IoT Devices",
        }
        assert rows[1]["Connection"] == "Disconnected"
        assert rows[1]["Type"] == "SFP"
        assert rows[1]["Operation"] == "Aggregating"
        assert rows[1]["Native Network"] == "unknown-id"
        assert rows[2]["Connection"] == "Disabled"

    def test_device_port_rows_gateway_er605(self) -> None:
        """ER605: port 1 WAN only, ports 2-4 WAN/LAN, port 5 LAN only."""
        from omada.registry import _device_port_rows

        context = {"networks": [{"id": "n1", "name": "Default", "vlan": 1}]}
        gw = {"deviceName": "GW", "deviceType": "gateway", "status": 1}
        rows = _device_port_rows([
            {**gw, "port": 1, "name": "WAN", "type": 0, "mode": 0,
             "portStatus": {"linkStatus": 1, "linkSpeed": 3, "duplex": 2}},
            {**gw, "port": 2, "name": "WAN/LAN1", "type": 1, "mode": 1, "pvid": 1,
             "portStatus": {"linkStatus": 0}},
            {**gw, "port": 3, "name": "WAN/LAN2", "type": 1, "mode": 0, "pvid": 1},
            {**gw, "port": 4, "name": "WAN/LAN3", "type": 1, "mode": 1, "pvid": 99,
             "status": 0},
            {**gw, "port": 5, "name": "LAN", "type": 2, "mode": 1, "pvid": 1,
             "mirrorEnable": True},
        ], context)
        assert [r["Type"] for r in rows] == ["WAN", "WAN/LAN", "WAN/LAN", "WAN/LAN", "LAN"]
        assert [r["Operation"] for r in rows] == ["WAN", "LAN", "WAN", "LAN", "Mirroring"]
        assert [r["Connection"] for r in rows] == [
            "Connected (1000M Full Duplex)", "Disconnected", "", "Disabled", "",
        ]
        # Native network only for LAN-mode ports, resolved from the PVID
        assert [r["Native Network"] for r in rows] == ["", "Default", "", "VLAN 99", "Default"]
        assert all(r["Label"] == "" and r["Profile"] == "" for r in rows)

    def test_acl_rule_rows(self) -> None:
        from omada.registry import _acl_rule_rows
        rows = _acl_rule_rows([{"description": "rule1", "policy": 1, "status": True}])
        assert rows[0]["Description"] == "rule1"
        assert rows[0]["Policy"] == "Permit"
        assert rows[0]["Status"] == "Enabled"

    def test_acl_rule_rows_resolves_names(self) -> None:
        from omada.registry import _acl_rule_rows
        context = {
            "ip_groups": [{"groupId": "ip1", "name": "HDHomeRun"}],
            "port_groups": [{"groupId": "pg1", "name": "Minecraft"}],
            "networks": [{"id": "net1", "name": "IoT Devices"}],
        }
        rules = [
            {
                "description": "Allow HDHomeRun",
                "policy": 1,
                "status": True,
                "sourceType": 1,
                "sourceIds": ["ip1"],
                "destinationType": 1,
                "destinationIds": ["ip1"],
            },
            {
                "description": "Allow Net to Port",
                "policy": 1,
                "status": True,
                "sourceType": 0,
                "sourceIds": ["net1"],
                "destinationType": 2,
                "destinationIds": ["pg1"],
            },
        ]
        rows = _acl_rule_rows(rules, context)
        assert rows[0]["Source"] == "HDHomeRun"
        assert rows[0]["Destination"] == "HDHomeRun"
        assert rows[1]["Source"] == "IoT Devices"
        assert rows[1]["Destination"] == "Minecraft"

    def test_acl_rule_rows_no_context_shows_raw_ids(self) -> None:
        from omada.registry import _acl_rule_rows
        rows = _acl_rule_rows([{"description": "r", "sourceIds": ["abc123"], "destinationIds": []}])
        assert rows[0]["Source"] == "abc123"
        assert rows[0]["Destination"] == ""

    def test_ip_group_rows(self) -> None:
        from omada.registry import _ip_group_rows
        rows = _ip_group_rows([{"name": "g1", "ipList": [{"ip": "10.0.0.0", "mask": "8"}]}])
        assert rows[0]["Name"] == "g1"
        assert "10.0.0.0/8" in rows[0]["IPs / Subnets"]

    def test_gateway_rows_dict_input(self) -> None:
        from omada.registry import _gateway_rows
        rows = _gateway_rows({"wanMode": "DHCP", "wan1Ip": "1.2.3.4"})
        assert rows[0]["WAN Mode"] == "DHCP"

    def test_gateway_rows_list_input(self) -> None:
        from omada.registry import _gateway_rows
        rows = _gateway_rows([{"wanMode": "PPPoE"}])
        assert rows[0]["WAN Mode"] == "PPPoE"

    def test_ssid_rows(self) -> None:
        from omada.registry import _ssid_rows
        rows = _ssid_rows([{"name": "HomeNet", "wlanName": "Main", "band": 3, "security": 3, "broadcast": False}])
        assert rows[0]["SSID"] == "HomeNet"
        assert rows[0]["Band"] == "2.4 GHz / 5 GHz"
        # security 3 is WPA-Personal per the spec (the old map mislabelled it "WPA2")
        assert rows[0]["Security"] == "WPA-Personal"
        assert rows[0]["Broadcast"] == "No"

    def test_dhcp_reservation_rows(self) -> None:
        from omada.registry import _dhcp_reservation_rows
        rows = _dhcp_reservation_rows(
            [{"netName": "IoT", "ip": "192.168.1.100", "mac": "AA-BB-CC-DD-EE-FF", "name": "laptop", "status": True, "serverName": "Gateway"}]
        )
        assert rows[0]["IP Address"] == "192.168.1.100"
        assert rows[0]["Name"] == "laptop"
        assert rows[0]["Network"] == "IoT"
        assert rows[0]["Status"] == "Enabled"

    def test_port_forwarding_rows(self) -> None:
        from omada.registry import _port_forwarding_rows
        context = {"gateway_settings": {"wanPortsConfig": [
            {"portId": "1_abc", "portName": "WAN"},
        ]}}
        rows = _port_forwarding_rows([
            {"name": "NAS HTTPS", "status": True, "from": 0,
             "interfaceWanPortId": ["1_abc"], "externalPort": "443",
             "forwardIp": "192.168.2.50", "forwardPort": "5001", "protocol": 1, "dMZ": False},
            {"name": "Game", "status": False, "from": 1, "limitedAddresses": ["8.8.8.8"],
             "interfaceWanPortId": ["2_def"], "virtualWanId": ["vw1"],
             "wanIps": [{"wanId": "1_abc", "ip": "203.0.113.5"}],
             "externalPort": "3074", "forwardIp": "192.168.2.60", "forwardPort": "3074",
             "protocol": 0, "dMZ": True},
        ], context)
        assert rows[0] == {
            "Name": "NAS HTTPS", "Status": "Enabled", "Interface": "WAN",
            "Source IP": "Any", "External Port": "443", "Forward IP": "192.168.2.50",
            "Forward Port": "5001", "Protocol": "TCP", "DMZ": "Disabled",
        }
        assert rows[1]["Status"] == "Disabled"
        assert rows[1]["Source IP"] == "8.8.8.8"
        assert rows[1]["Interface"] == "2_def; Virtual WAN vw1; WAN IP 203.0.113.5 (WAN)"
        assert rows[1]["Protocol"] == "All"
        assert rows[1]["DMZ"] == "Enabled"

    def test_one_to_one_nat_rows(self) -> None:
        from omada.registry import _one_to_one_nat_rows
        context = {"gateway_settings": {"wanPortsConfig": [{"portId": "1_abc", "portName": "WAN"}]}}
        rows = _one_to_one_nat_rows([
            {"name": "Web", "status": True, "interfaceIds": ["1_abc"],
             "internalIp": "192.168.2.10", "externalIp": "203.0.113.10",
             "dmz": False, "description": "Public web server"},
        ], context)
        assert rows == [{
            "Name": "Web", "Status": "Enabled", "Interface": "WAN",
            "Internal IP": "192.168.2.10", "External IP": "203.0.113.10",
            "DMZ": "Disabled", "Description": "Public web server",
        }]

    def test_alg_rows(self) -> None:
        from omada.registry import _alg_rows
        rows = _alg_rows({
            "ftp": True, "ftpPorts": [21, 2121], "h323": False, "pptp": True, "ipSec": True,
            "sip": True, "sipTcp": True, "sipUdp": False, "sipPorts": [5060, 5061],
            "sipDirectSignaling": True, "sipDirectMedia": False, "sipTimeout": True,
            "sipSignalingTimeout": 3600, "sipMediaTimeout": 120,
            "supportSipAlgConfig": True,
        })
        values = {r["Setting"]: r["Value"] for r in rows}
        assert values == {
            "FTP ALG": "Enabled", "FTP Ports": "21, 2121", "H.323 ALG": "Disabled",
            "PPTP ALG": "Enabled", "IPSec ALG": "Enabled", "SIP ALG": "Enabled",
            "SIP over TCP": "Enabled", "SIP over UDP": "Disabled",
            "SIP Direct Signaling": "Enabled", "SIP Direct Media": "Disabled",
            "SIP Timeout": "Enabled", "SIP Ports": "5060, 5061",
            "SIP Signaling Timeout": "3600 s", "SIP Media Timeout": "120 s",
        }

    def test_alg_rows_sip_disabled_hides_sip_options(self) -> None:
        from omada.registry import _alg_rows
        rows = _alg_rows({"ftp": False, "ftpPorts": [21], "sip": False, "sipTcp": True})
        assert rows == [
            {"Setting": "FTP ALG", "Value": "Disabled"},
            {"Setting": "SIP ALG", "Value": "Disabled"},
        ]

    def test_static_route_rows(self) -> None:
        from omada.registry import _static_route_rows
        context = {
            "gateway_settings": {"wanPortsConfig": [{"portId": "1_abc", "portName": "WAN"}]},
            "networks": [{"id": "net-lab", "name": "Lab"}],
        }
        rows = _static_route_rows([
            {"routeSource": "gateway", "name": "Via ISP", "status": True,
             "destinations": ["10.10.0.0/16", "10.20.0.0/16"], "routeType": 0,
             "nextHopIp": "203.0.113.1", "metric": 2},
            {"routeSource": "gateway", "name": "Out WAN", "status": True,
             "destinations": ["198.51.100.0/24"], "routeType": 1,
             "interfaceType": 0, "interfaceId": "1_abc", "nextHopIp": "203.0.113.254",
             "metric": 0},
            {"routeSource": "gateway", "name": "To Lab", "status": False,
             "destinations": ["172.16.0.0/12"], "routeType": 1,
             "interfaceType": 1, "interfaceId": "net-lab", "metric": 5},
            {"routeSource": "switch", "deviceName": "Core", "description": "Mgmt",
             "status": True, "destinations": ["192.168.99.0/24"],
             "nextHopIp": "192.168.2.1", "distance": 10},
        ], context)
        assert rows[0] == {
            "Name": "Via ISP", "Status": "Enabled", "Device": "Gateway",
            "Destinations": "10.10.0.0/16, 10.20.0.0/16", "Route Type": "Next Hop",
            "Next Hop": "203.0.113.1", "Interface": "", "Metric": "2", "Distance": "",
        }
        assert rows[1]["Route Type"] == "Interface"
        assert rows[1]["Interface"] == "WAN: WAN"
        assert rows[1]["Next Hop"] == "203.0.113.254"
        assert rows[1]["Metric"] == "0"
        assert rows[2]["Interface"] == "LAN: Lab"
        assert rows[2]["Status"] == "Disabled"
        assert rows[3] == {
            "Name": "Mgmt", "Status": "Enabled", "Device": "Core",
            "Destinations": "192.168.99.0/24", "Route Type": "Next Hop",
            "Next Hop": "192.168.2.1", "Interface": "", "Metric": "", "Distance": "10",
        }

    def test_static_route_rows_prefers_fetched_interface_name(self) -> None:
        from omada.registry import _static_route_rows
        rows = _static_route_rows([
            {"routeSource": "gateway", "name": "VPN", "routeType": 1, "interfaceType": 2,
             "interfaceId": "vpn-1", "interfaceName": "Office L2TP"},
        ])
        assert rows[0]["Interface"] == "L2TP: Office L2TP"

    def test_policy_route_rows(self) -> None:
        from omada.registry import _policy_route_rows
        context = {
            "gateway_settings": {"wanPortsConfig": [
                {"portId": "1_abc", "portName": "WAN"},
                {"portId": "2_def", "portName": "WAN/LAN1"},
            ]},
            "networks": [{"id": "net-iot", "name": "IoT"}],
            "ip_groups": [{"groupId": "grp-1", "name": "Streaming"}],
        }
        rows = _policy_route_rows([
            {"index": 10, "name": "Second", "status": False, "protocols": [256],
             "interfaceType": 4, "wanPortIds": ["1_abc", "2_def"], "vpnIds": ["vpn-9"],
             "backupInterface": True, "sourceType": 0, "sourceIds": ["net-iot"],
             "destinationType": 1, "destinationIds": ["grp-1"]},
            {"index": 2, "name": "First", "status": True, "protocols": [6, 17],
             "interfaceType": 0, "interfaceId": "2_def", "backupInterface": False,
             "sourceType": 0, "sourceIds": ["net-iot"], "destinationType": 0,
             "destinationIds": []},
        ], context)
        # Evaluation order by numeric index, not alphabetical
        assert [r["Name"] for r in rows] == ["First", "Second"]
        assert rows[0] == {
            "Index": "2", "Name": "First", "Status": "Enabled", "Protocols": "TCP, UDP",
            "Source": "IoT", "Source Type": "Network", "Destination": "",
            "Destination Type": "Network", "WAN Binding": "WAN: WAN/LAN1",
            "Backup Interface": "No",
        }
        assert rows[1]["Protocols"] == "All"
        assert rows[1]["Destination"] == "Streaming"
        assert rows[1]["Destination Type"] == "IP Group"
        assert rows[1]["WAN Binding"] == "WAN: WAN, WAN/LAN1; VPN: vpn-9"
        assert rows[1]["Backup Interface"] == "Yes"

    _VPN_CONTEXT = {
        "gateway_settings": {"wanPortsConfig": [{"portId": "1_abc", "portName": "WAN"}]},
        "networks": [{"id": "net-lan", "name": "LAN"}],
        "vpn_users": [
            {"username": "bob", "servers": ["srv-l2tp"]},
            {"username": "alice", "servers": ["srv-l2tp", "srv-ovpn"]},
        ],
    }
    _ADVANCED = {
        "keyExchangeVersion": 1, "phase1Proposal1": 2, "phase1Proposal2": 4,
        "phase1Proposal3": 3, "exchangeMode": 0, "negotiationMode": 0,
        "localIdType": 0, "remoteIdType": 1, "remoteName": "hq.example",
        "saLifetime": 28800, "dpd": True, "dpdInterval": 10, "encapsulationMode": 0,
        "phase2Proposal1": 1, "phase2Proposal2": 2, "phase2Proposal3": 4,
        "pfs": 14, "saLifetime2": 3600,
    }

    def test_site_to_site_vpn_rows_and_details(self) -> None:
        from omada.registry import _site_to_site_vpn_details, _site_to_site_vpn_rows
        vpns = [
            {"name": "HQ", "status": True, "siteVpnType": 1, "remoteIp": "203.0.113.9",
             "remoteSubnet": [{"ip": "10.50.0.0", "mask": 16}], "networkType": 0,
             "networkList": ["net-lan"], "wan": ["1_abc"], "preSharedKey": "<redacted>",
             "advancedSetting": self._ADVANCED},
            {"name": "Branch", "status": False, "siteVpnType": 0, "remoteSite": "Freehold",
             "networkType": 1, "customNetwork": [{"ip": "192.168.5.0", "mask": 24}]},
        ]
        rows = _site_to_site_vpn_rows(vpns, self._VPN_CONTEXT)
        assert rows[0] == {
            "Name": "HQ", "Status": "Enabled", "Type": "Manual IPsec",
            "Remote Peer": "203.0.113.9", "Remote Subnets": "10.50.0.0/16",
            "Local Networks": "LAN", "WAN": "WAN",
            "Encryption": "IKEv2 AES256/SHA256/DH14, ESP AES256/SHA256, PFS DH14",
            "Authentication": "Pre-shared Key (Configured)",
        }
        assert rows[1]["Type"] == "Auto IPsec"
        assert rows[1]["Remote Peer"] == "Freehold"
        assert rows[1]["Local Networks"] == "192.168.5.0/24"
        assert rows[1]["Authentication"] == "Automatic (controller-managed)"

        details = dict(_site_to_site_vpn_details(vpns, self._VPN_CONTEXT))
        hq = {(r["Category"], r["Setting"]): r["Value"] for r in details["HQ"]}
        assert hq[("Phase 1 (IKE)", "Key Exchange Version")] == "IKEv2"
        assert hq[("Phase 1 (IKE)", "DH Group")] == "DH14"
        assert hq[("Phase 1 (IKE)", "Negotiation Mode")] == "Initiator Mode"
        assert hq[("Phase 1 (IKE)", "SA Lifetime")] == "28800 s"
        assert hq[("Phase 1 (IKE)", "Dead Peer Detection")] == "Enabled (10 s)"
        assert hq[("Phase 2 (IPsec)", "Protocol")] == "ESP"
        assert hq[("Phase 2 (IPsec)", "PFS")] == "DH14"
        assert hq[("Authentication", "Remote ID Type")] == "Name"
        assert hq[("Authentication", "Remote ID")] == "hq.example"

    def test_remote_access_vpn_rows(self) -> None:
        from omada.registry import _remote_access_vpn_rows
        rows = _remote_access_vpn_rows([
            {"id": "srv-l2tp", "vpnRole": "server", "name": "L2TP", "status": True,
             "clientVpnType": 0, "encryption": 0, "preSharedKey": "<redacted>",
             "authMode": 0, "ipPoolStart": "10.9.0.10", "ipPoolEnd": "10.9.0.50",
             "wan": ["1_abc"], "networkType": 0, "networkList": ["net-lan"]},
            {"id": "srv-ovpn", "vpnRole": "server", "name": "OpenVPN", "status": True,
             "clientVpnType": 3, "openVpnMode": 1, "serviceType": 0, "servicePort": 1194,
             "ipPool": "10.8.0.0/24"},
            {"id": "cli-1", "vpnRole": "client", "name": "To Office", "status": False,
             "clientVpnType": 2, "remoteIp": "198.51.100.7",
             "remoteSubnet": [{"ip": "172.16.0.0", "mask": 12}], "preSharedKey": "",
             "advancedSetting": self._ADVANCED},
            {"id": "cli-2", "vpnRole": "client", "name": "PPTP out", "clientVpnType": 1,
             "encryption": 1, "remoteIp": "pptp.example", "clientUserName": "carol",
             "clientPassword": "<redacted>"},
        ], self._VPN_CONTEXT)
        l2tp, ovpn, ipsec, pptp = rows
        assert l2tp["Role"] == "Server"
        assert l2tp["Protocol"] == "L2TP"
        assert l2tp["Client IP Pool"] == "10.9.0.10 – 10.9.0.50"
        assert l2tp["WAN"] == "WAN"
        assert l2tp["Local Networks"] == "LAN"
        assert l2tp["Encryption"] == "L2TP over IPsec"
        assert l2tp["Authentication"] == "Local users; Users: alice, bob; Pre-shared Key Configured"
        assert ovpn["Service"] == "UDP 1194"
        assert ovpn["Encryption"] == "TLS"
        assert ovpn["Client IP Pool"] == "10.8.0.0/24"
        assert ovpn["Authentication"] == "Certificate + Account; Users: alice"
        assert ipsec["Role"] == "Client"
        assert ipsec["Remote Peer"] == "198.51.100.7"
        assert ipsec["Remote Subnets"] == "172.16.0.0/12"
        assert ipsec["Encryption"].startswith("IKEv2 AES256/SHA256/DH14")
        assert ipsec["Authentication"] == "Pre-shared Key Not set"
        assert pptp["Encryption"] == "Unencrypted"
        assert pptp["Authentication"] == "User carol; Password Configured"

    def test_remote_access_vpn_details_title_includes_role(self) -> None:
        from omada.registry import _remote_access_vpn_details
        details = _remote_access_vpn_details([
            {"name": "Office", "vpnRole": "server", "clientVpnType": 3, "tunnelMode": 0,
             "primaryDns": "1.1.1.1", "secondaryDns": "8.8.8.8"},
            {"name": "Office", "vpnRole": "client", "clientVpnType": 3, "workingMode": 1,
             "vpnConfiguration": {"id": "c1", "fileName": "office.ovpn"}, "openVpnMode": 0},
        ])
        titles = [t for t, _ in details]
        assert titles == ["Office (Server)", "Office (Client)"]
        server = {r["Setting"]: r["Value"] for r in details[0][1]}
        client = {r["Setting"]: r["Value"] for r in details[1][1]}
        assert server["Tunnel Mode"] == "Split"
        assert server["DNS"] == "1.1.1.1, 8.8.8.8"
        assert client["Working Mode"] == "Routing"
        assert client["References"] == "Certificate; Config file office.ovpn"

    def test_wireguard_rows_and_peer_details(self) -> None:
        from omada.registry import _wireguard_details, _wireguard_rows
        data = [{
            "name": "wg0", "status": True, "listenPort": 51820, "localIp": "10.7.0.1/24",
            "mtu": 1420, "publicKey": "PUB=", "privateKey": "<redacted>",
            "peers": [{"name": "Phone", "status": True, "endPoint": "vpn.example",
                       "endPointPort": 51820, "allowAddress": ["10.7.0.2/32"],
                       "keepAlive": 25, "publicKey": "PEER=", "presharedKey": "",
                       "comment": "Alice"}],
        }]
        assert _wireguard_rows(data) == [{
            "Name": "wg0", "Status": "Enabled", "Listen Port": "51820",
            "Local IP": "10.7.0.1/24", "MTU": "1420", "Public Key": "PUB=",
            "Private Key": "Configured", "Peers": "1",
        }]
        [(title, peers)] = _wireguard_details(data)
        assert title == "wg0 peers"
        assert peers == [{
            "Peer": "Phone", "Status": "Enabled", "Endpoint": "vpn.example:51820",
            "Allowed Addresses": "10.7.0.2/32", "Keepalive": "25 s",
            "Public Key": "PEER=", "Preshared Key": "Not set", "Comment": "Alice",
        }]

    def test_vpn_user_rows(self) -> None:
        from omada.registry import _vpn_user_rows
        rows = _vpn_user_rows([
            {"username": "alice", "password": "<redacted>", "protocol": 1, "clientMode": 0,
             "serverNames": "OpenVPN", "maxConnections": 2,
             "userRemoteSubnets": [{"ip": "192.168.50.0", "mask": 24}], "localIp": ""},
        ])
        assert rows == [{
            "Username": "alice", "Protocol": "OpenVPN", "Client Mode": "Client-to-Site",
            "Servers": "OpenVPN", "Max Connections": "2", "Remote Subnets": "192.168.50.0/24",
            "Local IP": "", "Password": "Configured",
        }]

    _SSL_VPN = {
        "setting": {
            "status": True, "wanPort": "1_abc", "wanIp": "203.0.113.2", "servicePort": 443,
            "ipPoolStart": "10.6.0.10", "ipPoolEnd": "10.6.0.99",
            "primaryDns": "1.1.1.1", "secondaryDns": "", "totalTraffic": False,
            "authType": 1,
            "radiusSetting": {"radiusProfile": "r1", "authType": 1, "repeatTime": 3,
                              "overTime": 5, "nasIp": "10.0.0.1", "defaultGroup": "g1"},
            "nameLockSetting": {"status": True, "times": 5, "duration": 30},
            "ipLockSetting": {"status": False},
            "exitAtIdle": True, "exitTime": 600,
        },
        "radiusServers": [{"id": "r1", "name": "Corp RADIUS"}],
        "userGroups": [{"id": "g1", "name": "Staff", "userList": ["alice", "bob"],
                        "resourceGroupList": [{"id": "rg1", "name": "Servers"}],
                        "radiusAttribute": "staff"}],
        "users": [{"name": "alice", "groupName": "Staff", "status": True,
                   "validity": "12/31/2027", "concurrentNumber": 2, "password": "<redacted>"}],
        "resources": [
            {"name": "NAS", "type": 0, "ip": "192.168.2.50", "mask": "32", "protocol": 1,
             "dstPortStart": 5000, "dstPortEnd": 5001,
             "resourceGroupList": [{"id": "rg1", "name": "Servers"}]},
            {"name": "Wiki", "type": 1, "domain": "wiki.example", "protocol": 4,
             "icmpType": 8, "icmpCode": 0},
        ],
        "resourceGroups": [{"name": "Servers", "resourcesList": [{"id": "x", "name": "NAS"}]}],
    }

    def test_ssl_vpn_rows(self) -> None:
        from omada.registry import _ssl_vpn_rows
        context = {"gateway_settings": {"wanPortsConfig": [{"portId": "1_abc", "portName": "WAN"}]}}
        values = {r["Setting"]: r["Value"] for r in _ssl_vpn_rows(self._SSL_VPN, context)}
        assert values == {
            "Status": "Enabled", "WAN": "WAN", "WAN IP": "203.0.113.2", "Service Port": "443",
            "Client IP Pool": "10.6.0.10 – 10.6.0.99", "DNS": "1.1.1.1",
            "Tunnel Mode": "Split", "Authentication": "RADIUS",
            "RADIUS Profile": "Corp RADIUS", "RADIUS Auth Protocol": "CHAP",
            "RADIUS Retries": "3", "RADIUS Timeout": "5 s", "NAS IP": "10.0.0.1",
            "Default User Group": "Staff",
            "Username Lockout": "Enabled (5 failures, 30 min)", "IP Lockout": "Disabled",
            "Idle Logout": "Enabled (600 s)",
        }
        assert _ssl_vpn_rows({}) == []
        assert _ssl_vpn_rows({"setting": {}}) == []

    def test_ssl_vpn_details(self) -> None:
        from omada.registry import _ssl_vpn_details
        sections = dict(_ssl_vpn_details(self._SSL_VPN))
        assert list(sections) == ["User Groups", "Users", "Resources", "Resource Groups"]
        assert sections["User Groups"] == [{
            "Name": "Staff", "Users": "alice, bob", "Resource Groups": "Servers",
            "RADIUS Attribute": "staff", "LDAP Attribute": "",
        }]
        assert sections["Users"] == [{
            "Name": "alice", "Group": "Staff", "Status": "Enabled", "Validity": "12/31/2027",
            "Concurrent Logins": "2", "Password": "Configured",
        }]
        nas, wiki = sections["Resources"]
        assert nas["Destination"] == "192.168.2.50/32"
        assert nas["Protocol"] == "TCP"
        assert nas["Ports / ICMP"] == "Destination 5000–5001"
        assert nas["Resource Groups"] == "Servers"
        assert wiki["Type"] == "Domain"
        assert wiki["Destination"] == "wiki.example"
        assert wiki["Ports / ICMP"] == "Type 8, Code 0"
        assert sections["Resource Groups"] == [{"Name": "Servers", "Resources": "NAS"}]

    def test_eogre_rows(self) -> None:
        from omada.registry import _eogre_rows
        rows = _eogre_rows({"greEnable": True, "tunnelMtu": 1476, "interval": 30,
                            "maxCount": 5, "primaryAddress": "10.1.1.1", "secondaryAddress": ""})
        assert rows == [
            {"Setting": "EoGRE Tunnel", "Value": "Enabled"},
            {"Setting": "MTU", "Value": "1476"},
            {"Setting": "Keepalive Interval", "Value": "30 s"},
            {"Setting": "Max Missed Keepalives", "Value": "5"},
            {"Setting": "Primary Gateway", "Value": "10.1.1.1"},
        ]

    def test_ipsec_failover_rows(self) -> None:
        from omada.registry import _ipsec_failover_rows
        rows = _ipsec_failover_rows([
            {"name": "HQ", "primary": {"id": "a", "name": "HQ-WAN1", "status": 0},
             "candidates": [{"id": "b", "name": "HQ-WAN2", "status": 1},
                            {"id": "c", "name": "HQ-LTE", "status": 2}],
             "failBack": True, "failBackTime": 60},
            {"name": "Branch", "primary": {"name": "BR-1"}, "candidates": [], "failBack": False},
        ])
        assert rows[0] == {
            "Name": "HQ", "Primary Tunnel": "HQ-WAN1 (Active)",
            "Candidates": "HQ-WAN2 (Standby) → HQ-LTE (Disconnected)",
            "Failback": "Enabled (after 60)",
        }
        assert rows[1]["Primary Tunnel"] == "BR-1"
        assert rows[1]["Failback"] == "Disabled"

    _DHCP_CONTEXT = {"devices": [
        {"name": "Astoria Gateway", "mac": "6C-5A-B0-28-3C-77"},
        {"name": "Core Switch", "mac": "AA-BB-CC-00-11-22"},
    ]}

    def test_dhcp_scope_rows(self) -> None:
        from omada.registry import _dhcp_scope_rows
        rows = _dhcp_scope_rows([
            {"name": "Client", "vlan": 10, "gatewaySubnet": "192.168.10.1/24",
             "deviceType": 1, "deviceMac": "6C-5A-B0-28-3C-77", "domain": "home.arpa",
             "dhcpL2RelayEnable": True,
             "dhcpSettings": {"enable": True, "dhcpns": "manual", "priDns": "192.168.20.253",
                              "sndDns": "8.8.8.8", "leasetime": 120, "gateway": "192.168.10.1",
                              "ipRangePool": [{"ipaddrStart": "192.168.10.50", "ipaddrEnd": "192.168.10.99"},
                                              {"ipaddrStart": "192.168.10.150", "ipaddrEnd": "192.168.10.199"}]},
             "poolStatus": [{"startIp": "192.168.10.50", "endIp": "192.168.10.99", "availableIpNum": 7}]},
            {"name": "Lab", "vlan": 50, "deviceType": 2, "deviceMac": "AA-BB-CC-00-11-22", "mode": 2,
             "dhcpRelay": {"addr": "10.50.0.1", "serverAddrs": ["10.0.0.5", "10.0.0.6"]}},
            {"name": "Guest", "deviceType": 1, "dhcpSettings": {"enable": False, "leasetime": 60}},
            {"name": "Ext", "deviceType": 0},
            {"name": "Legacy", "dhcpSettings": {"enable": True, "dhcpns": "auto",
                                                "ipaddrStart": "10.1.1.10", "ipaddrEnd": "10.1.1.20"}},
        ], self._DHCP_CONTEXT)
        client, lab, guest, ext, legacy = rows
        assert client == {
            "Network": "Client", "VLAN": "10", "Subnet": "192.168.10.1/24",
            "DHCP Server": "Gateway (Astoria Gateway)",
            "Pools": "192.168.10.50 – 192.168.10.99 (7 free); 192.168.10.150 – 192.168.10.199",
            "Lease Time": "120 min", "DNS": "192.168.20.253, 8.8.8.8", "Gateway": "192.168.10.1",
            "Domain": "home.arpa", "Relay To": "", "L2 Relay (Opt 82)": "Enabled",
        }
        assert lab["DHCP Server"] == "Switch DHCP Relay (Core Switch)"
        assert lab["Relay To"] == "10.0.0.5, 10.0.0.6"
        assert lab["Pools"] == ""
        assert guest["DHCP Server"] == "Disabled"
        assert guest["Lease Time"] == ""  # not serving: settings are not presented as active
        assert ext["DHCP Server"] == "External"
        assert legacy["DHCP Server"] == "Gateway"  # no deviceType: inferred from enable
        assert legacy["Pools"] == "10.1.1.10 – 10.1.1.20"
        assert legacy["DNS"] == "Auto"

    def test_dhcp_scope_details_gateway_options_and_guard(self) -> None:
        from omada.registry import _dhcp_scope_details
        [(title, rows)] = _dhcp_scope_details([{
            "name": "Voice", "gatewaySubnet": "192.168.60.1/24", "deviceType": 1,
            "deviceMac": "6C-5A-B0-28-3C-77", "domain": "voice.example",
            "dhcpSettings": {
                "enable": True, "dhcpns": "manual", "priDns": "1.1.1.1", "leasetime": 1440,
                "ipaddrStart": "192.168.60.10", "ipaddrEnd": "192.168.60.200",
                "option60": "PolycomVVX", "option66": "10.0.0.20", "option138": "10.0.0.2",
                "dhcpNextServer": "10.0.0.21",
                "options": [{"code": 150, "name": "TFTP list", "type": 1, "value": "10.0.0.20"},
                            {"code": 43, "type": 2, "value": "01:04:0a:00:00:02"}],
            },
            "dhcpGuard": {"enable": True, "mode": 2, "dhcpSvr1": "192.168.60.1", "dhcpSvr2": ""},
            "dhcpv6Guard": {"enable": False},
        }], self._DHCP_CONTEXT)
        assert title == "Voice"
        values = {(r["Category"], r["Setting"]): r["Value"] for r in rows}
        assert values[("Pool", "Range 1")] == "192.168.60.10 – 192.168.60.200"
        assert values[("Pool", "Lease Time")] == "1440 min"
        assert values[("DNS / Domain", "DNS Mode")] == "Manual"
        assert values[("DNS / Domain", "Primary DNS")] == "1.1.1.1"
        assert values[("DNS / Domain", "Domain Name")] == "voice.example"
        assert values[("Options", "Default Gateway (Option 3)")] == "Default"
        assert values[("Options", "Option 60 (Vendor Class)")] == "PolycomVVX"
        assert values[("Options", "Option 66 (TFTP Server)")] == "10.0.0.20"
        assert values[("Options", "Option 138 (Controller)")] == "10.0.0.2"
        assert values[("Options", "Next Server (siaddr)")] == "10.0.0.21"
        # Gateway option type codes: 1 = IP Address, 2 = Hex Array
        assert values[("Options", "Option 150 TFTP list")] == "IP Address: 10.0.0.20"
        assert values[("Options", "Option 43")] == "Hex Array: 01:04:0a:00:00:02"
        assert values[("Guard", "DHCP Guard")] == "Enabled"
        assert values[("Guard", "DHCP Guard Mode")] == "Custom"
        assert values[("Guard", "DHCP Guard Trusted Servers")] == "192.168.60.1"
        assert values[("Guard", "DHCPv6 Guard")] == "Disabled"

    def test_dhcp_scope_details_switch_server_uses_switch_option_types(self) -> None:
        from omada.registry import _dhcp_scope_details
        [(_, rows)] = _dhcp_scope_details([{
            "name": "Servers", "deviceType": 2, "deviceMac": "AA-BB-CC-00-11-22", "mode": 1,
            "dhcpServer": {"ip": "10.20.0.1", "netmask": "24", "leasetime": 480,
                           "range": [{"startIp": "10.20.0.100", "endIp": "10.20.0.150"}],
                           "priDns": "10.0.0.53", "gateway": "10.20.0.1",
                           "options": [{"code": 42, "type": 2, "value": "10.0.0.123"}]},
        }], self._DHCP_CONTEXT)
        values = {(r["Category"], r["Setting"]): r["Value"] for r in rows}
        assert values[("Server", "DHCP Server")] == "Switch DHCP Server (Core Switch)"
        assert values[("Server", "Switch Interface")] == "10.20.0.1/24"
        assert values[("Pool", "Range 1")] == "10.20.0.100 – 10.20.0.150"
        assert values[("Pool", "Lease Time")] == "480 min"
        assert values[("Options", "Default Gateway (Option 3)")] == "10.20.0.1"
        # Switch option type codes: 2 = IP Address
        assert values[("Options", "Option 42")] == "IP Address: 10.0.0.123"

    def test_dhcp_scope_details_switch_relay(self) -> None:
        from omada.registry import _dhcp_scope_details
        [(_, rows)] = _dhcp_scope_details([{
            "name": "Lab", "deviceType": 2, "mode": 2, "dhcpL2RelayEnable": False,
            "dhcpRelay": {"addr": "10.50.0.1", "serverAddrs": ["10.0.0.5"]},
        }])
        values = {(r["Category"], r["Setting"]): r["Value"] for r in rows}
        assert values[("Relay", "Relay Interface")] == "10.50.0.1"
        assert values[("Relay", "Relay To")] == "10.0.0.5"
        assert not any(r["Category"] in ("Pool", "Options") for r in rows)

    def test_dhcp_lease_rows_sorted_by_network_then_ip(self) -> None:
        from omada.registry import _dhcp_lease_rows
        rows = _dhcp_lease_rows([
            {"netName": "LAN", "ipAddress": "192.168.2.100", "macAddress": "B", "name": "nas",
             "type": 1, "showingType": "NAS", "status": 1, "leftLeaseTime": "1h 2m",
             "serverName": "Astoria Gateway"},
            {"netName": "LAN", "ipAddress": "192.168.2.20", "macAddress": "A", "name": "pc",
             "type": 1, "status": 0},
            {"netName": "IoT", "ipAddress": "192.168.40.9", "macAddress": "C", "type": 0, "status": 0},
        ])
        assert [r["IP Address"] for r in rows] == ["192.168.40.9", "192.168.2.20", "192.168.2.100"]
        assert rows[1]["Type"] == "Client"
        assert rows[1]["Binding"] == "Dynamic"
        assert rows[0]["Type"] == "Device"
        assert rows[2] == {
            "Network": "LAN", "IP Address": "192.168.2.100", "MAC Address": "B", "Name": "nas",
            "Type": "NAS", "Binding": "Static", "Lease Remaining": "1h 2m",
            "Server": "Astoria Gateway",
        }

    def test_dhcp_reservation_rows_sorted_with_description_and_options(self) -> None:
        from omada.registry import _dhcp_reservation_rows
        rows = _dhcp_reservation_rows([
            {"netName": "LAN", "ip": "192.168.2.250", "mac": "A", "name": "nas", "status": True,
             "description": "TrueNAS", "options": [{"code": 66, "value": "10.0.0.20"}]},
            {"netName": "LAN", "ip": "192.168.2.30", "mac": "B", "name": "printer", "status": False},
            {"netName": "IoT", "ip": "192.168.40.10", "mac": "C", "name": "tv", "status": True},
        ])
        assert [r["IP Address"] for r in rows] == ["192.168.40.10", "192.168.2.30", "192.168.2.250"]
        assert rows[2]["Description"] == "TrueNAS"
        assert rows[2]["Options"] == "Option 66: 10.0.0.20"
        assert rows[1]["Status"] == "Disabled"

    _WIFI_CONTEXT = {
        "radius_profiles": [{"radiusProfileId": "r1", "name": "Corp RADIUS"}],
        "rate_limit_profiles": [{"profileId": "rl1", "name": "Guest 10M"}],
        "time_range_profiles": [{"profileId": "t1", "name": "Office hours"}],
        "networks": [{"id": "net-iot", "name": "IoT Devices"}],
        "portals": [{"name": "Guest Portal", "ssidList": ["s-guest"]}],
    }

    def test_ssid_rows_resolve_profiles(self) -> None:
        from omada.registry import _ssid_rows
        rows = _ssid_rows([
            {"id": "s1", "name": "FROGGY", "wlanName": "Default", "band": 7, "security": 3,
             "pskSetting": {"versionPsk": 4, "encryptionPsk": 3, "securityKey": "<redacted>"},
             "vlanEnable": True, "vlanId": 10, "broadcast": True,
             "clientRateLimit": {"profileId": "rl1"},
             "wlanSchedule": {"wlanScheduleEnable": True, "action": 1, "scheduleId": "t1"},
             "ssidDhcpOption": {"mode": 3}},
            {"id": "s-guest", "name": "Guest", "security": 0, "oweEnable": True, "guestNetEnable": True,
             "clientRateLimit": {"customSetting": {"downLimitEnable": True, "downLimit": 20, "downLimitType": 1,
                                                   "upLimitEnable": True, "upLimit": 512, "upLimitType": 0}},
             "wlanSchedule": {"wlanScheduleEnable": False}, "bandSteer": {"mode": 1}},
            {"id": "s-ent", "name": "Corp", "security": 2,
             "entSetting": {"versionEnt": 4, "radiusProfileId": "r1"},
             "vlanSetting": {"mode": 1, "customConfig": {"customMode": 0, "lanNetworkId": "net-iot"}}},
        ], self._WIFI_CONTEXT)
        froggy, guest, corp = rows
        assert froggy["Security"] == "WPA2-PSK/WPA3-SAE (AES)"
        assert froggy["VLAN"] == "10"
        assert froggy["Client Rate Limit"] == "Guest 10M"
        assert froggy["Schedule"] == "Office hours (Radio on during schedule)"
        assert froggy["Band Steering"] == "Use site setting"
        assert guest["Security"] == "Open (OWE)"
        assert guest["Guest"] == "Yes"
        assert guest["Portal"] == "Guest Portal"
        assert guest["Client Rate Limit"] == "Down 20 Mbps / Up 512 Kbps"
        assert guest["Schedule"] == "None"
        assert guest["Band Steering"] == "Prefer 5GHz/6GHz"
        assert corp["Security"] == "WPA3-Enterprise (RADIUS: Corp RADIUS)"
        assert corp["VLAN"] == "IoT Devices"

    def test_ssid_details_and_ap_overrides(self) -> None:
        from omada.registry import _ssid_details
        details = _ssid_details([{
            "id": "s1", "name": "FROGGY", "wlanName": "Default", "band": 3, "ssidEnable": True,
            "deviceType": 3, "security": 3,
            "pskSetting": {"versionPsk": 4, "securityKey": "<redacted>", "gikRekeyPskEnable": True,
                           "rekeyPskInterval": 1, "intervalPskType": 2},
            "pmfMode": 2, "enable11r": True, "mloEnable": False,
            "ssidRateLimit": {"customSetting": {"downLimitEnable": False, "upLimitEnable": False}},
            "rateControl": {"rate2gCtrlEnable": True, "lowerDensity2g": 12, "cckRatesDisable": True,
                            "rate5gCtrlEnable": False},
            "macFilter": {"macFilterEnable": True, "policy": 1, "macFilterId": "mg1"},
            "multiCast": {"multiCastEnable": True, "channelUtil": 70},
            "dhcpOption82": {"dhcpEnable": False},
            "hotspotV2Setting": {"hotspotV2Enable": False},
            "apOverrides": [{"name": "Office AP", "mac": "AA", "ssidEnable": True,
                             "overrideName": "FROGGY-OFFICE", "overrideVlan": "30",
                             "overridePassword": "<redacted>"}],
        }], self._WIFI_CONTEXT)
        assert [t for t, _ in details] == ["FROGGY", "FROGGY AP overrides"]
        values = {(r["Category"], r["Setting"]): r["Value"] for r in details[0][1]}
        assert values[("General", "Applies To")] == "EAP, Gateway"
        assert values[("Security", "Passphrase")] == "Configured"
        assert values[("Security", "Group Key Update")] == "Every 1 h"
        assert values[("Security", "PMF")] == "Capable"
        assert values[("Security", "802.11r Fast Transition")] == "Enabled"
        assert values[("Rate Limits", "SSID Rate Limit")] == "Unlimited"
        assert values[("Rate Control", "2.4 GHz Data Rate")] == "Minimum 12 Mbps, CCK rates disabled"
        assert values[("Rate Control", "5 GHz Data Rate")] == "Disabled"
        assert values[("MAC Filter", "MAC Filter")] == "Enabled (Allow List, MAC group mg1)"
        assert values[("Multicast", "Channel Utilization Threshold")] == "70%"
        assert values[("DHCP", "DHCP Option 82")] == "Disabled"
        assert values[("Hotspot 2.0", "Hotspot 2.0")] == "Disabled"
        assert details[1][1] == [{
            "AP": "Office AP", "AP MAC": "AA", "SSID Enabled": "Enabled",
            "Override SSID Name": "FROGGY-OFFICE", "Override VLAN": "30", "Override Password": "Configured",
        }]

    def test_radius_profile_rows(self) -> None:
        from omada.registry import _radius_profile_rows
        rows = _radius_profile_rows([
            {"name": "Corp", "authServer": [{"radiusServerIp": "10.0.0.5", "radiusPort": 1812,
                                             "radiusPwd": "<redacted>", "radSecEnable": True}],
             "radiusAccountingEnable": True, "interimUpdateEnable": True, "interimUpdateInterval": 600,
             "acctServer": [{"accountingServerIp": "10.0.0.5", "accountingServerPort": 1813,
                             "accountingServerPwd": "<redacted>"}],
             "wirelessVlanAssignment": True, "coaEnable": False, "requireMessageAuthenticator": True},
            {"name": "Built-in", "builtInServer": True, "serverEnable": True, "ipType": 1,
             "customIp": "192.168.2.1"},
        ])
        assert rows[0] == {
            "Name": "Corp", "Type": "External",
            "Authentication Servers": "10.0.0.5:1812 (RadSec, secret configured)",
            "Accounting": "10.0.0.5:1813 (secret configured); interim update 600 s",
            "VLAN Assignment": "Enabled", "CoA": "Disabled", "Message-Authenticator": "Required",
        }
        assert rows[1]["Type"] == "Built-in"
        assert rows[1]["Authentication Servers"] == "Built-in server (enabled), IP 192.168.2.1"
        assert rows[1]["Accounting"] == "Disabled"

    def test_portal_rows_and_details(self) -> None:
        from omada.registry import _portal_details, _portal_rows
        context = {**self._WIFI_CONTEXT, "ssids": [{"id": "s-guest", "name": "Guest"}],
                   "networks": [{"id": "net-guest", "name": "Guest LAN"}]}
        portals = [
            {"name": "Hotspot", "enable": True, "authType": 11, "ssidList": ["s-guest"],
             "networkList": ["net-guest"], "hotspot": {"enabledTypes": [3, 6]},
             "authTimeout": {"authTimeout": 0, "customTimeout": 3, "customTimeoutUnit": 3},
             "landingPage": 2, "landingUrlScheme": "https", "landingUrl": "example.com/welcome",
             "httpsRedirectEnable": True,
             "sms": {"sid": "AC123", "authToken": "<redacted>", "phoneNum": "+15550100"}},
            {"name": "Radius", "enable": False, "authType": 2,
             "externalRadius": {"radiusProfileId": "r1", "authMode": 2, "nasId": "omada",
                                "portalCustom": 1, "disconnectReq": True, "receiverPort": 3799},
             "authTimeout": {"authTimeout": 6}},
        ]
        hotspot, radius = _portal_rows(portals, context)
        assert hotspot == {
            "Name": "Hotspot", "Status": "Enabled", "Authentication": "Hotspot (Voucher, SMS)",
            "SSIDs": "Guest", "Networks": "Guest LAN", "Auth Timeout": "3 days",
            "Landing Page": "Promotional URL (https://example.com/welcome)", "HTTPS Redirect": "Enabled",
        }
        assert radius["Auth Timeout"] == "1 day"
        assert radius["Status"] == "Disabled"
        details = dict(_portal_details(portals, context))
        sms = {r["Setting"]: r["Value"] for r in details["Hotspot"] if r["Category"] == "SMS (Twilio)"}
        assert sms == {"Account SID": "AC123", "Auth Token": "Configured", "Sender Number": "+15550100"}
        rad = {r["Setting"]: r["Value"] for r in details["Radius"]}
        assert rad["RADIUS Profile"] == "Corp RADIUS"
        assert rad["Auth Mode"] == "CHAP"
        assert rad["Portal Page"] == "Local Web Portal"
        assert rad["Disconnect Requests"] == "Enabled (port 3799)"

    def test_time_range_rows(self) -> None:
        from omada.registry import _time_range_rows
        rows = _time_range_rows([
            {"name": "Office hours", "dayMode": 1,
             "timeList": [{"dayType": 0, "startTimeH": 8, "startTimeM": 30, "endTimeH": 17, "endTimeM": 0}]},
            {"name": "Custom", "dayMode": 3,
             "customDayMode": {"dayMon": True, "dayWed": True, "daySun": False},
             "timeList": [{"dayType": 1, "startTimeH": 0, "startTimeM": 0, "endTimeH": 6, "endTimeM": 15},
                          {"dayType": 3, "startTimeH": 22, "startTimeM": 0, "endTimeH": 24, "endTimeM": 0}]},
        ])
        assert rows[0] == {"Name": "Office hours", "Days": "Weekdays", "Times": "08:30–17:00"}
        assert rows[1] == {"Name": "Custom", "Days": "Mon, Wed", "Times": "Mon 00:00–06:15, Wed 22:00–24:00"}

    def test_rate_limit_profile_rows(self) -> None:
        from omada.registry import _rate_limit_profile_rows
        rows = _rate_limit_profile_rows([
            {"name": "Guest", "downLimitEnable": True, "downLimit": 10240, "upLimitEnable": False,
             "defaultProfile": False},
        ])
        assert rows == [{"Name": "Guest", "Download": "10240 Kbps", "Upload": "Unlimited", "Default": "No"}]

    def test_wireless_settings_rows(self) -> None:
        from omada.registry import _wireless_settings_rows
        rows = _wireless_settings_rows({
            "bandSteering": {"bandSteeringForMultiBand": {"mode": 2}},
            "roaming": {"roaming": {"fastRoamingEnable": True, "aiRoamingEnable": False,
                                    "nonStickRoamingEnable": True}},
            "mesh": {"mesh": {"meshEnable": True, "autoFailoverEnable": True,
                              "defGatewayEnable": False, "gateway": "192.168.2.1", "fullSector": False}},
            "multicastRateLimit": {"mcastRateLimit": {"enable": True, "arpEnable": True, "arpPps": 100,
                                                      "mdnsEnable": False}},
        })
        values = {(r["Category"], r["Setting"]): r["Value"] for r in rows}
        assert values == {
            ("Band Steering", "Mode"): "Balance",
            ("Roaming", "Fast Roaming"): "Enabled",
            ("Roaming", "AI Roaming"): "Disabled",
            ("Roaming", "Non-Stick Roaming"): "Enabled",
            ("Mesh", "Mesh"): "Enabled",
            ("Mesh", "Auto Failover"): "Enabled",
            ("Mesh", "Full-Sector DFS"): "Disabled",
            ("Mesh", "Connectivity Detection"): "Custom IP 192.168.2.1",
            ("Multicast Rate Limit", "Multicast Rate Limit"): "Enabled",
            ("Multicast Rate Limit", "ARP"): "100 pps",
            ("Multicast Rate Limit", "mDNS"): "Not limited",
        }

    def test_ap_radio_rows(self) -> None:
        from omada.registry import _ap_radio_rows
        rows = _ap_radio_rows([{
            "deviceName": "Lower AP", "deviceModel": "EAP620 HD",
            "radios": {
                "5g": {"radioEnable": True, "channel": "36", "channelWidth": "5", "txPowerLevel": 3,
                       "txPower": 18, "wirelessMode": 16, "channelLimitEnable": False},
                "2g": {"radioEnable": True, "channel": "0", "channelWidth": "4", "txPowerLevel": 4,
                       "wirelessMode": -2},
                "6g": {"radioEnable": False, "channel": "37", "txPowerLevel": 2},
            },
        }])
        assert [r["Band"] for r in rows] == ["2.4 GHz", "5 GHz", "6 GHz"]
        two, five, six = rows
        assert two["Channel"] == "Auto"
        assert two["Channel Width"] == "Auto (20/40 MHz)"
        assert two["Tx Power"] == "Auto"
        assert two["Wireless Mode"] == "Auto"
        assert five == {
            "AP": "Lower AP", "Model": "EAP620 HD", "Band": "5 GHz", "Radio": "Enabled",
            "Channel": "36", "Channel Width": "80 MHz", "Tx Power": "Custom (18 dBm)",
            "Wireless Mode": "802.11a/n/ac/ax", "Channel Limit": "Disabled",
        }
        assert six["Radio"] == "Disabled"
        assert six["Channel"] == "" and six["Tx Power"] == ""

    _SERVICES_CONTEXT = {
        "gateway_settings": {"wanPortsConfig": [{"portId": "1_abc", "portName": "WAN"}]},
        "networks": [{"id": "net-lan", "name": "LAN"}, {"id": "net-iot", "name": "IoT Devices"}],
        "time_range_profiles": [{"profileId": "t1", "name": "Business hours"}],
    }

    def test_wan_failover_rows(self) -> None:
        from omada.registry import _wan_failover_rows
        data = {
            "internet": {"interval": 10, "portList": [
                {"portId": "2_def", "portName": "WAN/LAN1", "portMode": 0},
                {"portId": "1_abc", "portName": "WAN", "portMode": 0},
                {"portId": "3_ghi", "portName": "WAN/LAN2", "portMode": 1},
            ]},
            "loadBalance": {"linkBackup": True, "primaryWans": ["1_abc"], "backupWan": "2_def",
                            "mode": 2, "timeRangeId": "t1", "backupMode": 1,
                            "appOptRouting": True, "weights": [3, 1]},
        }
        values = {r["Setting"]: r["Value"] for r in _wan_failover_rows(data, self._SERVICES_CONTEXT)}
        assert values == {
            "Health Check (Online Detection)": "Every 10 s",
            "Link Backup (Failover)": "Enabled",
            "Primary WANs": "WAN",
            "Backup WAN": "WAN/LAN1",
            "Backup Trigger": "On schedule (Business hours)",
            "Backup Mode": "Return to primary when it recovers",
            "Application Optimized Routing": "Enabled",
            # weights follow WAN-mode ports in port-ID order
            "Load Balancing Weights": "WAN: 3, WAN/LAN1: 1",
        }
        off = {r["Setting"]: r["Value"] for r in _wan_failover_rows(
            {"internet": {"interval": 0}, "loadBalance": {"linkBackup": False, "weights": [1, 2, 3]}})}
        assert off["Health Check (Online Detection)"] == "Disabled"
        assert off["Link Backup (Failover)"] == "Disabled"
        assert off["Load Balancing Weights"] == "1, 2, 3"  # port list unknown: raw order
        assert "Backup WAN" not in off

    def test_wan_failover_health_snapshot(self) -> None:
        from omada.registry import _wan_failover_details
        [(title, rows)] = _wan_failover_details({"wanHealth": [
            {"gatewayName": "GW", "name": "WAN", "mode": 0, "status": 1, "internetState": 1,
             "onlineDetection": 1, "ip": "203.0.113.4", "proto": "DHCP", "speed": 3,
             "latency": 9, "loss": 0.5, "healthLevel": 0},
            {"gatewayName": "GW", "name": "WAN/LAN1", "mode": 1, "status": 1},
        ]})
        assert title == "WAN Health (status at export time)"
        assert rows == [{
            "Gateway": "GW", "WAN": "WAN", "Link": "Connected", "Internet": "Online",
            "Online Detection": "Online", "IP": "203.0.113.4", "Connection": "DHCP",
            "Speed": "1000M", "Latency": "9 ms", "Packet Loss": "0.5%", "Health Level": "0",
        }]

    def test_dns_settings_rows_per_proxy_type(self) -> None:
        from omada.registry import _dns_settings_rows

        def values(proxy: dict) -> dict:
            return {r["Setting"]: r["Value"] for r in _dns_settings_rows(
                {"dnsProxy": proxy, "dnsCache": {"enable": True, "ttl": 300}, "lanDns": [{}], "ddns": []},
                self._SERVICES_CONTEXT)}

        doh = values({"enable": True, "type": 1, "dohSetting": {
            "defaultServers": [1, 5],
            "customizedServers": [{"enable": True, "name": "NextDNS", "server": "dns.nextdns.io"},
                                  {"enable": False, "name": "Off", "server": "x"}]}})
        assert doh["DNS Proxy Type"] == "DNS over HTTPS"
        assert doh["Upstream Servers"] == "Cloudflare, Quad9 (1), NextDNS (dns.nextdns.io)"
        assert doh["DNS Cache"] == "Enabled (TTL 300 s)"
        assert doh["LAN DNS Records"] == "1"
        assert doh["Dynamic DNS Entries"] == "0"
        dot = values({"enable": True, "type": 2, "dotSetting": {
            "defaultServers": [2],
            "customizedServers": [{"enable": True, "name": "Mine", "servers": ["1.1.1.1", "9.9.9.9"]}]}})
        assert dot["Upstream Servers"] == "OpenDNS, Mine (1.1.1.1, 9.9.9.9)"
        sec = values({"enable": True, "type": 0, "dnsSecSetting": {"servers": ["1.1.1.1"], "replyPolicy": 1}})
        assert sec["DNSSEC Servers"] == "1.1.1.1" and sec["Bogus Reply Policy"] == "Drop"
        override = values({"enable": True, "type": 3, "dnsOverrideSetting": {
            "primaryDnsServer": "192.168.20.253", "secondaryDnsServer": "", "applyNetwork": ["net-iot"]}})
        assert override["Override Servers"] == "192.168.20.253"
        assert override["Override Applies To"] == "IoT Devices"
        assert values({"enable": False})["DNS Proxy"] == "Disabled"

    def test_dns_settings_details(self) -> None:
        from omada.registry import _dns_settings_details
        sections = dict(_dns_settings_details({
            "lanDns": [
                {"name": "nas", "enable": True, "domain": "nas.home.arpa", "aliases": ["files.home.arpa"],
                 "type": 0, "ipAddresses": ["192.168.2.250"], "lanNetworkIds": ["net-lan"], "customTtl": False},
                {"name": "corp", "enable": True, "domain": "corp.example", "type": 2,
                 "dnsServers": ["10.0.0.53"], "customTtl": True, "ttl": 60},
                {"name": "www", "enable": False, "domain": "app.home.arpa", "type": 1, "cname": "nas.home.arpa"},
            ],
            "ddns": [{"service": 1, "status": True, "domainName": "astoria.ddns.net", "interfacePortId": "1_abc",
                      "username": "frank", "password": "<redacted>", "updateInterval": 1}],
        }, self._SERVICES_CONTEXT))
        records = sections["LAN DNS Records"]
        assert [r["Domain"] for r in records] == ["app.home.arpa", "corp.example", "nas.home.arpa"]
        assert records[0]["Answer"] == "nas.home.arpa" and records[0]["Type"] == "CNAME"
        assert records[1]["Answer"] == "Forward to 10.0.0.53" and records[1]["TTL"] == "60 s"
        assert records[2]["Answer"] == "192.168.2.250" and records[2]["Networks"] == "LAN"
        assert records[2]["TTL"] == "Default (3600 s)"
        assert sections["Dynamic DNS"] == [{
            "Service": "NO-IP", "Status": "Enabled", "Domain": "astoria.ddns.net", "Interface": "WAN",
            "Username": "frank", "Password": "Configured", "Update Interval": "1 h", "Update URL": "",
        }]

    def test_time_settings_rows(self) -> None:
        from omada.registry import _time_settings_rows
        values = {r["Setting"]: r["Value"] for r in _time_settings_rows({
            "site": {"timeZone": "America/New_York", "region": "US",
                     "ntpServers": ["time.google.com", "pool.ntp.org"]},
            "dst": {"enable": True, "mode": 1, "offset": 3600000},
        })}
        assert values == {
            "Time Zone": "America/New_York", "Region": "US",
            "NTP Servers": "time.google.com, pool.ntp.org",
            "Daylight Saving Time": "Automatic", "DST Offset": "60 min",
        }
        assert {r["Setting"]: r["Value"] for r in _time_settings_rows(
            {"site": {"ntpServers": []}})}["NTP Servers"] == "Default"

    def test_multicast_services_rows_and_details(self) -> None:
        from omada.registry import _multicast_services_details, _multicast_services_rows
        data = {
            "igmp": {"enable": True, "version": 3, "wanPortId": "1_abc"},
            "mld": {"enable": False, "version": 2},
            "iptv": {"enable": True, "mode": 1, "wanPortId": "1_abc",
                     "customConfig": {"iptvVlanId": 85, "iptvVlanPriority": 4,
                                      "ipPhoneVlanId": 86, "ipPhoneVlanPriority": 5},
                     "portConfig": [{"portId": "4_x", "name": "LAN3", "type": 2}]},
            "upnp": {"enable": True, "wanPortIds": ["1_abc"], "networkIds": ["net-lan"]},
            "bonjourServices": [{"id": "b1", "name": "AirPlay", "serviceIds": ["_airplay._tcp.local"],
                                 "defaultProfile": True},
                                {"id": "b2", "name": "Chromecast", "serviceIds": ["_googlecast._tcp.local"]}],
            "mdnsRules": [
                {"name": "Cast to IoT", "status": True, "profileIds": ["b1", "b2"], "type": 1,
                 "osg": {"serviceNetworks": ["net-iot"], "clientNetworks": ["net-lan"]}},
                {"name": "AP rule", "status": False, "profileIds": ["b1"], "type": 0,
                 "ap": {"serviceVlan": "40", "clientVlan": "10,20"}},
            ],
            "lanMulticasts": [{"name": "IGMP LAN", "protocol": 0, "networks": [{"id": "net-lan"}],
                               "unknownMulticastRule": 1, "querierEnable": True, "floodKnownEnable": False,
                               "routerPortEnable": False,
                               "snoopConfig": {"reportSuppressionEnable": True, "leaveTime": 1}}],
        }
        values = {(r["Category"], r["Setting"]): r["Value"]
                  for r in _multicast_services_rows(data, self._SERVICES_CONTEXT)}
        assert values[("Multicast", "IGMP Proxy")] == "Enabled (v3, upstream WAN)"
        assert values[("Multicast", "MLD Proxy")] == "Disabled"
        assert values[("Multicast", "IPTV")] == "Enabled (Custom, WAN WAN)"
        assert values[("Multicast", "IPTV VLAN")] == "85 (priority 4)"
        assert values[("Multicast", "IP Phone VLAN")] == "86 (priority 5)"
        assert values[("Multicast", "IPTV Port Roles")] == "LAN3: IPTV"
        assert values[("Services", "UPnP")] == "Enabled (WAN WAN; LAN LAN)"
        assert values[("Bonjour / mDNS", "mDNS Rules")] == "2 (1 enabled)"
        assert values[("Bonjour / mDNS", "Bonjour Service Profiles")] == "2"
        assert values[("Multicast", "Multicast Snooping Configs")] == "1"

        sections = dict(_multicast_services_details(data, self._SERVICES_CONTEXT))
        assert sections["mDNS (Bonjour) Rules"] == [
            {"Name": "Cast to IoT", "Status": "Enabled", "Services": "AirPlay, Chromecast",
             "Mode": "By Network", "Service Networks": "IoT Devices", "Client Networks": "LAN"},
            {"Name": "AP rule", "Status": "Disabled", "Services": "AirPlay",
             "Mode": "By VLAN ID", "Service Networks": "VLAN 40", "Client Networks": "VLAN 10,20"},
        ]
        assert sections["Bonjour Service Profiles"][0] == {
            "Name": "AirPlay", "Service IDs": "_airplay._tcp.local", "Built-in": "Yes"}
        assert sections["Multicast Snooping"] == [{
            "Name": "IGMP LAN", "Protocol": "IGMP Snooping", "Networks": "LAN",
            "Unknown Multicast": "Discard", "Querier": "Enabled", "Flood Known": "Disabled",
            "Manual Router Ports": "Disabled", "Report Suppression": "Enabled", "Leave Time": "1 s",
        }]

    def test_lag_rows_and_details(self) -> None:
        from omada.registry import _lag_details, _lag_rows
        data = {
            "lags": [
                {"deviceName": "Main Switch", "lagId": 1, "lagType": 2, "memberPorts": [25, 26],
                 "profileName": "All", "members": [
                     {"port": 25, "portName": "Port25", "connectedStatus": 0,
                      "portStatus": {"linkStatus": 1, "linkSpeed": 3, "duplex": 2}, "profileName": "All"},
                     {"port": 26, "portName": "Port26", "connectedStatus": 1}]},
                {"deviceName": "Core Stack", "lagId": 3, "name": "Uplink", "lagType": 3, "ports": [1, 2],
                 "memberPorts": [1, 2], "mlagEnable": True, "mlagName": "DC Pair",
                 "standardPorts": [{"unit": 1, "slot": 0, "port": 1}, {"unit": 2, "slot": 0, "port": 1}],
                 "lagStatus": {"linkStatus": 1, "linkSpeed": 5}},
                {"deviceName": "Lab Switch", "lagId": None, "memberPorts": [7], "members": []},
            ],
            "mlagGroups": [{"name": "DC Pair", "status": 0, "members": [
                {"name": "Core-A", "role": "Primary", "peerLinkPorts": [47, 48]},
                {"name": "Core-B", "role": "Secondary"}]}],
            "hashAlgorithm": {"type": 5},
        }
        rows = _lag_rows(data)
        assert rows[0] == {
            "Device": "Main Switch", "LAG": "LAG 1", "Name": "", "Mode": "LACP",
            "Member Ports": "25, 26", "Link": "1/2 members up", "Profile": "All", "M-LAG": "",
        }
        assert rows[1]["Mode"] == "LACP (Active)"
        assert rows[1]["Member Ports"] == "1/0/1, 2/0/1"
        assert rows[1]["Link"] == "Up (10G)"
        assert rows[1]["M-LAG"] == "DC Pair"
        assert rows[2]["LAG"] == "LAG (group unknown)" and rows[2]["Mode"] == ""

        sections = dict(_lag_details(data))
        assert sections["Main Switch LAG 1 members"] == [
            {"Port": "25", "Name": "Port25", "Connection": "Connected (1000M Full Duplex)", "Profile": "All"},
            {"Port": "26", "Name": "Port26", "Connection": "Disconnected", "Profile": ""},
        ]
        assert sections["M-LAG Groups"] == [{
            "Name": "DC Pair", "Status": "Normal", "Members": "Core-A (Primary), Core-B (Secondary)",
            "Peer Link Ports": "Core-A: 47, 48",
        }]
        assert sections["Site LAG Settings"] == [{"Setting": "Hash Algorithm", "Value": "Source + Destination IP"}]
        assert _lag_rows({}) == [] and _lag_details({}) == []

    def test_device_port_operation_names_lag(self) -> None:
        from omada.registry import _device_port_rows
        rows = _device_port_rows([
            {"deviceName": "SW", "deviceType": "switch", "port": 25, "operation": "AGGREGATING",
             "lagSetting": {"lagId": 1, "ports": [25, 26]}},
            {"deviceName": "SW", "deviceType": "switch", "port": 9, "operation": "AGGREGATING"},
        ])
        assert rows[0]["Operation"] == "Aggregating (LAG 1)"
        assert rows[1]["Operation"] == "Aggregating"

    def test_switch_port_profile_rows(self) -> None:
        from omada.registry import _switch_port_profile_rows
        rows = _switch_port_profile_rows([
            {"name": "Trunk Profile", "type": 0, "spanningTreeEnable": True, "poe": 1}
        ])
        assert rows[0]["Name"] == "Trunk Profile"
        assert rows[0]["Type"] == "All"
        assert rows[0]["Spanning Tree"] == "Enabled"
        assert rows[0]["PoE"] == "Enabled"
        assert rows[0]["Tagged Networks"] == ""

    def test_switch_port_profile_rows_resolves_tagged_networks(self) -> None:
        from omada.registry import _switch_port_profile_rows
        context = {
            "networks": [
                {"id": "net1", "name": "IoT"},
                {"id": "net2", "name": "LAN"},
            ]
        }
        rows = _switch_port_profile_rows(
            [{"name": "Trunk Profile", "type": 0, "tagNetworkIds": ["net1", "net2"]}],
            context=context,
        )
        assert rows[0]["Tagged Networks"] == "IoT, LAN"

    def test_switch_port_profile_rows_no_context_shows_raw_ids(self) -> None:
        from omada.registry import _switch_port_profile_rows
        rows = _switch_port_profile_rows(
            [{"name": "Profile", "type": 2, "spanningTreeEnable": False, "poe": 0,
              "taggedNetworkIds": ["abc123"]}]
        )
        assert rows[0]["Tagged Networks"] == "abc123"

    def test_switch_port_profile_rows_vlan_columns(self) -> None:
        from omada.registry import _switch_port_profile_rows
        context = {"networks": [{"id": "n1", "name": "Default"}, {"id": "n2", "name": "IoT"}]}
        rows = _switch_port_profile_rows(
            [{"name": "P", "type": 2, "nativeNetworkId": "n1",
              "untagNetworkIds": ["n1"], "tagNetworkIds": ["n2"]}],
            context=context,
        )
        assert rows[0]["Type"] == "Standard"
        assert rows[0]["Native Network"] == "Default"
        assert rows[0]["Untagged Networks"] == "Default"
        assert rows[0]["Tagged Networks"] == "IoT"

    def test_switch_port_profile_details_lists_all_properties(self) -> None:
        from omada.registry import _switch_port_profile_details
        context = {"networks": [{"id": "n1", "name": "Default"}, {"id": "v1", "name": "Voice"}]}
        profile = {
            "id": "prof-1", "name": "Cameras", "flag": 2, "type": 2, "poe": 1, "dot1x": 2,
            "nativeNetworkId": "n1", "untagNetworkIds": [], "tagNetworkIds": [],
            "networkTagsSetting": 2, "voiceNetworkEnable": True, "voiceNetworkId": "v1",
            "voiceDscpEnable": True, "voiceDscp": 46, "networkConflict": False,
            "portIsolationEnable": True, "lldpMedEnable": True,
            "dhcpL2RelaySettings": {"enable": True, "format": 1},
            "dot1pPriority": 5, "trustMode": 2,
            "bandWidthCtrlType": 1,
            "bandCtrl": {"ingressEnable": True, "ingressLimit": 100, "ingressUnit": 2,
                         "egressEnable": False},
            "spanningTreeEnable": True,
            "spanningTreeSetting": {"priority": 128, "p2pLink": 0, "edgePort": True},
            "supportESEnable": False,
            "vlanConfigEnable": True,
            "nativeBridgeVlan": 1,
        }
        [(title, rows)] = _switch_port_profile_details([profile], context)
        assert title == "Cameras"
        values = {(r["Category"], r["Setting"]): r["Value"] for r in rows}
        assert values[("General", "Origin")] == "User-created"
        assert values[("General", "Profile ID")] == "prof-1"
        assert values[("General", "PoE")] == "Enabled"
        assert values[("General", "802.1X")] == "Auto"
        assert values[("VLAN", "Native Network")] == "Default"
        assert values[("VLAN", "Network Tags Setting")] == "Custom"
        assert values[("VLAN", "Voice Network")] == "Voice"
        assert values[("VLAN", "Voice DSCP")] == "46"
        assert values[("Switching", "Port Isolation")] == "Enabled"
        assert values[("Switching", "DHCP L2 Relay")] == "Enabled (Private)"
        assert values[("Switching", "ES Supported")] == "No"
        assert values[("QoS & Bandwidth", "Trust Mode")] == "Trust DSCP"
        assert values[("QoS & Bandwidth", "Bandwidth Control")] == "Rate Limit"
        assert values[("QoS & Bandwidth", "Ingress Rate Limit")] == "100 Mbps"
        assert values[("QoS & Bandwidth", "Egress Rate Limit")] == "Disabled"
        assert values[("Spanning Tree", "Priority")] == "128"
        assert values[("Spanning Tree", "P2P Link")] == "Auto"
        assert values[("Spanning Tree", "Edge Port")] == "Enabled"
        # Unmapped keys are still listed; internal bridge-VLAN bookkeeping is not
        assert values[("Other", "Vlan Config Enable")] == "Yes"
        assert not any("Bridge" in r["Setting"] for r in rows)

    def test_switch_port_profile_details_storm_control(self) -> None:
        from omada.registry import _switch_port_profile_details
        [(_, rows)] = _switch_port_profile_details([{
            "name": "Storm", "bandWidthCtrlType": 2,
            "stormCtrl": {"rateMode": 0, "broadcastEnable": True, "broadcast": 10,
                          "multicastEnable": False, "unknownUnicastEnable": False,
                          "action": 1, "recoverTime": 600},
            "spanningTreeEnable": False,
            "spanningTreeSetting": {"priority": 128},
        }])
        values = {r["Setting"]: r["Value"] for r in rows}
        assert values["Bandwidth Control"] == "Storm Control"
        assert values["Storm Control: Broadcast"] == "10%"
        assert values["Storm Control: Multicast"] == "Disabled"
        assert values["Storm Control: Action"] == "Shutdown"
        assert values["Storm Control: Recover Time"] == "600 s"
        # STP sub-settings are omitted when spanning tree is off
        assert values["Spanning Tree"] == "Disabled"
        assert "Priority" not in values

    def test_switch_port_profile_details_empty_input(self) -> None:
        from omada.registry import _switch_port_profile_details
        assert _switch_port_profile_details([]) == []
        assert _switch_port_profile_details({}) == []


class TestGenerateFromYaml:
    def _write_yaml(self, path: Path, data) -> None:
        path.write_text(yaml.dump(data, sort_keys=True), encoding="utf-8")

    def test_generates_markdown_from_yaml_files(self, tmp_path: Path) -> None:
        self._write_yaml(
            tmp_path / "acl_rules.yaml",
            [{"description": "rule1", "policy": 1}],
        )
        self._write_yaml(
            tmp_path / "ip_groups.yaml",
            [{"name": "RFC1918", "ipList": ["10.0.0.0/8"]}],
        )

        paths = generate_from_yaml(tmp_path, tmp_path)

        assert "acl_rules" in paths
        assert "ip_groups" in paths
        assert (tmp_path / "acl_rules.md").exists()
        assert (tmp_path / "ip_groups.md").exists()
        assert "rule1" in (tmp_path / "acl_rules.md").read_text()

    def test_separate_input_output_dirs(self, tmp_path: Path) -> None:
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        self._write_yaml(input_dir / "networks.yaml", [{"name": "LAN"}])

        paths = generate_from_yaml(input_dir, output_dir)

        assert (output_dir / "networks.md").exists()

    def test_empty_dir_returns_empty_dict(self, tmp_path: Path) -> None:
        paths = generate_from_yaml(tmp_path, tmp_path)
        assert paths == {}

    def test_empty_yaml_file_handled(self, tmp_path: Path) -> None:
        (tmp_path / "acl_rules.yaml").write_text("", encoding="utf-8")
        paths = generate_from_yaml(tmp_path, tmp_path)
        assert "acl_rules" in paths
        content = (tmp_path / "acl_rules.md").read_text()
        assert "_No records found._" in content

    def test_creates_output_dir_if_missing(self, tmp_path: Path) -> None:
        input_dir = tmp_path / "in"
        output_dir = tmp_path / "out" / "nested"
        input_dir.mkdir()
        self._write_yaml(input_dir / "vlans.yaml", [{"name": "IoT", "vlanId": 20}])

        generate_from_yaml(input_dir, output_dir)
        assert output_dir.is_dir()
