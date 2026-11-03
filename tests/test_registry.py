"""Tests for the resource registry and generate_from_yaml service function."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from omada.registry import REGISTRY, RESOURCES, ResourceDefinition
from omada.service import generate_from_yaml


class TestRegistry:
    def test_all_eleven_resources_defined(self) -> None:
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
        assert rows[0]["Security"] == "WPA2"
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
