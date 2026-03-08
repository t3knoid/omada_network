"""Tests for the resource registry and generate_from_yaml service function."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from omada.registry import REGISTRY, RESOURCES, ResourceDefinition
from omada.service import generate_from_yaml


class TestRegistry:
    def test_all_nine_resources_defined(self) -> None:
        names = {r.name for r in RESOURCES}
        assert names == {
            "acl_rules",
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
