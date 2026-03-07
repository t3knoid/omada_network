"""Unit tests for YAML exporter and Markdown generator."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from omada.exporters.markdown_generator import MarkdownGenerator, _table, _column_header
from omada.exporters.yaml_exporter import YamlExporter


# ---------------------------------------------------------------------------
# YAML Exporter
# ---------------------------------------------------------------------------

class TestYamlExporter:
    def test_exports_list(self, tmp_path: Path) -> None:
        exporter = YamlExporter(tmp_path)
        data = [{"name": "rule1", "policy": "accept"}]
        path = exporter.export("acl_rules", data)
        assert path.exists()
        loaded = yaml.safe_load(path.read_text())
        assert loaded == data

    def test_exports_dict(self, tmp_path: Path) -> None:
        exporter = YamlExporter(tmp_path)
        data = {"wanMode": "DHCP", "wan1Ip": "1.2.3.4"}
        path = exporter.export("gateway_settings", data)
        loaded = yaml.safe_load(path.read_text())
        assert loaded == data

    def test_sort_keys_true(self, tmp_path: Path) -> None:
        """YAML keys must be sorted alphabetically for deterministic diffs."""
        exporter = YamlExporter(tmp_path)
        data = {"z_key": 1, "a_key": 2, "m_key": 3}
        path = exporter.export("test", data)
        raw = path.read_text()
        # a_key should appear before z_key in the file
        assert raw.index("a_key") < raw.index("z_key")

    def test_creates_output_dir(self, tmp_path: Path) -> None:
        target = tmp_path / "nested" / "output"
        exporter = YamlExporter(target)
        exporter.export("test", [{"a": 1}])
        assert target.is_dir()

    def test_export_all(self, tmp_path: Path) -> None:
        exporter = YamlExporter(tmp_path)
        data = {
            "acl_rules": [{"name": "r1"}],
            "ip_groups": [{"name": "g1"}],
        }
        paths = exporter.export_all(data)
        assert set(paths.keys()) == {"acl_rules", "ip_groups"}
        for p in paths.values():
            assert p.exists()

    def test_unicode_content(self, tmp_path: Path) -> None:
        exporter = YamlExporter(tmp_path)
        data = [{"name": "réseau-principal", "description": "日本語テスト"}]
        path = exporter.export("networks", data)
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert loaded[0]["name"] == "réseau-principal"


# ---------------------------------------------------------------------------
# Markdown Generator helpers
# ---------------------------------------------------------------------------

class TestMarkdownHelpers:
    def test_column_header_converts_snake_case(self) -> None:
        assert _column_header("vlan_id") == "Vlan Id"
        assert _column_header("ip_address") == "Ip Address"

    def test_table_empty(self) -> None:
        result = _table([])
        assert "_No records found._" in result

    def test_table_single_row(self) -> None:
        result = _table([{"name": "LAN", "vlanId": 10}])
        assert "LAN" in result
        assert "10" in result
        assert "| ---" in result

    def test_table_pipe_escaping(self) -> None:
        result = _table([{"data": "a|b"}])
        assert "a\\|b" in result

    def test_table_bool_rendering(self) -> None:
        result = _table([{"enabled": True, "disabled": False}])
        assert "✓" in result
        assert "✗" in result


# ---------------------------------------------------------------------------
# Markdown Generator – full resource rendering
# ---------------------------------------------------------------------------

class TestMarkdownGenerator:
    def test_generate_acl_rules(self, tmp_path: Path) -> None:
        gen = MarkdownGenerator(tmp_path)
        data = [
            {
                "name": "Block Telnet",
                "status": False,
                "policy": "drop",
                "protocol": "TCP",
                "srcType": "IP",
                "srcIp": "any",
                "dstType": "IP",
                "dstIp": "any",
                "dstPort": "23",
            }
        ]
        path = gen.generate("acl_rules", data)
        content = path.read_text()
        assert "# ACL Rules" in content
        assert "Block Telnet" in content
        assert "drop" in content

    def test_generate_ip_groups(self, tmp_path: Path) -> None:
        gen = MarkdownGenerator(tmp_path)
        data = [{"name": "RFC1918", "type": "network", "ipList": ["10.0.0.0/8"]}]
        path = gen.generate("ip_groups", data)
        assert "RFC1918" in path.read_text()

    def test_generate_networks(self, tmp_path: Path) -> None:
        gen = MarkdownGenerator(tmp_path)
        data = [
            {
                "name": "LAN",
                "purpose": "user",
                "networkIp": "192.168.1.0",
                "prefixLen": 24,
                "vlanId": 1,
                "dhcpEnable": True,
            }
        ]
        path = gen.generate("networks", data)
        content = path.read_text()
        assert "LAN" in content
        assert "192.168.1.0" in content

    def test_generate_vlans(self, tmp_path: Path) -> None:
        gen = MarkdownGenerator(tmp_path)
        data = [{"name": "IoT", "vlanId": 20, "networkIp": "10.20.0.0", "prefixLen": 24}]
        path = gen.generate("vlans", data)
        assert "20" in path.read_text()

    def test_generate_ssids(self, tmp_path: Path) -> None:
        gen = MarkdownGenerator(tmp_path)
        data = [
            {"wlanName": "Home", "ssid": "MyWifi", "security": "WPA2", "enable": True}
        ]
        path = gen.generate("ssids", data)
        assert "MyWifi" in path.read_text()

    def test_generate_dhcp_reservations(self, tmp_path: Path) -> None:
        gen = MarkdownGenerator(tmp_path)
        data = [
            {
                "networkName": "LAN",
                "ip": "192.168.1.50",
                "mac": "aa:bb:cc:dd:ee:ff",
                "name": "printer",
            }
        ]
        path = gen.generate("dhcp_reservations", data)
        content = path.read_text()
        assert "192.168.1.50" in content
        assert "printer" in content

    def test_generate_gateway_settings(self, tmp_path: Path) -> None:
        gen = MarkdownGenerator(tmp_path)
        data = {"wanMode": "DHCP", "wan1Ip": "203.0.113.1"}
        path = gen.generate("gateway_settings", data)
        assert "DHCP" in path.read_text()

    def test_generate_all(self, tmp_path: Path) -> None:
        gen = MarkdownGenerator(tmp_path)
        data = {
            "acl_rules": [{"name": "r1"}],
            "ip_groups": [],
        }
        paths = gen.generate_all(data)
        assert set(paths.keys()) == {"acl_rules", "ip_groups"}
        for p in paths.values():
            assert p.exists()

    def test_unknown_resource_fallback(self, tmp_path: Path) -> None:
        gen = MarkdownGenerator(tmp_path)
        path = gen.generate("custom_resource", [{"some_key": "value"}])
        content = path.read_text()
        assert "Custom Resource" in content
        # Raw snake_case keys must be converted to Title Case in the table header
        assert "Some Key" in content
        assert "some_key" not in content

    def test_rows_sorted_by_name(self, tmp_path: Path) -> None:
        """Rows must be sorted alphabetically by the configured sort_key."""
        gen = MarkdownGenerator(tmp_path)
        data = [
            {"name": "Zulu Rule", "policy": "accept"},
            {"name": "Alpha Rule", "policy": "drop"},
        ]
        path = gen.generate("acl_rules", data)
        content = path.read_text()
        # Alpha Rule must appear before Zulu Rule
        assert content.index("Alpha Rule") < content.index("Zulu Rule")

    def test_ssids_sorted_by_ssid_column(self, tmp_path: Path) -> None:
        gen = MarkdownGenerator(tmp_path)
        data = [
            {"ssid": "Zulu-Net", "wlanName": "home"},
            {"ssid": "Alpha-Net", "wlanName": "home"},
        ]
        path = gen.generate("ssids", data)
        content = path.read_text()
        assert content.index("Alpha-Net") < content.index("Zulu-Net")

