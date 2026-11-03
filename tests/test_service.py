"""Unit tests for the OmadaService service layer."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from omada.service import OmadaService


@pytest.fixture()
def mock_client() -> MagicMock:
    client = MagicMock()
    client.get_acl_rules.return_value = []
    client.get_ip_groups.return_value = []
    client.get_port_groups.return_value = []
    client.get_networks.return_value = []
    client.get_vlans.return_value = []
    client.get_switch_port_profiles.return_value = []
    client.get_gateway_settings.return_value = {}
    client.get_ssids.return_value = []
    client.get_dhcp_reservations.return_value = []
    client.get_devices.return_value = []
    client.get_device_ports.return_value = []
    client.get_port_forwarding.return_value = []
    client.get_one_to_one_nat.return_value = []
    client.get_alg_settings.return_value = {}
    client.get_static_routes.return_value = []
    client.get_policy_routes.return_value = []
    client.get_site_to_site_vpns.return_value = []
    client.get_remote_access_vpns.return_value = []
    client.get_wireguard.return_value = []
    client.get_vpn_users.return_value = []
    client.get_ssl_vpn.return_value = {}
    client.get_eogre_tunnel.return_value = {}
    client.get_ipsec_failover.return_value = []
    return client


@pytest.fixture()
def service(tmp_path: Path, mock_client: MagicMock) -> OmadaService:
    return OmadaService(
        client=mock_client,
        site_id="site001",
        output_dir=tmp_path,
        site_name="Home Office",
    )


def _empty_data() -> dict:
    return {
        "acl_rules": [],
        "ip_groups": [],
        "port_groups": [],
        "networks": [],
        "vlans": [],
        "switch_port_profiles": [],
        "gateway_settings": {},
        "ssids": [],
        "dhcp_reservations": [],
        "devices": [],
        "device_ports": [],
        "port_forwarding": [],
        "one_to_one_nat": [],
        "alg": {},
        "static_routes": [],
        "policy_routes": [],
        "site_to_site_vpns": [],
        "remote_access_vpns": [],
        "wireguard": [],
        "vpn_users": [],
        "ssl_vpn": {},
        "eogre_tunnel": {},
        "ipsec_failover": [],
    }


class TestOmadaServiceFetchAll:
    def test_fetch_all_returns_all_keys(self, service: OmadaService) -> None:
        data = service.fetch_all()
        assert set(data.keys()) == set(OmadaService.RESOURCE_NAMES)

    def test_fetch_all_handles_partial_failures(self, service: OmadaService) -> None:
        """A failing fetcher should not crash the whole run; result = []."""
        service._client.get_acl_rules.side_effect = Exception("network error")
        service._client.get_ip_groups.return_value = [{"name": "g1"}]
        data = service.fetch_all()
        assert data["acl_rules"] == []
        assert data["ip_groups"] == [{"name": "g1"}]

    def test_fetch_all_logs_error_summary_on_failures(
        self, service: OmadaService,
    ) -> None:
        """When fetches fail, an error summary with resource names is logged."""
        service._client.get_acl_rules.side_effect = Exception("timeout")
        service._client.get_ip_groups.side_effect = Exception("timeout")
        with patch("omada.service.logger") as mock_logger:
            service.fetch_all()
        error_calls = [
            c for c in mock_logger.error.call_args_list
            if "failed to fetch" in str(c)
        ]
        assert len(error_calls) == 1
        summary_msg = str(error_calls[0])
        assert "acl_rules" in summary_msg
        assert "ip_groups" in summary_msg


class TestOmadaServiceExport:
    def test_export_yaml_writes_files(self, service: OmadaService, tmp_path: Path) -> None:
        data = _empty_data()
        paths = service.export_yaml(data)
        for name, path in paths.items():
            assert path.exists(), f"{name}.yaml not created"
            assert path.parent == tmp_path / "Home Office"

    def test_generate_docs_writes_files(self, service: OmadaService, tmp_path: Path) -> None:
        data = _empty_data()
        paths = service.generate_docs(data)
        for name, path in paths.items():
            assert path.exists(), f"{name}.md not created"
            assert path.parent == tmp_path / "Home Office"


class TestOmadaServiceRun:
    def test_run_creates_output_dir(self, tmp_path: Path, mock_client: MagicMock) -> None:
        output_dir = tmp_path / "output"
        service = OmadaService(
            client=mock_client,
            site_id="sid",
            output_dir=output_dir,
        )
        with patch.object(service, "fetch_all", return_value=_empty_data()):
            service.run()
        assert output_dir.is_dir()

    def test_run_returns_yaml_and_doc_paths(self, service: OmadaService) -> None:
        with patch.object(service, "fetch_all", return_value=_empty_data()):
            result = service.run()
        assert "yaml" in result
        assert "docs" in result
        assert len(result["yaml"]) == len(OmadaService.RESOURCE_NAMES)
        assert len(result["docs"]) == len(OmadaService.RESOURCE_NAMES)
        assert all(path.parent.name == "Home Office" for path in result["docs"].values())
        assert all(path.parent == service.site_output_dir for path in result["yaml"].values())


class TestVpnSecretsNeverExported:
    def test_vpn_secrets_redacted_in_yaml_and_markdown(self, tmp_path: Path) -> None:
        from omada.api.openapi_client import OmadaOpenApiClient

        client = OmadaOpenApiClient("https://ctrl", "cid", "token")
        secrets = ["S2S-PSK-123", "SRV-PSK-456", "CLI-PW-789", "WG-PRIV=", "WG-PSK=", "USER-PW",
                   "SSL-USER-PW"]
        responses = {
            "sites/s1/vpn/site-to-site-vpns": [
                {"name": "HQ", "siteVpnType": 1, "preSharedKey": secrets[0]}],
            "sites/s1/vpn/client-to-site-vpn-servers": [
                {"name": "L2TP", "clientVpnType": 0, "encryption": 0, "preSharedKey": secrets[1]}],
            "sites/s1/vpn/client-to-site-vpn-clients": [
                {"name": "Out", "clientVpnType": 1, "clientPassword": secrets[2]}],
            "sites/s1/vpn/wireguards": [{"id": "w", "name": "wg0", "privateKey": secrets[3]}],
            "sites/s1/vpn/wireguard-peers": [
                {"name": "p", "interfaceId": "w", "presharedKey": secrets[4]}],
            "sites/s1/vpn/users": [{"username": "u", "password": secrets[5]}],
            "sites/s1/vpn/ssl-vpn-server/user-groups": [],
            "sites/s1/vpn/ssl-vpn-server/users": [{"name": "s", "password": secrets[6]}],
            "sites/s1/vpn/ssl-vpn-server/resources": [],
            "sites/s1/vpn/ssl-vpn-server/resource-groups": [],
        }
        get_responses = {
            "sites/s1/vpn/ssl-vpn-server/setting": {"status": True},
            "sites/s1/vpn/ssl-vpn-server/radius": [],
        }
        with (
            patch.object(client, "_get_paged", side_effect=lambda path: responses[path]),
            patch.object(client, "_get", side_effect=lambda path: get_responses[path]),
        ):
            data = {
                "site_to_site_vpns": client.get_site_to_site_vpns("s1"),
                "remote_access_vpns": client.get_remote_access_vpns("s1"),
                "wireguard": client.get_wireguard("s1"),
                "vpn_users": client.get_vpn_users("s1"),
                "ssl_vpn": client.get_ssl_vpn("s1"),
            }
        service = OmadaService(client=MagicMock(), site_id="s1", output_dir=tmp_path)
        service.export_yaml(data)
        service.generate_docs(data)

        written = "".join(
            f.read_text(encoding="utf-8") for f in service.site_output_dir.iterdir()
        )
        assert written  # files were produced
        for secret in secrets:
            assert secret not in written
        assert "<redacted>" in written

