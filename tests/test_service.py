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
    return client


@pytest.fixture()
def service(tmp_path: Path, mock_client: MagicMock) -> OmadaService:
    return OmadaService(
        client=mock_client,
        site_id="site001",
        output_dir=tmp_path,
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

    def test_generate_docs_writes_files(self, service: OmadaService, tmp_path: Path) -> None:
        data = _empty_data()
        paths = service.generate_docs(data)
        for name, path in paths.items():
            assert path.exists(), f"{name}.md not created"


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
