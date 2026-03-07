"""Unit tests for the Omada API client."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
import requests

from omada.api.client import OmadaAPIError, OmadaClient


@pytest.fixture()
def client() -> OmadaClient:
    return OmadaClient(
        base_url="https://192.168.1.1:8043",
        controller_id="abc123",
        token="test-token",
        verify_ssl=False,
    )


def _mock_response(data: dict, status_code: int = 200) -> MagicMock:
    mock = MagicMock(spec=requests.Response)
    mock.status_code = status_code
    mock.json.return_value = data
    mock.raise_for_status = MagicMock()
    return mock


class TestOmadaClientUrlBuilding:
    def test_api_url_basic(self, client: OmadaClient) -> None:
        url = client._api_url("sites/abc/setting/acl/rules")
        assert url == "https://192.168.1.1:8043/abc123/api/v2/sites/abc/setting/acl/rules"

    def test_api_url_strips_leading_slash(self, client: OmadaClient) -> None:
        url = client._api_url("/sites/abc/foo")
        assert "//sites" not in url
        assert "/sites/abc/foo" in url


class TestOmadaClientGet:
    def test_get_success(self, client: OmadaClient) -> None:
        with patch.object(client._session, "get") as mock_get:
            mock_get.return_value = _mock_response(
                {"errorCode": 0, "result": {"data": [{"id": "1"}], "totalRows": 1}}
            )
            result = client._get("sites/s1/setting/networks")
        assert "data" in result

    def test_get_raises_on_error_code(self, client: OmadaClient) -> None:
        with patch.object(client._session, "get") as mock_get:
            mock_get.return_value = _mock_response(
                {"errorCode": 7003, "msg": "Authentication failed"}
            )
            with pytest.raises(OmadaAPIError) as exc_info:
                client._get("sites/s1/setting/networks")
        assert exc_info.value.error_code == 7003

    def test_get_paged_collects_all_pages(self, client: OmadaClient) -> None:
        page1 = {
            "errorCode": 0,
            "result": {"data": [{"id": "1"}, {"id": "2"}], "totalRows": 3},
        }
        page2 = {
            "errorCode": 0,
            "result": {"data": [{"id": "3"}], "totalRows": 3},
        }
        responses = [_mock_response(page1), _mock_response(page2)]
        with patch.object(client._session, "get", side_effect=responses):
            items = client._get_paged("sites/s1/setting/networks", page_size=2)
        assert len(items) == 3
        assert items[2]["id"] == "3"

    def test_get_paged_single_page(self, client: OmadaClient) -> None:
        resp = {
            "errorCode": 0,
            "result": {"data": [{"id": "1"}], "totalRows": 1},
        }
        with patch.object(
            client._session, "get", return_value=_mock_response(resp)
        ):
            items = client._get_paged("sites/s1/setting/networks")
        assert items == [{"id": "1"}]

    def test_get_paged_stops_at_max_pages(self, client: OmadaClient) -> None:
        """A lying API that never reports completion must stop at max_pages."""
        # Each response claims totalRows=9999 but only returns 1 item
        infinite_page = {
            "errorCode": 0,
            "result": {"data": [{"id": "x"}], "totalRows": 9999},
        }
        with patch.object(
            client._session, "get", return_value=_mock_response(infinite_page)
        ):
            items = client._get_paged(
                "sites/s1/setting/networks", page_size=1, max_pages=3
            )
        # Should have stopped after 3 pages (3 items) instead of looping forever
        assert len(items) == 3


class TestOmadaClientResourceMethods:
    def _patch_paged(self, client: OmadaClient, return_value: list):
        return patch.object(client, "_get_paged", return_value=return_value)

    def _patch_get(self, client: OmadaClient, return_value):
        return patch.object(client, "_get", return_value=return_value)

    def test_get_acl_rules(self, client: OmadaClient) -> None:
        expected = [{"name": "rule1"}]
        with self._patch_paged(client, expected):
            result = client.get_acl_rules("site1")
        assert result == expected

    def test_get_ip_groups(self, client: OmadaClient) -> None:
        expected = [{"name": "group1", "ipList": ["10.0.0.1"]}]
        with self._patch_paged(client, expected):
            result = client.get_ip_groups("site1")
        assert result == expected

    def test_get_port_groups(self, client: OmadaClient) -> None:
        expected = [{"name": "http", "portList": [80, 443]}]
        with self._patch_paged(client, expected):
            result = client.get_port_groups("site1")
        assert result == expected

    def test_get_networks(self, client: OmadaClient) -> None:
        expected = [{"name": "LAN", "vlanId": 10}]
        with self._patch_paged(client, expected):
            result = client.get_networks("site1")
        assert result == expected

    def test_get_vlans_filters_by_vlan_id(self, client: OmadaClient) -> None:
        all_nets = [
            {"name": "LAN", "vlanId": 10},
            {"name": "Management", "vlanId": None},
        ]
        with self._patch_paged(client, all_nets):
            vlans = client.get_vlans("site1")
        # Only the network with vlanId should be returned
        assert all(v.get("vlanId") is not None for v in vlans)
        assert len(vlans) == 1

    def test_get_vlans_returns_all_when_no_vlan_ids(self, client: OmadaClient) -> None:
        all_nets = [{"name": "LAN"}, {"name": "Mgmt"}]
        with self._patch_paged(client, all_nets):
            vlans = client.get_vlans("site1")
        assert vlans == all_nets

    def test_get_switch_port_profiles(self, client: OmadaClient) -> None:
        expected = [{"name": "default"}]
        with self._patch_paged(client, expected):
            result = client.get_switch_port_profiles("site1")
        assert result == expected

    def test_get_gateway_settings(self, client: OmadaClient) -> None:
        expected = {"wanMode": "DHCP"}
        with self._patch_get(client, expected):
            result = client.get_gateway_settings("site1")
        assert result == expected

    def test_get_ssids(self, client: OmadaClient) -> None:
        wlans = [{"id": "w1", "name": "Main"}]
        ssids = [{"ssid": "HomeNetwork", "enable": True}]
        with patch.object(client, "_get_paged", side_effect=[wlans, ssids]):
            result = client.get_ssids("site1")
        assert result[0]["wlanName"] == "Main"
        assert result[0]["ssid"] == "HomeNetwork"

    def test_get_ssids_fallback_flat_endpoint(self, client: OmadaClient) -> None:
        """When per-WLAN lookup fails, a flat endpoint should be tried."""
        flat_ssids = [{"ssid": "Guest"}]
        # First call returns empty wlans, second is the flat fallback
        with patch.object(client, "_get_paged", side_effect=[[], flat_ssids]):
            result = client.get_ssids("site1")
        assert result == flat_ssids

    def test_get_dhcp_reservations_direct(self, client: OmadaClient) -> None:
        expected = [{"ip": "192.168.1.100", "mac": "aa:bb:cc:dd:ee:ff"}]
        with self._patch_paged(client, expected):
            result = client.get_dhcp_reservations("site1")
        assert result == expected

    def test_get_dhcp_reservations_per_network_fallback(
        self, client: OmadaClient
    ) -> None:
        networks = [{"id": "net1", "name": "LAN"}]
        reservations = [{"ip": "10.0.0.50", "mac": "11:22:33:44:55:66"}]

        side_effects = [
            OmadaAPIError(404, "not found"),  # direct endpoint fails
            networks,  # get_networks call
            reservations,  # per-network reservation
        ]
        with patch.object(client, "_get_paged", side_effect=side_effects):
            result = client.get_dhcp_reservations("site1")
        assert result[0]["networkName"] == "LAN"
