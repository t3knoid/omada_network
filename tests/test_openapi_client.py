"""Unit tests for the Omada Open API client."""

from __future__ import annotations

import logging
from unittest.mock import MagicMock, patch

import pytest
import requests

from omada.api.openapi_client import (
    OmadaAPIError,
    OmadaOpenApiClient,
    OpenApiLoginResult,
    discover_controller_id,
    openapi_auth_code_login,
    openapi_discover_site,
    openapi_discover_site_id,
    openapi_login,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def openapi_client() -> OmadaOpenApiClient:
    return OmadaOpenApiClient(
        base_url="https://192.168.1.1",
        omadac_id="ctrl-001",
        access_token="test-access-token",
        verify_ssl=False,
    )


def _mock_response(data: dict, status_code: int = 200) -> MagicMock:
    mock = MagicMock(spec=requests.Response)
    mock.status_code = status_code
    mock.json.return_value = data
    mock.raise_for_status = MagicMock()
    return mock


# ---------------------------------------------------------------------------
# Auth tests
# ---------------------------------------------------------------------------

class TestOpenApiLogin:
    def test_successful_login(self) -> None:
        token_resp = {
            "errorCode": 0,
            "msg": "Success.",
            "result": {
                "accessToken": "abc123",
                "tokenType": "Bearer",
                "expiresIn": 3600,
            },
        }
        with patch("omada.api.openapi_client._make_session") as mock_session_factory:
            mock_sess = MagicMock(spec=requests.Session)
            mock_sess.post.return_value = _mock_response(token_resp)
            mock_sess.headers = {}
            mock_session_factory.return_value = mock_sess

            result = openapi_login(
                "https://192.168.1.1",
                "ctrl-001",
                "my-client-id",
                "my-client-secret",
                verify_ssl=False,
            )

        assert isinstance(result, OpenApiLoginResult)
        assert result.access_token == "abc123"
        assert result.base_url == "https://192.168.1.1"

    def test_login_error_code(self) -> None:
        token_resp = {"errorCode": -30109, "msg": "Invalid client ID or secret."}
        with patch("omada.api.openapi_client._make_session") as mock_session_factory:
            mock_sess = MagicMock(spec=requests.Session)
            mock_sess.post.return_value = _mock_response(token_resp)
            mock_session_factory.return_value = mock_sess

            with pytest.raises(OmadaAPIError) as exc_info:
                openapi_login(
                    "https://192.168.1.1",
                    "ctrl-001",
                    "bad-id",
                    "bad-secret",
                )
        assert exc_info.value.error_code == -30109

    def test_login_missing_access_token(self) -> None:
        token_resp = {"errorCode": 0, "result": {}}
        with patch("omada.api.openapi_client._make_session") as mock_session_factory:
            mock_sess = MagicMock(spec=requests.Session)
            mock_sess.post.return_value = _mock_response(token_resp)
            mock_session_factory.return_value = mock_sess

            with pytest.raises(RuntimeError, match="no accessToken"):
                openapi_login(
                    "https://192.168.1.1",
                    "ctrl-001",
                    "id",
                    "secret",
                )


class TestOpenApiAuthCodeLogin:
    def test_successful_auth_code_login(self) -> None:
        login_resp = {
            "errorCode": 0,
            "result": {"csrfToken": "csrf-123", "sessionId": "sess-abc"},
        }
        code_resp = {
            "errorCode": 0,
            "result": "OC-my-auth-code",
        }
        token_resp = {
            "errorCode": 0,
            "result": {
                "accessToken": "AT-abc123",
                "tokenType": "Bearer",
                "expiresIn": 7200,
                "refreshToken": "RT-xyz789",
            },
        }
        with patch("omada.api.openapi_client._make_session") as mock_session_factory:
            mock_sess = MagicMock(spec=requests.Session)
            mock_sess.post.side_effect = [
                _mock_response(login_resp),
                _mock_response(code_resp),
                _mock_response(token_resp),
            ]
            mock_sess.headers = {}
            mock_sess.cookies = MagicMock()
            mock_session_factory.return_value = mock_sess

            result = openapi_auth_code_login(
                "https://192.168.1.1",
                "ctrl-001",
                "my-client-id",
                "my-client-secret",
                "admin",
                "password123",
                verify_ssl=False,
            )

        assert isinstance(result, OpenApiLoginResult)
        assert result.access_token == "AT-abc123"
        assert result.base_url == "https://192.168.1.1"
        assert mock_sess.post.call_count == 3

        # Verify query params are consistent across all three steps
        step1_call = mock_sess.post.call_args_list[0]
        assert step1_call.kwargs["params"] == {
            "client_id": "my-client-id",
            "omadacId": "ctrl-001",
        }
        step2_call = mock_sess.post.call_args_list[1]
        assert step2_call.kwargs["params"] == {
            "client_id": "my-client-id",
            "omadacId": "ctrl-001",
            "response_type": "code",
        }
        step3_call = mock_sess.post.call_args_list[2]
        assert step3_call.kwargs["params"] == {
            "grant_type": "authorization_code",
            "code": "OC-my-auth-code",
        }

    def test_auth_code_login_step1_error(self) -> None:
        login_resp = {"errorCode": -30109, "msg": "Invalid credentials"}
        with patch("omada.api.openapi_client._make_session") as mock_session_factory:
            mock_sess = MagicMock(spec=requests.Session)
            mock_sess.post.return_value = _mock_response(login_resp)
            mock_session_factory.return_value = mock_sess

            with pytest.raises(OmadaAPIError) as exc_info:
                openapi_auth_code_login(
                    "https://192.168.1.1",
                    "ctrl-001",
                    "id",
                    "secret",
                    "admin",
                    "wrong",
                )
        assert exc_info.value.error_code == -30109


class TestDiscoverControllerId:
    def test_successful_discovery(self) -> None:
        resp = {
            "errorCode": 0,
            "result": {"omadacId": "ctrl-discovered"},
        }
        with patch("omada.api.openapi_client._make_session") as mock_session_factory:
            mock_sess = MagicMock(spec=requests.Session)
            mock_sess.get.return_value = _mock_response(resp)
            mock_session_factory.return_value = mock_sess

            cid = discover_controller_id(
                "https://192.168.1.1", verify_ssl=False,
            )
        assert cid == "ctrl-discovered"

    def test_discovery_error_code(self) -> None:
        resp = {"errorCode": -1, "msg": "Unknown error"}
        with patch("omada.api.openapi_client._make_session") as mock_session_factory:
            mock_sess = MagicMock(spec=requests.Session)
            mock_sess.get.return_value = _mock_response(resp)
            mock_session_factory.return_value = mock_sess

            with pytest.raises(OmadaAPIError):
                discover_controller_id("https://192.168.1.1")

    def test_discovery_missing_omadac_id(self) -> None:
        resp = {"errorCode": 0, "result": {}}
        with patch("omada.api.openapi_client._make_session") as mock_session_factory:
            mock_sess = MagicMock(spec=requests.Session)
            mock_sess.get.return_value = _mock_response(resp)
            mock_session_factory.return_value = mock_sess

            with pytest.raises(RuntimeError, match="omadacId"):
                discover_controller_id("https://192.168.1.1")


# ---------------------------------------------------------------------------
# Site discovery tests
# ---------------------------------------------------------------------------

class TestOpenApiDiscoverSite:
    def test_site_discovery_returns_id_and_name(self) -> None:
        resp = {
            "errorCode": 0,
            "result": {
                "data": [{"name": "Home", "siteId": "site-002"}],
            },
        }
        mock_sess = MagicMock(spec=requests.Session)
        mock_sess.get.return_value = _mock_response(resp)

        site_id, site_name = openapi_discover_site(
            "https://192.168.1.1", "ctrl-001", mock_sess,
        )

        assert site_id == "site-002"
        assert site_name == "Home"

    def test_single_site_auto_select(self) -> None:
        resp = {
            "errorCode": 0,
            "result": {
                "data": [{"name": "Default", "siteId": "site-001"}],
            },
        }
        mock_sess = MagicMock(spec=requests.Session)
        mock_sess.get.return_value = _mock_response(resp)

        site_id = openapi_discover_site_id(
            "https://192.168.1.1", "ctrl-001", mock_sess,
        )
        assert site_id == "site-001"

    def test_select_by_name(self) -> None:
        resp = {
            "errorCode": 0,
            "result": {
                "data": [
                    {"name": "Office", "siteId": "site-001"},
                    {"name": "Home", "siteId": "site-002"},
                ],
            },
        }
        mock_sess = MagicMock(spec=requests.Session)
        mock_sess.get.return_value = _mock_response(resp)

        site_id = openapi_discover_site_id(
            "https://192.168.1.1", "ctrl-001", mock_sess,
            site_name="Home",
        )
        assert site_id == "site-002"

    def test_name_not_found(self) -> None:
        resp = {
            "errorCode": 0,
            "result": {
                "data": [{"name": "Office", "siteId": "site-001"}],
            },
        }
        mock_sess = MagicMock(spec=requests.Session)
        mock_sess.get.return_value = _mock_response(resp)

        with pytest.raises(RuntimeError, match="No site named"):
            openapi_discover_site_id(
                "https://192.168.1.1", "ctrl-001", mock_sess,
                site_name="NoSuchSite",
            )

    def test_multiple_sites_no_name(self) -> None:
        resp = {
            "errorCode": 0,
            "result": {
                "data": [
                    {"name": "Office", "siteId": "site-001"},
                    {"name": "Home", "siteId": "site-002"},
                ],
            },
        }
        mock_sess = MagicMock(spec=requests.Session)
        mock_sess.get.return_value = _mock_response(resp)

        with pytest.raises(RuntimeError, match="Multiple sites"):
            openapi_discover_site_id(
                "https://192.168.1.1", "ctrl-001", mock_sess,
            )

    def test_no_sites(self) -> None:
        resp = {"errorCode": 0, "result": {"data": []}}
        mock_sess = MagicMock(spec=requests.Session)
        mock_sess.get.return_value = _mock_response(resp)

        with pytest.raises(RuntimeError, match="No sites found"):
            openapi_discover_site_id(
                "https://192.168.1.1", "ctrl-001", mock_sess,
            )

    def test_result_as_list(self) -> None:
        resp = {
            "errorCode": 0,
            "result": [{"name": "Default", "siteId": "site-001"}],
        }
        mock_sess = MagicMock(spec=requests.Session)
        mock_sess.get.return_value = _mock_response(resp)

        site_id = openapi_discover_site_id(
            "https://192.168.1.1", "ctrl-001", mock_sess,
        )
        assert site_id == "site-001"


# ---------------------------------------------------------------------------
# URL building tests
# ---------------------------------------------------------------------------

class TestOpenApiClientUrl:
    def test_api_url_v1(self, openapi_client: OmadaOpenApiClient) -> None:
        url = openapi_client._api_url("sites/s1/acls/osg-acls")
        assert url == "https://192.168.1.1/openapi/v1/ctrl-001/sites/s1/acls/osg-acls"

    def test_api_url_v2(self, openapi_client: OmadaOpenApiClient) -> None:
        url = openapi_client._api_url("sites/s1/lan-profiles", api_version="v2")
        assert url == "https://192.168.1.1/openapi/v2/ctrl-001/sites/s1/lan-profiles"

    def test_api_url_strips_leading_slash(self, openapi_client: OmadaOpenApiClient) -> None:
        url = openapi_client._api_url("/sites/s1/foo")
        assert "//sites" not in url


# ---------------------------------------------------------------------------
# GET / pagination tests
# ---------------------------------------------------------------------------

class TestOpenApiClientGet:
    def test_get_success(self, openapi_client: OmadaOpenApiClient) -> None:
        with patch.object(openapi_client._session, "get") as mock_get:
            mock_get.return_value = _mock_response(
                {"errorCode": 0, "result": [{"id": "1"}]}
            )
            result = openapi_client._get("sites/s1/profiles/groups/0")
        assert result == [{"id": "1"}]

    def test_get_raises_on_error(self, openapi_client: OmadaOpenApiClient) -> None:
        with patch.object(openapi_client._session, "get") as mock_get:
            mock_get.return_value = _mock_response(
                {"errorCode": -1600, "msg": "Unsupported"}
            )
            with pytest.raises(OmadaAPIError) as exc_info:
                openapi_client._get("sites/s1/bad/path")
        assert exc_info.value.error_code == -1600

    def test_get_paged_single_page(self, openapi_client: OmadaOpenApiClient) -> None:
        resp = {
            "errorCode": 0,
            "result": {"data": [{"id": "1"}, {"id": "2"}], "totalRows": 2},
        }
        with patch.object(
            openapi_client._session, "get", return_value=_mock_response(resp),
        ):
            items = openapi_client._get_paged("sites/s1/acls/osg-acls")
        assert len(items) == 2

    def test_get_paged_multiple_pages(self, openapi_client: OmadaOpenApiClient) -> None:
        page1 = {
            "errorCode": 0,
            "result": {"data": [{"id": "1"}], "totalRows": 2},
        }
        page2 = {
            "errorCode": 0,
            "result": {"data": [{"id": "2"}], "totalRows": 2},
        }
        with patch.object(
            openapi_client._session, "get",
            side_effect=[_mock_response(page1), _mock_response(page2)],
        ):
            items = openapi_client._get_paged(
                "sites/s1/acls/osg-acls", page_size=1,
            )
        assert len(items) == 2

    def test_get_paged_result_is_list(self, openapi_client: OmadaOpenApiClient) -> None:
        resp = {"errorCode": 0, "result": [{"id": "1"}]}
        with patch.object(
            openapi_client._session, "get", return_value=_mock_response(resp),
        ):
            items = openapi_client._get_paged("sites/s1/foo")
        assert items == [{"id": "1"}]

    def test_get_paged_stops_at_max_pages(self, openapi_client: OmadaOpenApiClient) -> None:
        infinite = {
            "errorCode": 0,
            "result": {"data": [{"id": "x"}], "totalRows": 9999},
        }
        with patch.object(
            openapi_client._session, "get",
            return_value=_mock_response(infinite),
        ):
            items = openapi_client._get_paged(
                "sites/s1/foo", page_size=1, max_pages=3,
            )
        assert len(items) == 3


# ---------------------------------------------------------------------------
# Resource method tests
# ---------------------------------------------------------------------------

class TestOpenApiResourceMethods:
    def test_get_acl_rules(self, openapi_client: OmadaOpenApiClient) -> None:
        gw = [{"name": "rule1", "id": "1"}]
        sw = [{"name": "rule2", "id": "2"}]
        with patch.object(openapi_client, "_get_paged") as mock:
            mock.side_effect = [gw, sw, []]  # gateway, switch, eap
            result = openapi_client.get_acl_rules("site-001")
        assert len(result) == 2
        assert result[0]["aclType"] == "gateway"
        assert result[1]["aclType"] == "switch"

    def test_get_acl_rules_gateway_fails(self, openapi_client: OmadaOpenApiClient) -> None:
        with patch.object(openapi_client, "_get_paged") as mock:
            mock.side_effect = [
                OmadaAPIError(-1600, "Unsupported"),
                [{"name": "sw_rule"}],
                [],
            ]
            result = openapi_client.get_acl_rules("site-001")
        assert len(result) == 1
        assert result[0]["aclType"] == "switch"

    def test_get_ip_groups(self, openapi_client: OmadaOpenApiClient) -> None:
        groups = [{"name": "LAN", "type": 0}]
        with patch.object(openapi_client, "_get") as mock:
            mock.return_value = groups
            result = openapi_client.get_ip_groups("site-001")
        assert result == groups

    def test_get_ip_groups_fallback(self, openapi_client: OmadaOpenApiClient) -> None:
        all_groups = [
            {"name": "LAN", "type": 0},
            {"name": "HTTP", "type": 1},
        ]
        with patch.object(openapi_client, "_get") as mock:
            mock.side_effect = [
                OmadaAPIError(-1600, "Unsupported"),
                all_groups,
            ]
            result = openapi_client.get_ip_groups("site-001")
        assert len(result) == 1
        assert result[0]["type"] == 0

    def test_get_port_groups(self, openapi_client: OmadaOpenApiClient) -> None:
        groups = [{"name": "HTTP", "type": 1}]
        with patch.object(openapi_client, "_get") as mock:
            mock.return_value = groups
            result = openapi_client.get_port_groups("site-001")
        assert result == groups

    def test_get_port_groups_fallback(self, openapi_client: OmadaOpenApiClient) -> None:
        all_groups = [
            {"name": "LAN", "type": 0},
            {"name": "HTTP", "type": 1},
        ]
        with patch.object(openapi_client, "_get") as mock:
            mock.side_effect = [
                OmadaAPIError(-1600, "Unsupported"),
                all_groups,
            ]
            result = openapi_client.get_port_groups("site-001")
        assert len(result) == 1
        assert result[0]["type"] == 1

    def test_get_networks(self, openapi_client: OmadaOpenApiClient) -> None:
        nets = [{"name": "LAN", "vlanId": 1}]
        with patch.object(openapi_client, "_get") as mock:
            mock.return_value = nets
            result = openapi_client.get_networks("site-001")
        assert result == nets

    def test_get_networks_fallback_to_paged(self, openapi_client: OmadaOpenApiClient) -> None:
        nets = [{"name": "LAN", "vlanId": 1}]
        with patch.object(openapi_client, "_get") as mock_get, \
             patch.object(openapi_client, "_get_paged") as mock_paged:
            mock_get.side_effect = OmadaAPIError(-1600, "Unsupported")
            mock_paged.return_value = nets
            result = openapi_client.get_networks("site-001")
        assert result == nets

    def test_get_vlans_filters_by_vlanid(self, openapi_client: OmadaOpenApiClient) -> None:
        nets = [
            {"name": "LAN", "vlanId": 1},
            {"name": "Guest", "vlanId": 100},
            {"name": "NoVlan"},
        ]
        with patch.object(openapi_client, "get_networks") as mock:
            mock.return_value = nets
            result = openapi_client.get_vlans("site-001")
        assert len(result) == 2
        assert result[0]["vlanId"] == 1

    def test_get_devices(self, openapi_client: OmadaOpenApiClient) -> None:
        devices = [{"name": "Switch 1", "mac": "AA-BB-CC-DD-EE-FF"}]
        with patch.object(openapi_client, "_get_paged", return_value=devices) as mock:
            result = openapi_client.get_devices("site-001")

        assert result == devices
        mock.assert_called_once_with("sites/site-001/devices")

    def test_get_device_ports_switch_uses_overview(
        self, openapi_client: OmadaOpenApiClient,
    ) -> None:
        devices = [{"name": "Switch 1", "type": "switch", "mac": "AA-BB", "model": "SG2008"}]
        overview = [
            {"switchMac": "aa:bb", "port": 2, "portName": "Port2", "tagName": "NAS"},
            {"switchMac": "AA-BB", "port": 1, "portName": "Port1", "operation": "SWITCHING"},
            {"switchMac": "CC-DD", "port": 1, "portName": "Other"},
        ]
        with (
            patch.object(openapi_client, "_get_paged", side_effect=[devices, overview]) as mock_paged,
            patch.object(openapi_client, "_get") as mock_get,
        ):
            result = openapi_client.get_device_ports("site-001")

        assert mock_paged.call_args_list[1].args == ("sites/site-001/switches/ports/overview",)
        mock_get.assert_not_called()
        assert [p["port"] for p in result] == [1, 2]
        assert result[0]["deviceName"] == "Switch 1"
        assert result[0]["deviceMac"] == "AA-BB"
        assert result[0]["deviceType"] == "switch"
        assert result[0]["deviceModel"] == "SG2008"
        assert result[1]["tagName"] == "NAS"

    def test_get_device_ports_switch_falls_back_when_overview_fails(
        self, openapi_client: OmadaOpenApiClient,
    ) -> None:
        devices = [{"name": "Switch 1", "type": "switch", "mac": "AA-BB"}]
        switch_info = {"mac": "AA-BB", "portList": [
            {"port": 2, "name": "Port2"},
            {"port": 1, "name": "Port1", "profileName": "Default"},
        ]}
        with (
            patch.object(
                openapi_client, "_get_paged",
                side_effect=[devices, OmadaAPIError(-1600, "Unsupported")],
            ),
            patch.object(openapi_client, "_get", return_value=switch_info) as mock_get,
        ):
            result = openapi_client.get_device_ports("site-001")

        mock_get.assert_called_once_with("sites/site-001/switches/AA-BB")
        assert [p["port"] for p in result] == [1, 2]
        assert result[0]["profileName"] == "Default"

    def test_get_device_ports_gateway_merges_sources(
        self, openapi_client: OmadaOpenApiClient,
    ) -> None:
        devices = [{"name": "GW", "type": "gateway", "mac": "11-22"}]
        responses = {
            "sites/site-001/gateways/11-22": {"portConfigs": [
                {"port": 1, "linkSpeed": 0, "status": 1},
                {"port": 2, "linkSpeed": 3, "status": 0},
            ]},
            "sites/site-001/gateways/11-22/ports": {"osgPortInfos": [
                {"port": 1, "name": "WAN", "type": 0, "mode": 0},
                {"port": 2, "name": "WAN/LAN1", "type": 1, "mode": 1},
            ]},
            "sites/site-001/gateways/11-22/wan-status": [
                {"port": 1, "name": "WAN", "status": 1, "speed": 3, "duplex": 2},
                {"port": 2, "name": "WAN/LAN1", "status": 0},
            ],
        }
        with (
            patch.object(openapi_client, "_get_paged", return_value=devices),
            patch.object(openapi_client, "_get", side_effect=responses.__getitem__),
        ):
            result = openapi_client.get_device_ports("site-001")

        assert len(result) == 2
        assert result[0]["name"] == "WAN"
        assert result[0]["linkSpeed"] == 0
        assert result[0]["status"] == 1  # enabled flag from portConfigs is kept
        assert result[0]["portStatus"] == {"linkStatus": 1, "linkSpeed": 3, "duplex": 2}
        assert result[1]["name"] == "WAN/LAN1"
        assert result[1]["status"] == 0
        assert result[1]["portStatus"]["linkStatus"] == 0

    def test_get_device_ports_gateway_partial_failure(
        self, openapi_client: OmadaOpenApiClient,
    ) -> None:
        devices = [{"name": "GW", "type": "gateway", "mac": "11-22"}]

        def fake_get(path: str) -> dict:
            if path.endswith(("/ports", "/wan-status")):
                raise OmadaAPIError(-1600, "Unsupported")
            return {"portConfigs": [{"port": 1, "status": 1}]}

        with (
            patch.object(openapi_client, "_get_paged", return_value=devices),
            patch.object(openapi_client, "_get", side_effect=fake_get),
        ):
            result = openapi_client.get_device_ports("site-001")

        assert result == [{
            "deviceName": "GW", "deviceMac": "11-22", "deviceType": "gateway",
            "deviceModel": "", "port": 1, "status": 1,
        }]

    def test_get_device_ports_gateway_all_sources_fail(
        self,
        openapi_client: OmadaOpenApiClient,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        devices = [{"name": "GW", "type": "gateway", "mac": "11-22"}]
        with (
            patch.object(openapi_client, "_get_paged", return_value=devices),
            patch.object(openapi_client, "_get", side_effect=OmadaAPIError(-1, "x")),
            caplog.at_level(logging.WARNING),
        ):
            result = openapi_client.get_device_ports("site-001")

        assert result == []
        assert "Unable to enumerate ports for gateway GW" in caplog.text

    def test_get_device_ports_skips_aps_and_missing_mac(
        self, openapi_client: OmadaOpenApiClient,
    ) -> None:
        devices = [
            {"name": "AP", "type": "ap", "mac": "AA"},
            {"name": "Switch without MAC", "type": "switch"},
        ]
        with (
            patch.object(openapi_client, "_get_paged", side_effect=[devices, []]),
            patch.object(openapi_client, "_get") as mock_get,
        ):
            result = openapi_client.get_device_ports("site-001")

        assert result == []
        mock_get.assert_not_called()

    def test_get_device_ports_skips_overview_without_switches(
        self, openapi_client: OmadaOpenApiClient,
    ) -> None:
        devices = [{"name": "AP", "type": "ap", "mac": "AA"}]
        with patch.object(openapi_client, "_get_paged", return_value=devices) as mock_paged:
            openapi_client.get_device_ports("site-001")

        mock_paged.assert_called_once_with("sites/site-001/devices")

    def test_get_device_ports_continues_when_device_fails(
        self,
        openapi_client: OmadaOpenApiClient,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        devices = [
            {"name": "Switch 1", "type": "switch", "mac": "AA"},
            {"name": "Switch 2", "type": "switch", "mac": "BB"},
        ]

        def fake_get(path: str) -> dict:
            if path.endswith("/AA"):
                raise OmadaAPIError(-1600, "Unsupported")
            return {"portList": [{"port": 1}]}

        with (
            patch.object(
                openapi_client, "_get_paged",
                side_effect=[devices, OmadaAPIError(-1600, "Unsupported")],
            ),
            patch.object(openapi_client, "_get", side_effect=fake_get),
            caplog.at_level(logging.WARNING),
        ):
            result = openapi_client.get_device_ports("site-001")

        assert [p["deviceName"] for p in result] == ["Switch 2"]
        assert "Unable to enumerate ports for switch Switch 1" in caplog.text

    def test_get_switch_port_profiles(self, openapi_client: OmadaOpenApiClient) -> None:
        profiles = [{"name": "Default"}]
        with patch.object(openapi_client, "_get_paged") as mock:
            mock.return_value = profiles
            result = openapi_client.get_switch_port_profiles("site-001")
        assert result == profiles

    def test_get_switch_port_profiles_all_fail(self, openapi_client: OmadaOpenApiClient) -> None:
        with patch.object(openapi_client, "_get_paged") as mock:
            mock.side_effect = OmadaAPIError(-1600, "Unsupported")
            result = openapi_client.get_switch_port_profiles("site-001")
        assert result == []

    def test_get_gateway_settings(self, openapi_client: OmadaOpenApiClient) -> None:
        config = {"wanMode": "DHCP"}
        with patch.object(openapi_client, "_get") as mock:
            mock.return_value = config
            result = openapi_client.get_gateway_settings("site-001")
        assert result == config

    def test_get_gateway_settings_fallback(self, openapi_client: OmadaOpenApiClient) -> None:
        with patch.object(openapi_client, "_get") as mock:
            mock.side_effect = [
                OmadaAPIError(-1600, "Unsupported"),
                {"mode": "static"},
                {"virtualWans": []},
            ]
            result = openapi_client.get_gateway_settings("site-001")
        assert result == {"mode": "static"}

    def test_get_gateway_settings_all_fail(self, openapi_client: OmadaOpenApiClient) -> None:
        with patch.object(openapi_client, "_get") as mock:
            mock.side_effect = OmadaAPIError(-1600, "Unsupported")
            result = openapi_client.get_gateway_settings("site-001")
        assert result == {}

    def test_get_ssids(self, openapi_client: OmadaOpenApiClient) -> None:
        wlans = [{"wlanId": "wlan-1", "name": "WLAN Group 1"}]
        ssids = [{"name": "MySSID", "band": 2, "security": 3}]
        with patch.object(openapi_client, "_get_paged") as mock_paged:
            mock_paged.side_effect = [wlans, ssids]
            result = openapi_client.get_ssids("site-001")
        assert len(result) == 1
        assert result[0]["name"] == "MySSID"
        assert result[0]["wlanName"] == "WLAN Group 1"

    def test_get_ssids_no_wlans(self, openapi_client: OmadaOpenApiClient) -> None:
        with patch.object(openapi_client, "_get_paged") as mock:
            mock.side_effect = OmadaAPIError(-1600, "Unsupported")
            result = openapi_client.get_ssids("site-001")
        assert result == []

    def test_get_port_forwarding(self, openapi_client: OmadaOpenApiClient) -> None:
        rules = [{"name": "NAS", "externalPort": "443", "forwardIp": "192.168.2.50"}]
        with patch.object(openapi_client, "_get_paged", return_value=rules) as mock:
            result = openapi_client.get_port_forwarding("site-001")
        assert result == rules
        mock.assert_called_once_with("sites/site-001/nat/port-forwardings")

    def test_get_one_to_one_nat(self, openapi_client: OmadaOpenApiClient) -> None:
        rules = [{"name": "Server", "internalIp": "192.168.2.10", "externalIp": "1.2.3.4"}]
        with patch.object(openapi_client, "_get_paged", return_value=rules) as mock:
            result = openapi_client.get_one_to_one_nat("site-001")
        assert result == rules
        mock.assert_called_once_with("sites/site-001/nat/one-to-one-nat")

    def test_get_alg_settings(self, openapi_client: OmadaOpenApiClient) -> None:
        alg = {"ftp": True, "sip": False}
        with patch.object(openapi_client, "_get", return_value=alg) as mock:
            result = openapi_client.get_alg_settings("site-001")
        assert result == alg
        mock.assert_called_once_with("sites/site-001/nat/alg")

    def test_get_alg_settings_non_dict_result(self, openapi_client: OmadaOpenApiClient) -> None:
        with patch.object(openapi_client, "_get", return_value=[]):
            assert openapi_client.get_alg_settings("site-001") == {}

    def test_get_dhcp_reservations(self, openapi_client: OmadaOpenApiClient) -> None:
        reservations = [{"netName": "LAN", "ip": "192.168.1.50", "mac": "AA-BB-CC-DD-EE-FF", "name": "printer", "status": True, "serverName": "Gateway"}]
        with patch.object(openapi_client, "_get_paged") as mock:
            mock.return_value = reservations
            result = openapi_client.get_dhcp_reservations("site-001")
        assert len(result) == 1
        assert result[0]["ip"] == "192.168.1.50"
        assert result[0]["netName"] == "LAN"


# ---------------------------------------------------------------------------
# Service integration test
# ---------------------------------------------------------------------------

class TestServiceWithOpenApiClient:
    def test_service_accepts_injected_client(self) -> None:
        """OmadaService should use an injected client instead of creating one."""
        from omada.service import OmadaService

        mock_client = MagicMock()
        service = OmadaService(
            client=mock_client,
            site_id="site-001",
            output_dir="/tmp/test-out",
        )
        assert service._client is mock_client

    def test_service_fetch_all_uses_injected_client(self, tmp_path) -> None:
        """fetch_all should call the injected client's get_* methods."""
        from omada.service import OmadaService

        mock_client = MagicMock()
        mock_client.get_acl_rules.return_value = [{"name": "rule1"}]
        mock_client.get_ip_groups.return_value = []
        mock_client.get_port_groups.return_value = []
        mock_client.get_networks.return_value = [{"name": "LAN"}]
        mock_client.get_vlans.return_value = []
        mock_client.get_switch_port_profiles.return_value = []
        mock_client.get_gateway_settings.return_value = {}
        mock_client.get_ssids.return_value = []
        mock_client.get_dhcp_reservations.return_value = []
        mock_client.get_devices.return_value = []
        mock_client.get_device_ports.return_value = []
        mock_client.get_port_forwarding.return_value = []
        mock_client.get_one_to_one_nat.return_value = []
        mock_client.get_alg_settings.return_value = {}

        service = OmadaService(
            client=mock_client,
            site_id="site-001",
            output_dir=str(tmp_path),
        )
        data = service.fetch_all()
        assert data["acl_rules"] == [{"name": "rule1"}]
        assert data["networks"] == [{"name": "LAN"}]
        mock_client.get_acl_rules.assert_called_once_with("site-001")
