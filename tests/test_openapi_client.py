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
            patch.object(openapi_client, "_get_paged",
                         side_effect=[devices, overview, [], []]) as mock_paged,
            patch.object(openapi_client, "_get") as mock_get,
            patch.object(openapi_client, "_post", return_value=[]),
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

    def test_get_ssids_merges_detail_and_overrides_and_redacts(
        self, openapi_client: OmadaOpenApiClient,
    ) -> None:
        wlans = [{"wlanId": "w1", "name": "Default"}]
        listed = [{"id": "s1", "name": "FROGGY", "security": 3}]
        overrides = [{"name": "Office AP", "overrideName": "FROGGY-OFFICE", "overridePassword": "ovr-pw"}]

        def fake_paged(path: str) -> list:
            return {
                "sites/site-001/wireless-network/wlans": wlans,
                "sites/site-001/wireless-network/wlans/w1/ssids": listed,
                "sites/site-001/wireless-network/ssids/s1/overrides": overrides,
            }[path]

        detail = {"id": "s1", "name": "FROGGY", "security": 3,
                  "pskSetting": {"securityKey": "wifi-passphrase", "versionPsk": 4},
                  "wlanSchedule": {"wlanScheduleEnable": True, "scheduleId": "t1"}}
        with (
            patch.object(openapi_client, "_get_paged", side_effect=fake_paged),
            patch.object(openapi_client, "_get", return_value=detail) as mock_get,
        ):
            result = openapi_client.get_ssids("site-001")

        mock_get.assert_called_once_with("sites/site-001/wireless-network/ssids/s1")
        ssid = result[0]
        assert ssid["wlanName"] == "Default" and ssid["wlanId"] == "w1"
        assert ssid["pskSetting"] == {"securityKey": "<redacted>", "versionPsk": 4}
        assert ssid["wlanSchedule"]["scheduleId"] == "t1"
        assert ssid["apOverrides"][0]["overrideName"] == "FROGGY-OFFICE"
        assert ssid["apOverrides"][0]["overridePassword"] == "<redacted>"
        assert "wifi-passphrase" not in repr(result) and "ovr-pw" not in repr(result)

    def test_get_ssids_detail_falls_back_to_wlan_path(
        self, openapi_client: OmadaOpenApiClient,
    ) -> None:
        wlans = [{"wlanId": "w1", "name": "Default"}]
        listed = [{"id": "s1", "name": "Legacy"}]

        def fake_get(path: str) -> dict:
            if path == "sites/site-001/wireless-network/ssids/s1":
                raise OmadaAPIError(-1600, "Unsupported")
            return {"id": "s1", "enable11r": True}

        with (
            patch.object(openapi_client, "_get_paged",
                         side_effect=[wlans, listed, OmadaAPIError(-1, "no overrides")]),
            patch.object(openapi_client, "_get", side_effect=fake_get) as mock_get,
        ):
            result = openapi_client.get_ssids("site-001")
        assert mock_get.call_args_list[-1].args == ("sites/site-001/wireless-network/wlans/w1/ssids/s1",)
        assert result[0]["enable11r"] is True
        assert "apOverrides" not in result[0]

    def test_get_radius_profiles_redacts_all_secrets(self, openapi_client: OmadaOpenApiClient) -> None:
        profiles = [{
            "radiusProfileId": "r1", "name": "Corp",
            "authServer": [{"radiusServerIp": "10.0.0.5", "radiusPort": 1812, "radiusPwd": "auth-secret"}],
            "acctServer": [{"accountingServerIp": "10.0.0.5", "accountingServerPwd": "acct-secret"}],
            "coaPassword": "coa-secret", "builtInServerSecret": "builtin-secret",
        }]
        with patch.object(openapi_client, "_get", return_value=profiles) as mock:
            result = openapi_client.get_radius_profiles("site-001")
        mock.assert_called_once_with("sites/site-001/profiles/radius")
        text = repr(result)
        for secret in ("auth-secret", "acct-secret", "coa-secret", "builtin-secret"):
            assert secret not in text
        assert result[0]["authServer"][0]["radiusServerIp"] == "10.0.0.5"

    def test_get_portals_merges_detail_and_redacts(self, openapi_client: OmadaOpenApiClient) -> None:
        def fake_get(path: str):
            if path == "sites/site-001/portals":
                return [{"id": "p1", "name": "Guest", "authType": 1}, {"id": "p2", "name": "Broken"}]
            if path == "sites/site-001/portal/p1":
                return {"id": "p1", "simplePassword": {"password": "guest-pw"},
                        "google": {"clientId": "cid", "clientSecret": "g-secret"},
                        "sms": {"sid": "AC123", "authToken": "twilio-token"}}
            raise OmadaAPIError(-1, "detail unavailable")

        with patch.object(openapi_client, "_get", side_effect=fake_get):
            result = openapi_client.get_portals("site-001")
        assert [p["name"] for p in result] == ["Guest", "Broken"]
        assert result[0]["authType"] == 1  # list fields kept
        assert result[0]["sms"]["sid"] == "AC123"  # account identifier kept
        assert result[0]["google"]["clientId"] == "cid"
        for secret in ("guest-pw", "g-secret", "twilio-token"):
            assert secret not in repr(result)

    def test_get_time_range_and_rate_limit_profiles(self, openapi_client: OmadaOpenApiClient) -> None:
        with patch.object(openapi_client, "_get", return_value=[{"name": "Office hours"}]) as mock:
            assert openapi_client.get_time_range_profiles("site-001") == [{"name": "Office hours"}]
        mock.assert_called_once_with("sites/site-001/time-range-profiles")
        with patch.object(openapi_client, "_get", return_value=[{"name": "Guest 10M"}]) as mock:
            assert openapi_client.get_rate_limit_profiles("site-001") == [{"name": "Guest 10M"}]
        mock.assert_called_once_with("sites/site-001/rate-limit-profiles")

    def test_get_wireless_settings_partial_and_total_failure(
        self, openapi_client: OmadaOpenApiClient,
    ) -> None:
        def fake_get(path: str) -> dict:
            if path.endswith("/mesh"):
                raise OmadaAPIError(-1600, "Unsupported")
            return {"path": path}

        with patch.object(openapi_client, "_get", side_effect=fake_get):
            result = openapi_client.get_wireless_settings("site-001")
        assert set(result) == {"bandSteering", "roaming", "multicastRateLimit"}
        assert result["bandSteering"] == {"path": "sites/site-001/band-steering"}
        with patch.object(openapi_client, "_get", side_effect=OmadaAPIError(-1, "x")):
            with pytest.raises(OmadaAPIError):
                openapi_client.get_wireless_settings("site-001")

    def test_get_ap_radios(self, openapi_client: OmadaOpenApiClient, caplog: pytest.LogCaptureFixture) -> None:
        devices = [
            {"name": "Lower AP", "type": "ap", "mac": "AA", "model": "EAP620 HD"},
            {"name": "Broken AP", "type": "ap", "mac": "BB"},
            {"name": "Switch", "type": "switch", "mac": "CC"},
        ]

        def fake_get(path: str) -> dict:
            if "/BB/" in path:
                raise OmadaAPIError(-1, "offline")
            return {"radioSetting2g": {"radioEnable": True, "channel": "6"},
                    "radioSetting5g": {"radioEnable": False}, "unrelated": 1}

        with (
            patch.object(openapi_client, "_get_paged", return_value=devices),
            patch.object(openapi_client, "_get", side_effect=fake_get) as mock_get,
            caplog.at_level(logging.WARNING),
        ):
            result = openapi_client.get_ap_radios("site-001")
        assert [c.args[0] for c in mock_get.call_args_list] == [
            "sites/site-001/aps/AA/radio-config", "sites/site-001/aps/BB/radio-config",
        ]
        assert result == [{
            "deviceName": "Lower AP", "deviceMac": "AA", "deviceModel": "EAP620 HD",
            "radios": {"2g": {"radioEnable": True, "channel": "6"}, "5g": {"radioEnable": False}},
        }]
        assert "Radio config unavailable for AP Broken AP" in caplog.text

    def test_get_wan_failover_collects_config_and_health(
        self, openapi_client: OmadaOpenApiClient,
    ) -> None:
        devices = [{"name": "Astoria Gateway", "type": "gateway", "mac": "6C-5A"},
                   {"name": "AP", "type": "ap", "mac": "AA"}]
        responses = {
            "sites/site-001/internet/load-balance": {"linkBackup": True, "weights": [1, 1]},
            "sites/site-001/internet/basic-info": {"interval": 10, "portList": []},
            "sites/site-001/gateways/6C-5A/wan-status": [{"port": 1, "name": "WAN", "latency": 8}],
        }
        with (
            patch.object(openapi_client, "_get_paged", return_value=devices),
            patch.object(openapi_client, "_get", side_effect=responses.__getitem__),
        ):
            result = openapi_client.get_wan_failover("site-001")
        assert result["loadBalance"]["linkBackup"] is True
        assert result["internet"]["interval"] == 10
        assert result["wanHealth"] == [{"gatewayName": "Astoria Gateway", "port": 1, "name": "WAN", "latency": 8}]

    def test_collect_tolerates_partial_and_raises_on_total_failure(
        self, openapi_client: OmadaOpenApiClient, caplog: pytest.LogCaptureFixture,
    ) -> None:
        def fake_get(path: str) -> dict:
            if path.endswith("dns-cache"):
                raise OmadaAPIError(-1600, "Unsupported")
            return {"enable": True}

        with (
            patch.object(openapi_client, "_get", side_effect=fake_get),
            patch.object(openapi_client, "_get_paged", return_value=[{"username": "u", "password": "ddns-pw"}]),
            caplog.at_level(logging.WARNING),
        ):
            result = openapi_client.get_dns_settings("site-001")
        assert set(result) == {"dnsProxy", "lanDns", "ddns"}
        assert result["ddns"][0]["password"] == "<redacted>"
        assert "setting/service/dns-cache unavailable" in caplog.text
        with (
            patch.object(openapi_client, "_get", side_effect=OmadaAPIError(-1, "x")),
            patch.object(openapi_client, "_get_paged", side_effect=OmadaAPIError(-1, "x")),
        ):
            with pytest.raises(OmadaAPIError):
                openapi_client.get_dns_settings("site-001")

    def test_get_time_settings_uses_site_info_without_trailing_slash(
        self, openapi_client: OmadaOpenApiClient,
    ) -> None:
        responses = {
            "sites/site-001": {"name": "Astoria", "timeZone": "America/New_York",
                               "ntpServers": ["pool.ntp.org"], "region": "US", "scenario": "Home",
                               "type": 0, "id": "site-001"},
            "sites/site-001/dst-info": {"enable": True, "mode": 1},
            "sites/site-001/setting/ntp": {"enable": True},
        }
        with patch.object(openapi_client, "_get", side_effect=responses.__getitem__):
            result = openapi_client.get_time_settings("site-001")
        assert result["site"] == {"name": "Astoria", "region": "US", "timeZone": "America/New_York",
                                  "ntpServers": ["pool.ntp.org"], "scenario": "Home"}
        assert result["dst"]["mode"] == 1

    def test_get_multicast_services_unwraps_bonjour(self, openapi_client: OmadaOpenApiClient) -> None:
        get_responses = {
            "sites/site-001/setting/service/igmp": {"enable": False},
            "sites/site-001/setting/service/mld": {"enable": False},
            "sites/site-001/setting/service/iptv": {"enable": False},
            "sites/site-001/upnp": {"enable": True},
            "sites/site-001/profiles/bonjour-service": {"data": [{"id": "b1", "name": "AirPlay"}]},
        }
        paged = {
            "sites/site-001/setting/service/mdns": [{"name": "Cast to IoT"}],
            "sites/site-001/lan-multicasts": [],
        }
        with (
            patch.object(openapi_client, "_get", side_effect=get_responses.__getitem__),
            patch.object(openapi_client, "_get_paged", side_effect=paged.__getitem__),
        ):
            result = openapi_client.get_multicast_services("site-001")
        assert result["bonjourServices"] == [{"id": "b1", "name": "AirPlay"}]
        assert result["mdnsRules"] == [{"name": "Cast to IoT"}]
        assert result["upnp"] == {"enable": True}

    def test_get_lags_rebuilds_groups_from_port_overview(
        self, openapi_client: OmadaOpenApiClient,
    ) -> None:
        devices = [{"name": "Main Switch", "type": "switch", "mac": "54-AF"}]
        overview = [
            # Port 25 carries the full definition: members 25-26, LACP
            {"switchMac": "54-AF", "port": 25, "portName": "Port25", "operation": "AGGREGATING",
             "lagSetting": {"lagId": 1, "ports": [25, 26], "lagType": 2}, "profileName": "All"},
            # Port 26 lists only itself -- membership must still be the union
            {"switchMac": "54-AF", "port": 26, "portName": "Port26", "operation": "AGGREGATING",
             "lagSetting": {"lagId": 1, "ports": [26]}},
            # A second, static LAG whose member list includes a port not in the overview page
            {"switchMac": "54-AF", "port": 27, "operation": "AGGREGATING",
             "lagSetting": {"lagId": 2, "ports": [27, 28], "lagType": 1}},
            # Aggregating without lagSetting: grouped as unknown
            {"switchMac": "54-AF", "port": 9, "operation": "AGGREGATING"},
            {"switchMac": "54-AF", "port": 1, "operation": "SWITCHING"},
        ]

        def fake_paged(path: str) -> list:
            return {
                "sites/site-001/devices": devices,
                "sites/site-001/switches/ports/overview": overview,
                "sites/site-001/stacks": [],
                "sites/site-001/mlag": [],
            }[path]

        with (
            patch.object(openapi_client, "_get_paged", side_effect=fake_paged),
            patch.object(openapi_client, "_get", return_value={"type": 2}),
        ):
            result = openapi_client.get_lags("site-001")

        lags = result["lags"]
        assert [(lag["lagId"], lag["memberPorts"]) for lag in lags] == [
            (1, [25, 26]), (2, [27, 28]), (None, [9]),
        ]
        assert lags[0]["lagType"] == 2 and lags[0]["profileName"] == "All"
        assert lags[0]["deviceName"] == "Main Switch"
        assert [m["port"] for m in lags[0]["members"]] == [25, 26]
        assert [m["port"] for m in lags[1]["members"]] == [27]  # 28 known only from the group
        assert lags[1]["lagType"] == 1
        assert result["hashAlgorithm"] == {"type": 2}
        assert result["mlagGroups"] == []

    def test_get_lags_fallback_and_stacks(self, openapi_client: OmadaOpenApiClient) -> None:
        devices = [{"name": "Lab Switch", "type": "switch", "mac": "20-23"}]
        stack_lag = {"lagId": 3, "name": "Uplink", "lagType": 3, "ports": [1, 2],
                     "standardPorts": [{"unit": 1, "slot": 0, "port": 1}, {"unit": 2, "slot": 0, "port": 1}],
                     "lagStatus": {"linkStatus": 1, "linkSpeed": 5}}

        def fake_paged(path: str) -> list:
            if path == "sites/site-001/switches/ports/overview":
                raise OmadaAPIError(-1600, "Unsupported")
            if path == "sites/site-001/mlag":
                raise OmadaAPIError(-1600, "Unsupported")
            return {"sites/site-001/devices": devices,
                    "sites/site-001/stacks": [{"id": "st1", "name": "Core Stack"}]}[path]

        def fake_get(path: str):
            if path == "sites/site-001/switches/20-23":
                return {"portList": [{"port": 7, "lagPort": True}, {"port": 8, "lagPort": False}]}
            if path == "sites/site-001/stacks/st1/lags":
                return [stack_lag]
            raise OmadaAPIError(-1600, "Unsupported")

        with (
            patch.object(openapi_client, "_get_paged", side_effect=fake_paged),
            patch.object(openapi_client, "_get", side_effect=fake_get),
        ):
            result = openapi_client.get_lags("site-001")

        fallback, stack = result["lags"]
        assert fallback["lagId"] is None and fallback["memberPorts"] == [7]
        assert fallback["source"] == "switch-info"
        assert stack["deviceName"] == "Core Stack" and stack["deviceType"] == "stack"
        assert stack["name"] == "Uplink" and stack["memberPorts"] == [1, 2]
        assert "mlagGroups" not in result and "hashAlgorithm" not in result

    def test_get_switch_settings(self, openapi_client: OmadaOpenApiClient) -> None:
        devices = [
            {"name": "Main Switch", "type": "switch", "mac": "54-AF", "model": "TL-SG2428P"},
            {"name": "Lab Switch", "type": "switch", "mac": "20-23"},
            {"name": "GW", "type": "gateway", "mac": "6C-5A"},
        ]
        gets = {
            "sites/site-001/jumbo": {"size": 9216},
            "sites/site-001/switches/54-AF/general-config": {
                "ledSetting": 2, "jumboFollowSite": True,
                "location": {"latitude": 40.7, "longitude": -73.9, "address": "Home"}},
            "sites/site-001/switches/54-AF/rpvst-instances": [{"vlan": 10, "priority": 4096, "enable": True}],
        }
        paged = {
            "sites/site-001/devices": devices,
            "sites/site-001/switches/54-AF/networks": [{"vlan": 1, "mvlan": True}],
        }

        def fake_get(path: str):
            if path in gets:
                return gets[path]
            raise OmadaAPIError(-1600, "Unsupported")

        def fake_paged(path: str):
            if path in paged:
                return paged[path]
            raise OmadaAPIError(-1600, "Unsupported")

        with (
            patch.object(openapi_client, "_get", side_effect=fake_get),
            patch.object(openapi_client, "_get_paged", side_effect=fake_paged),
        ):
            result = openapi_client.get_switch_settings("site-001")

        assert result["site"] == {"jumbo": {"size": 9216}}  # lldp unavailable: omitted
        main, lab = result["switches"]
        assert main["deviceName"] == "Main Switch" and main["deviceModel"] == "TL-SG2428P"
        assert main["general"] == {"ledSetting": 2, "jumboFollowSite": True}  # GPS location dropped
        assert main["networks"] == [{"vlan": 1, "mvlan": True}]
        assert main["rpvst"] == [{"vlan": 10, "priority": 4096, "enable": True}]
        assert lab == {"deviceName": "Lab Switch", "deviceMac": "20-23", "deviceModel": ""}

    def test_post_returns_result_and_raises_on_error(self, openapi_client: OmadaOpenApiClient) -> None:
        ok = _mock_response({"errorCode": 0, "result": [{"mac": "AA"}]})
        with patch.object(openapi_client._session, "post", return_value=ok) as mock_post:
            assert openapi_client._post("sites/s1/switches/ports/select", {"selectAll": True}) == [{"mac": "AA"}]
        assert mock_post.call_args.kwargs["json"] == {"selectAll": True}
        bad = _mock_response({"errorCode": -1600, "msg": "Unsupported"})
        with patch.object(openapi_client._session, "post", return_value=bad):
            with pytest.raises(OmadaAPIError):
                openapi_client._post("sites/s1/switches/ports/select", {})

    def test_get_device_ports_merges_full_config_and_schedules(
        self, openapi_client: OmadaOpenApiClient,
    ) -> None:
        devices = [{"name": "Main Switch", "type": "switch", "mac": "54-AF"}]
        overview = [{"switchMac": "54-AF", "port": 3, "portName": "Port3", "connectedStatus": 0,
                     "profileName": "All", "profileOverrideEnable": False}]
        selected = [{"mac": "54-af", "ports": [
            {"port": 3, "name": "Port3", "dot1x": 0, "portIsolationEnable": True,
             "voiceNetworkEnable": True, "voiceNetworkId": "net-voice", "bandWidthCtrlType": 2,
             "stormCtrl": {"broadcastEnable": True, "broadcast": 10}, "site": "s", "switchId": "x"},
        ], "lags": []}]
        schedules = {
            "sites/site-001/poe-schedules": [{"name": "Night PoE off", "poePortsMap": {"54-AF": [3, 4]}}],
            "sites/site-001/port-schedules": [{"name": "Lab hours", "portsMap": {"54:af": [3]}}],
        }

        def fake_paged(path: str) -> list:
            return {"sites/site-001/devices": devices,
                    "sites/site-001/switches/ports/overview": overview, **schedules}[path]

        with (
            patch.object(openapi_client, "_get_paged", side_effect=fake_paged),
            patch.object(openapi_client, "_post", return_value=selected) as mock_post,
        ):
            [port] = openapi_client.get_device_ports("site-001")

        mock_post.assert_called_once_with("sites/site-001/switches/ports/select",
                                          {"selectAll": True, "switchList": []})
        assert port["connectedStatus"] == 0            # overview status kept
        assert port["portIsolationEnable"] is True     # full config merged in
        assert port["voiceNetworkId"] == "net-voice"
        assert port["stormCtrl"] == {"broadcastEnable": True, "broadcast": 10}
        assert "site" not in port and "switchId" not in port
        assert port["poeSchedules"] == ["Night PoE off"]
        assert port["portSchedules"] == ["Lab hours"]

    def test_get_device_ports_without_full_config(
        self, openapi_client: OmadaOpenApiClient, caplog: pytest.LogCaptureFixture,
    ) -> None:
        devices = [{"name": "Main Switch", "type": "switch", "mac": "54-AF"}]
        overview = [{"switchMac": "54-AF", "port": 3, "portName": "Port3"}]
        with (
            patch.object(openapi_client, "_get_paged", side_effect=[devices, overview, [], []]),
            patch.object(openapi_client, "_post", side_effect=OmadaAPIError(-1600, "Unsupported")),
            caplog.at_level(logging.WARNING),
        ):
            [port] = openapi_client.get_device_ports("site-001")
        assert port["portName"] == "Port3"
        assert "exporting overview only" in caplog.text

    def test_get_lags_uses_full_lag_config(self, openapi_client: OmadaOpenApiClient) -> None:
        devices = [{"name": "Main Switch", "type": "switch", "mac": "54-AF"}]
        overview = [{"switchMac": "54-AF", "port": 25, "operation": "AGGREGATING",
                     "lagSetting": {"lagId": 1, "ports": [25]}}]
        selected = [{"mac": "54-AF", "ports": [], "lags": [
            {"lagId": 1, "name": "NAS bond", "profileName": "Infra", "lagType": 2, "ports": [25, 26]}]}]

        def fake_paged(path: str) -> list:
            return {"sites/site-001/devices": devices, "sites/site-001/switches/ports/overview": overview,
                    "sites/site-001/stacks": [], "sites/site-001/mlag": []}[path]

        with (
            patch.object(openapi_client, "_get_paged", side_effect=fake_paged),
            patch.object(openapi_client, "_post", return_value=selected),
            patch.object(openapi_client, "_get", return_value={}),
        ):
            [lag] = openapi_client.get_lags("site-001")["lags"]
        assert lag["name"] == "NAS bond" and lag["profileName"] == "Infra"
        assert lag["lagType"] == 2
        assert lag["memberPorts"] == [25, 26]

    def test_get_port_schedules(self, openapi_client: OmadaOpenApiClient) -> None:
        def fake_paged(path: str) -> list:
            if path.endswith("port-schedules"):
                raise OmadaAPIError(-1600, "Unsupported")
            return [{"name": "Night PoE off"}]

        with patch.object(openapi_client, "_get_paged", side_effect=fake_paged):
            assert openapi_client.get_port_schedules("site-001") == {"poeSchedules": [{"name": "Night PoE off"}]}

    def test_get_uplinks_switch_detail_fallback_and_stacks(
        self, openapi_client: OmadaOpenApiClient,
    ) -> None:
        devices = [
            {"name": "Main Switch", "type": "switch", "mac": "54-AF", "model": "TL-SG2428P"},
            {"name": "Lab Switch", "type": "switch", "mac": "20-23", "model": "SG2008"},
            {"name": "AP", "type": "ap", "mac": "AA"},
        ]
        detail = [{"mac": "54-af", "uplink": {"port": 24, "name": "Astoria Gateway", "type": "gateway",
                                             "linkPeerPortInfo": {"port": 2}},
                   "downlinkList": [{"port": 1, "name": "Lab Switch", "type": "switch"}],
                   "stackMsg": {"stackId": None}}]
        selected = [{"mac": "20-23", "uplink": {"port": 8, "name": "Main Switch", "type": "switch"}}]
        stacks = [{"id": "st1", "name": "Core", "status": 0, "masterMac": "CC", "member": [
            {"name": "Core-1", "mac": "CC", "unit": 1, "priority": 15, "memberStatus": 0, "cpuUtil": 9,
             "stackPorts": [{"ID": 1, "name": "Group 1", "ports": [25, 26]}]}]}]

        def fake_paged(path: str) -> list:
            return {"sites/site-001/devices": devices, "sites/site-001/stacks": stacks}[path]

        with (
            patch.object(openapi_client, "_get_paged", side_effect=fake_paged),
            patch.object(openapi_client, "_get", return_value=detail) as mock_get,
            patch.object(openapi_client, "_post", return_value=selected) as mock_post,
        ):
            result = openapi_client.get_uplinks("site-001")

        mock_get.assert_called_once_with("sites/site-001/switches/ports/switch-detail")
        mock_post.assert_called_once()  # Lab Switch missing from switch-detail
        main, lab = result["switches"]
        assert main["uplink"]["name"] == "Astoria Gateway"
        assert main["downlinks"] == [{"port": 1, "name": "Lab Switch", "type": "switch"}]
        assert "stackMsg" not in main  # no stackId: not stacked
        assert lab["uplink"]["port"] == 8 and lab["deviceModel"] == "SG2008"
        [stack] = result["stacks"]
        assert stack["name"] == "Core" and stack["members"][0]["unit"] == 1
        assert "cpuUtil" not in stack["members"][0]  # runtime stats dropped

    def test_get_uplinks_no_switches(self, openapi_client: OmadaOpenApiClient) -> None:
        with (
            patch.object(openapi_client, "_get_paged",
                         side_effect=[[{"name": "AP", "type": "ap", "mac": "AA"}], OmadaAPIError(-1, "x")]),
            patch.object(openapi_client, "_get") as mock_get,
        ):
            assert openapi_client.get_uplinks("site-001") == {"switches": [], "stacks": []}
        mock_get.assert_not_called()

    def test_get_switch_port_sheets_lists_switches(self, openapi_client: OmadaOpenApiClient) -> None:
        devices = [
            {"name": "Main Switch", "type": "switch", "mac": "54-AF", "model": "TL-SG2428P"},
            {"name": "GW", "type": "gateway", "mac": "6C-5A"},
            {"name": "No MAC", "type": "switch"},
        ]
        with patch.object(openapi_client, "_get_paged", return_value=devices) as mock:
            result = openapi_client.get_switch_port_sheets("site-001")
        mock.assert_called_once_with("sites/site-001/devices")
        assert result == [{"deviceName": "Main Switch", "deviceMac": "54-AF", "deviceModel": "TL-SG2428P"}]

    def test_get_switch_security_collects_parts(self, openapi_client: OmadaOpenApiClient) -> None:
        gets = {
            "sites/site-001/dot1x": {"enable": True, "radiusProfileId": "r1"},
            "sites/site-001/mac-auth": {"enable": False},
            "sites/site-001/dhcpSnoops/status": {"dhcpSnoopEnable": True},
            "sites/site-001/arpDetects/status": {"arpDetectEnable": False},
            "sites/site-001/ip-mac-bind": {"enable": False},
        }
        paged = {
            "sites/site-001/dhcpSnoops": [{"mac": "54-AF", "ports": [{"port": 1}]}],
            "sites/site-001/ip-mac-binds": [{"ip": "192.168.2.5", "mac": "AA"}],
        }

        def fake_paged(path: str) -> list:
            if path in paged:
                return paged[path]
            raise OmadaAPIError(-1600, "Unsupported")

        with (
            patch.object(openapi_client, "_get", side_effect=gets.__getitem__),
            patch.object(openapi_client, "_get_paged", side_effect=fake_paged),
        ):
            result = openapi_client.get_switch_security("site-001")
        assert set(result) == {"dot1x", "macAuth", "dhcpSnoopStatus", "dhcpSnoops",
                               "arpDetectStatus", "ipMacBind", "ipMacBinds"}  # arpDetects failed: omitted
        assert result["dhcpSnoops"][0]["ports"] == [{"port": 1}]

    def test_get_oui_vlans_qos_and_port_labels(self, openapi_client: OmadaOpenApiClient) -> None:
        paged = {
            "sites/site-001/switch-oui-rules": [{"name": "Phones"}],
            "sites/site-001/oui-profiles": [{"name": "Yealink"}],
            "sites/site-001/switch-qos/qos-rule": [{"name": "Voice"}],
        }
        gets = {
            "sites/site-001/switch-qos/qos-mode": {"qosMode": 1},
            "sites/site-001/switch-qos/qos-rule/dscp-mapping": {"mapping": {"5": [46]}},
            "sites/site-001/switch-qos/qos-rule/scheduler-mapping": {"name": "Default", "mapping": []},
            "sites/site-001/switches/port-tag": [{"tagId": "t1", "name": "Camera"}],
        }
        with (
            patch.object(openapi_client, "_get_paged", side_effect=paged.__getitem__),
            patch.object(openapi_client, "_get", side_effect=gets.__getitem__),
        ):
            assert openapi_client.get_oui_vlans("site-001") == {
                "rules": [{"name": "Phones"}], "profiles": [{"name": "Yealink"}]}
            qos = openapi_client.get_switch_qos("site-001")
            assert qos["mode"] == {"qosMode": 1} and qos["rules"] == [{"name": "Voice"}]
            assert openapi_client.get_port_labels("site-001") == [{"tagId": "t1", "name": "Camera"}]

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

    def test_get_static_routes_gateway_and_switch(
        self, openapi_client: OmadaOpenApiClient,
    ) -> None:
        gateway_routes = [{"name": "To lab", "interfaceId": "net-1", "routeType": 1}]
        devices = [
            {"name": "Core", "type": "switch", "mac": "AA-BB"},
            {"name": "GW", "type": "gateway", "mac": "11-22"},
        ]
        switch_routes = [{"description": "Mgmt", "nextHopIp": "10.0.0.1", "distance": 1}]

        def fake_paged(path: str) -> list:
            return {
                "sites/site-001/routing/static-routings": gateway_routes,
                "sites/site-001/devices": devices,
                "sites/site-001/switches/AA-BB/staticRoutings": switch_routes,
            }[path]

        interfaces = {"interfaceInfoList": [{"id": "net-1", "name": "Lab LAN", "interfaceType": 1}]}
        with (
            patch.object(openapi_client, "_get_paged", side_effect=fake_paged) as mock_paged,
            patch.object(openapi_client, "_get", return_value=interfaces) as mock_get,
        ):
            result = openapi_client.get_static_routes("site-001")

        mock_get.assert_called_once_with("sites/site-001/routing/static-routings/interfaces")
        # Gateways are not queried for switch static routes
        assert all("11-22" not in c.args[0] for c in mock_paged.call_args_list)
        assert result[0]["routeSource"] == "gateway"
        assert result[0]["interfaceName"] == "Lab LAN"
        assert result[1]["routeSource"] == "switch"
        assert result[1]["deviceName"] == "Core"
        assert result[1]["deviceMac"] == "AA-BB"

    def test_get_static_routes_tolerates_failures(
        self,
        openapi_client: OmadaOpenApiClient,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        devices = [{"name": "Smart", "type": "switch", "mac": "AA"}]

        def fake_paged(path: str) -> list:
            if path == "sites/site-001/devices":
                return devices
            raise OmadaAPIError(-1600, "Unsupported")

        with (
            patch.object(openapi_client, "_get_paged", side_effect=fake_paged),
            patch.object(openapi_client, "_get") as mock_get,
            caplog.at_level(logging.WARNING),
        ):
            result = openapi_client.get_static_routes("site-001")

        assert result == []
        mock_get.assert_not_called()  # no gateway routes -> no interface lookup
        assert "Gateway static routes unavailable" in caplog.text
        # L2 switches without static routing are not warned about
        assert "Static routes unavailable for switch" not in caplog.text

    def test_get_policy_routes(self, openapi_client: OmadaOpenApiClient) -> None:
        rules = [{"name": "IoT via WAN2", "index": 1}]
        with patch.object(openapi_client, "_get_paged", return_value=rules) as mock:
            result = openapi_client.get_policy_routes("site-001")
        assert result == rules
        mock.assert_called_once_with("sites/site-001/routing/policy-routings")

    def test_get_site_to_site_vpns_redacts_psk(self, openapi_client: OmadaOpenApiClient) -> None:
        vpns = [{"name": "HQ", "siteVpnType": 1, "preSharedKey": "s3cret!", "remoteIp": "1.2.3.4"}]
        with patch.object(openapi_client, "_get_paged", return_value=vpns) as mock:
            result = openapi_client.get_site_to_site_vpns("site-001")
        mock.assert_called_once_with("sites/site-001/vpn/site-to-site-vpns")
        assert result[0]["preSharedKey"] == "<redacted>"
        assert result[0]["remoteIp"] == "1.2.3.4"
        assert "s3cret!" not in repr(result)

    def test_get_remote_access_vpns_tags_roles_and_redacts(
        self, openapi_client: OmadaOpenApiClient,
    ) -> None:
        servers = [{"name": "L2TP Server", "preSharedKey": "psk", "accountPassword": True}]
        clients = [{"name": "To Office", "clientUserName": "bob", "clientPassword": "pw"}]
        with patch.object(openapi_client, "_get_paged", side_effect=[servers, clients]) as mock:
            result = openapi_client.get_remote_access_vpns("site-001")
        assert [c.args[0] for c in mock.call_args_list] == [
            "sites/site-001/vpn/client-to-site-vpn-servers",
            "sites/site-001/vpn/client-to-site-vpn-clients",
        ]
        assert [v["vpnRole"] for v in result] == ["server", "client"]
        assert result[0]["preSharedKey"] == "<redacted>"
        assert result[0]["accountPassword"] is True  # boolean flag, not a secret
        assert result[1]["clientUserName"] == "bob"
        assert result[1]["clientPassword"] == "<redacted>"

    def test_get_remote_access_vpns_partial_and_total_failure(
        self, openapi_client: OmadaOpenApiClient,
    ) -> None:
        clients = [{"name": "To Office"}]
        with patch.object(
            openapi_client, "_get_paged",
            side_effect=[OmadaAPIError(-1, "x"), clients],
        ):
            assert [v["name"] for v in openapi_client.get_remote_access_vpns("site-001")] == ["To Office"]
        with patch.object(openapi_client, "_get_paged", side_effect=OmadaAPIError(-1, "x")):
            with pytest.raises(OmadaAPIError):
                openapi_client.get_remote_access_vpns("site-001")

    def test_get_wireguard_nests_peers_and_redacts(self, openapi_client: OmadaOpenApiClient) -> None:
        interfaces = [{"id": "wg1", "name": "wg0", "privateKey": "PRIV=", "publicKey": "PUB="}]
        peers = [
            {"name": "Laptop", "interfaceId": "wg1", "presharedKey": "PSK=", "publicKey": "PEER="},
            {"name": "Orphan", "interfaceId": "wg9", "interfaceName": "wg-old"},
        ]
        with patch.object(openapi_client, "_get_paged", side_effect=[interfaces, peers]):
            result = openapi_client.get_wireguard("site-001")
        assert result[0]["privateKey"] == "<redacted>"
        assert result[0]["publicKey"] == "PUB="
        assert result[0]["peers"][0]["name"] == "Laptop"
        assert result[0]["peers"][0]["presharedKey"] == "<redacted>"
        assert result[1]["name"] == "wg-old"
        assert [p["name"] for p in result[1]["peers"]] == ["Orphan"]
        assert "PRIV=" not in repr(result) and "PSK=" not in repr(result)

    def test_get_vpn_users_redacts_passwords(self, openapi_client: OmadaOpenApiClient) -> None:
        users = [{"username": "alice", "password": "hunter2", "servers": ["srv1"]}]
        with patch.object(openapi_client, "_get_paged", return_value=users) as mock:
            result = openapi_client.get_vpn_users("site-001")
        mock.assert_called_once_with("sites/site-001/vpn/users")
        assert result == [{"username": "alice", "password": "<redacted>", "servers": ["srv1"]}]

    def test_get_ssl_vpn_collects_lists_and_redacts(
        self,
        openapi_client: OmadaOpenApiClient,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        base = "sites/site-001/vpn/ssl-vpn-server"
        paged = {
            f"{base}/user-groups": [{"id": "g1", "name": "Staff"}],
            f"{base}/users": [{"name": "alice", "password": "pw!"}],
            f"{base}/resources": [{"name": "NAS"}],
        }

        def fake_paged(path: str) -> list:
            if path == f"{base}/resource-groups":
                raise OmadaAPIError(-1600, "Unsupported")
            return paged[path]

        def fake_get(path: str):
            return {f"{base}/setting": {"status": True, "authType": 0},
                    f"{base}/radius": [{"id": "r1", "name": "Corp RADIUS"}]}[path]

        with (
            patch.object(openapi_client, "_get_paged", side_effect=fake_paged),
            patch.object(openapi_client, "_get", side_effect=fake_get),
            caplog.at_level(logging.WARNING),
        ):
            result = openapi_client.get_ssl_vpn("site-001")

        assert result["setting"] == {"status": True, "authType": 0}
        assert result["userGroups"] == [{"id": "g1", "name": "Staff"}]
        assert result["users"] == [{"name": "alice", "password": "<redacted>"}]
        assert result["resources"] == [{"name": "NAS"}]
        assert result["resourceGroups"] == []
        assert result["radiusServers"] == [{"id": "r1", "name": "Corp RADIUS"}]
        assert "SSL VPN resource-groups unavailable" in caplog.text

    def test_get_ssl_vpn_setting_failure_propagates(self, openapi_client: OmadaOpenApiClient) -> None:
        with patch.object(openapi_client, "_get", side_effect=OmadaAPIError(-1600, "Unsupported")):
            with pytest.raises(OmadaAPIError):
                openapi_client.get_ssl_vpn("site-001")

    def test_get_eogre_tunnel(self, openapi_client: OmadaOpenApiClient) -> None:
        cfg = {"greEnable": True, "tunnelMtu": 1476}
        with patch.object(openapi_client, "_get", return_value=cfg) as mock:
            assert openapi_client.get_eogre_tunnel("site-001") == cfg
        mock.assert_called_once_with("sites/site-001/vpn/gre-tunnel")
        with patch.object(openapi_client, "_get", return_value=None):
            assert openapi_client.get_eogre_tunnel("site-001") == {}

    def test_get_ipsec_failover(self, openapi_client: OmadaOpenApiClient) -> None:
        groups = [{"name": "HQ failover"}]
        with patch.object(openapi_client, "_get_paged", return_value=groups) as mock:
            assert openapi_client.get_ipsec_failover("site-001") == groups
        mock.assert_called_once_with("sites/site-001/vpn/ipsec_failovers")

    def test_get_dhcp_scopes_extracts_dhcp_fields_and_pool_status(
        self, openapi_client: OmadaOpenApiClient,
    ) -> None:
        networks = [
            {"id": "n1", "name": "LAN", "vlan": 1, "gatewaySubnet": "192.168.2.1/24",
             "deviceType": 1, "deviceMac": "GW", "domain": "lan.example",
             "dhcpSettings": {"enable": True, "leasetime": 120}, "dhcpL2RelayEnable": False,
             "igmpSnoopEnable": True, "isolation": False},
            {"id": "n2", "name": "Relayed", "deviceType": 2, "mode": 2,
             "dhcpRelay": {"serverAddrs": ["10.0.0.5"]}},
            {"id": "n3", "name": "Off", "deviceType": 1, "dhcpSettings": {"enable": False}},
        ]
        info = {"ranges": [{"startIp": "192.168.2.11", "endIp": "192.168.2.100", "availableIpNum": 42}]}
        with (
            patch.object(openapi_client, "get_networks", return_value=networks),
            patch.object(openapi_client, "_get", return_value=info) as mock_get,
        ):
            result = openapi_client.get_dhcp_scopes("site-001")

        # Pool usage only for networks actually serving DHCP
        mock_get.assert_called_once_with("sites/site-001/networks/n1/dhcp-server-info")
        assert result[0]["poolStatus"] == info["ranges"]
        assert result[0]["domain"] == "lan.example"
        # Non-DHCP network settings are not copied into the scope
        assert "igmpSnoopEnable" not in result[0] and "isolation" not in result[0]
        assert result[1]["dhcpRelay"] == {"serverAddrs": ["10.0.0.5"]}
        assert "poolStatus" not in result[1] and "poolStatus" not in result[2]

    def test_get_dhcp_scopes_tolerates_pool_status_failure(
        self, openapi_client: OmadaOpenApiClient,
    ) -> None:
        networks = [{"id": "n1", "name": "LAN", "dhcpSettings": {"enable": True}}]
        with (
            patch.object(openapi_client, "get_networks", return_value=networks),
            patch.object(openapi_client, "_get", side_effect=OmadaAPIError(-1, "x")),
        ):
            result = openapi_client.get_dhcp_scopes("site-001")
        assert result == [{"id": "n1", "name": "LAN", "dhcpSettings": {"enable": True}}]

    def test_get_dhcp_leases(self, openapi_client: OmadaOpenApiClient) -> None:
        leases = [{"ipAddress": "192.168.2.50", "macAddress": "AA"}]
        with patch.object(openapi_client, "_get_paged", return_value=leases) as mock:
            assert openapi_client.get_dhcp_leases("site-001") == leases
        mock.assert_called_once_with("sites/site-001/setting/service/dhcp/user-list")

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
        mock_client.get_static_routes.return_value = []
        mock_client.get_policy_routes.return_value = []
        mock_client.get_site_to_site_vpns.return_value = []
        mock_client.get_remote_access_vpns.return_value = []
        mock_client.get_wireguard.return_value = []
        mock_client.get_vpn_users.return_value = []
        mock_client.get_ssl_vpn.return_value = {}
        mock_client.get_eogre_tunnel.return_value = {}
        mock_client.get_ipsec_failover.return_value = []
        mock_client.get_dhcp_scopes.return_value = []
        mock_client.get_dhcp_leases.return_value = []
        mock_client.get_radius_profiles.return_value = []
        mock_client.get_portals.return_value = []
        mock_client.get_time_range_profiles.return_value = []
        mock_client.get_rate_limit_profiles.return_value = []
        mock_client.get_wireless_settings.return_value = {}
        mock_client.get_ap_radios.return_value = []
        mock_client.get_wan_failover.return_value = {}
        mock_client.get_dns_settings.return_value = {}
        mock_client.get_time_settings.return_value = {}
        mock_client.get_multicast_services.return_value = {}
        mock_client.get_lags.return_value = {}
        mock_client.get_switch_settings.return_value = {}
        mock_client.get_port_schedules.return_value = {}
        mock_client.get_uplinks.return_value = {}
        mock_client.get_switch_port_sheets.return_value = []
        mock_client.get_switch_security.return_value = {}
        mock_client.get_oui_vlans.return_value = {}
        mock_client.get_switch_qos.return_value = {}
        mock_client.get_port_labels.return_value = []

        service = OmadaService(
            client=mock_client,
            site_id="site-001",
            output_dir=str(tmp_path),
        )
        data = service.fetch_all()
        assert data["acl_rules"] == [{"name": "rule1"}]
        assert data["networks"] == [{"name": "LAN"}]
        mock_client.get_acl_rules.assert_called_once_with("site-001")
