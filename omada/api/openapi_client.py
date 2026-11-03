"""Omada Open API (Northbound API) client.

Supports the official Omada Open API using both OAuth2 authentication
modes documented in the TP-Link Open API Access Guide:

* **Client Credentials Mode** — direct token exchange using
  ``client_id``, ``client_secret``, and ``omadacId``.
* **Authorization Code Mode** — three-step flow: login with user
  credentials, obtain an authorization code, then exchange for a token.

The base-path prefix is ``/openapi/v1/{omadacId}/…`` (or ``/openapi/v2/``
for a handful of newer endpoints).

This module also provides:

* :func:`openapi_login` — Client Credentials Mode token exchange.
* :func:`openapi_auth_code_login` — Authorization Code Mode (3-step).
* :func:`openapi_discover_site_id` — list sites and select by name.
* :func:`discover_controller_id` — ``GET /api/info`` to find omadacId.
"""

from __future__ import annotations

import logging
import warnings
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urljoin

import requests
import urllib3

from omada.redaction import REDACTED, redact_secrets  # noqa: F401  (REDACTED re-exported)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Shared utilities
# ---------------------------------------------------------------------------

class OmadaAPIError(Exception):
    """Raised when the Omada controller returns an error response."""

    def __init__(self, error_code: int, message: str) -> None:
        self.error_code = error_code
        super().__init__(f"Omada API error {error_code}: {message}")


def _make_session(verify_ssl: bool, base_url: str) -> requests.Session:
    """Create a :class:`requests.Session` with optional TLS verification."""
    sess = requests.Session()
    sess.headers.update({"Content-Type": "application/json"})
    if not verify_ssl:
        sess.verify = False
        warnings.warn(
            f"TLS certificate verification is disabled for {base_url}. "
            "This makes the connection vulnerable to MITM attacks.",
            urllib3.exceptions.InsecureRequestWarning,
            stacklevel=3,
        )
    return sess


def discover_controller_id(
    base_url: str,
    *,
    verify_ssl: bool = True,
    timeout: int = 30,
) -> str:
    """Discover the controller ID (``omadacId``) from ``GET /api/info``.

    This endpoint is unauthenticated and works regardless of auth mode.
    """
    url = base_url.rstrip("/") + "/api/info"
    sess = _make_session(verify_ssl, base_url)
    resp = sess.get(url, timeout=timeout)
    resp.raise_for_status()
    body = resp.json()
    error_code = body.get("errorCode", -1)
    if error_code != 0:
        raise OmadaAPIError(error_code, body.get("msg", "unknown error"))
    result = body.get("result", {})
    cid = result.get("omadacId", "")
    if not cid:
        raise RuntimeError(
            "Could not determine controller ID: 'omadacId' not found "
            "in /api/info response"
        )
    logger.info("Discovered controller ID: %s", cid)
    return cid


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

@dataclass
class OpenApiLoginResult:
    """Result of a successful login (either auth mode)."""

    access_token: str
    session: requests.Session
    base_url: str


def openapi_login(
    base_url: str,
    omadac_id: str,
    client_id: str,
    client_secret: str,
    *,
    verify_ssl: bool = True,
    timeout: int = 30,
) -> OpenApiLoginResult:
    """Authenticate via **Client Credentials Mode** and return a session.

    Endpoint: ``POST /openapi/authorize/token?grant_type=client_credentials``

    Parameters
    ----------
    base_url:
        Controller base URL, e.g. ``https://192.168.1.1:8043``.
    omadac_id:
        The Omada controller ID.
    client_id, client_secret:
        Open API application credentials.
    """
    sess = _make_session(verify_ssl, base_url)
    base = base_url.rstrip("/")
    token_url = f"{base}/openapi/authorize/token"

    resp = sess.post(
        token_url,
        params={"grant_type": "client_credentials"},
        json={
            "omadacId": omadac_id,
            "client_id": client_id,
            "client_secret": client_secret,
        },
        timeout=timeout,
    )
    resp.raise_for_status()
    body = resp.json()

    error_code = body.get("errorCode", -1)
    if error_code != 0:
        raise OmadaAPIError(error_code, body.get("msg", "unknown error"))

    result = body.get("result", {})
    access_token = result.get("accessToken", "")
    if not access_token:
        raise RuntimeError(
            "Open API login succeeded but no accessToken was returned"
        )

    sess.headers.update({"Authorization": f"AccessToken={access_token}"})
    logger.info("Client Credentials login successful — token obtained")
    return OpenApiLoginResult(
        access_token=access_token, session=sess, base_url=base,
    )


def openapi_auth_code_login(
    base_url: str,
    omadac_id: str,
    client_id: str,
    client_secret: str,
    username: str,
    password: str,
    *,
    verify_ssl: bool = True,
    timeout: int = 30,
) -> OpenApiLoginResult:
    """Authenticate via **Authorization Code Mode** (3-step) and return a session.

    Steps per TP-Link Open API docs §2.2:

    1. ``POST /openapi/authorize/login`` — log in with user credentials.
    2. ``POST /openapi/authorize/code``  — obtain an authorization code.
    3. ``POST /openapi/authorize/token`` — exchange the code for a token.

    Parameters
    ----------
    base_url:
        Controller base URL, e.g. ``https://192.168.1.1:8043``.
    omadac_id:
        The Omada controller ID.
    client_id, client_secret:
        Open API application credentials.
    username, password:
        Omada controller user credentials.
    """
    sess = _make_session(verify_ssl, base_url)
    base = base_url.rstrip("/")

    # Step 1 — Login
    login_url = f"{base}/openapi/authorize/login"
    login_resp = sess.post(
        login_url,
        params={"client_id": client_id, "omadacId": omadac_id},
        json={"username": username, "password": password},
        timeout=timeout,
    )
    login_resp.raise_for_status()
    login_body = login_resp.json()

    login_error = login_body.get("errorCode", -1)
    if login_error != 0:
        raise OmadaAPIError(login_error, login_body.get("msg", "login failed"))

    login_result = login_body.get("result", {})
    csrf_token = login_result.get("csrfToken", "")
    session_id = login_result.get("sessionId", "")
    if not csrf_token or not session_id:
        raise RuntimeError(
            "Authorization Code login succeeded but csrfToken/sessionId missing"
        )

    # Step 2 — Obtain authorization code
    code_url = f"{base}/openapi/authorize/code"
    code_resp = sess.post(
        code_url,
        params={
            "client_id": client_id,
            "omadacId": omadac_id,
            "response_type": "code",
        },
        headers={
            "Csrf-Token": csrf_token,
            "Cookie": f"TPOMADA_SESSIONID={session_id}",
        },
        timeout=timeout,
    )
    code_resp.raise_for_status()
    code_body = code_resp.json()

    code_error = code_body.get("errorCode", -1)
    if code_error != 0:
        raise OmadaAPIError(code_error, code_body.get("msg", "authorize failed"))

    auth_code = code_body.get("result", "")
    if not auth_code:
        raise RuntimeError(
            "Authorization Code grant succeeded but no code was returned"
        )

    # Step 3 — Exchange authorization code for access token
    token_url = f"{base}/openapi/authorize/token"
    token_resp = sess.post(
        token_url,
        params={
            "grant_type": "authorization_code",
            "code": auth_code,
        },
        json={
            "omadacId": omadac_id,
            "client_id": client_id,
            "client_secret": client_secret,
        },
        timeout=timeout,
    )
    token_resp.raise_for_status()
    token_body = token_resp.json()

    token_error = token_body.get("errorCode", -1)
    if token_error != 0:
        raise OmadaAPIError(token_error, token_body.get("msg", "token exchange failed"))

    token_result = token_body.get("result", {})
    access_token = token_result.get("accessToken", "")
    if not access_token:
        raise RuntimeError(
            "Authorization Code token exchange succeeded but no accessToken "
            "was returned"
        )

    # Prepare session for subsequent API calls
    sess.headers.update({"Authorization": f"AccessToken={access_token}"})
    # Clear login cookies — we only need the bearer token going forward
    sess.cookies.clear()
    logger.info("Authorization Code login successful — token obtained")
    return OpenApiLoginResult(
        access_token=access_token, session=sess, base_url=base,
    )


def openapi_discover_site(
    base_url: str,
    omadac_id: str,
    session: requests.Session,
    *,
    site_name: str = "",
    timeout: int = 30,
) -> tuple[str, str]:
    """Discover a site's ID and display name via the Open API.

    Parameters
    ----------
    session:
        An authenticated session from :func:`openapi_login`.
    site_name:
        Human-readable site name to match (case-insensitive).

    Returns
    -------
    tuple[str, str]
        The site ID and display name.
    """
    url = (
        f"{base_url.rstrip('/')}/openapi/v1/{omadac_id}/sites"
        "?page=1&pageSize=1000"
    )
    resp = session.get(url, timeout=timeout)
    resp.raise_for_status()
    body = resp.json()

    error_code = body.get("errorCode", -1)
    if error_code != 0:
        raise OmadaAPIError(error_code, body.get("msg", "unknown error"))

    result = body.get("result", {})
    if isinstance(result, dict):
        sites = result.get("data", [])
    elif isinstance(result, list):
        sites = result
    else:
        raise RuntimeError("Unexpected response format from Open API /sites")

    if not sites:
        raise RuntimeError("No sites found via Open API")

    needle = site_name.strip().casefold()
    if needle:
        for s in sites:
            if s.get("name", "").strip().casefold() == needle:
                site_id = s.get("siteId", s.get("id", ""))
                logger.info(
                    "Matched site by name: %s (%s)", s.get("name"), site_id,
                )
                return site_id, s.get("name", "")
        available = ", ".join(s.get("name", "?") for s in sites)
        raise RuntimeError(
            f"No site named '{site_name.strip()}' found. "
            f"Available sites: {available}"
        )

    if len(sites) == 1:
        site_id = sites[0].get("siteId", sites[0].get("id", ""))
        logger.info(
            "Auto-selected site: %s (%s)", sites[0].get("name"), site_id,
        )
        return site_id, sites[0].get("name", "")

    lines = ["Multiple sites found. Please select a site by name or id:"]
    for s in sites:
        sid = s.get("siteId", s.get("id", "?"))
        lines.append(f"  • {s.get('name', '?')}  (id: {sid})")
    raise RuntimeError("\n".join(lines))


def openapi_discover_site_id(
    base_url: str,
    omadac_id: str,
    session: requests.Session,
    *,
    site_name: str = "",
    timeout: int = 30,
) -> str:
    """Discover a site ID via the Open API."""
    site_id, _ = openapi_discover_site(
        base_url,
        omadac_id,
        session,
        site_name=site_name,
        timeout=timeout,
    )
    return site_id


def _sort_ports(ports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Sort port dicts numerically by their ``port`` field when possible."""
    def key(port: dict[str, Any]) -> tuple[int, Any]:
        value = port.get("port")
        return (0, value) if isinstance(value, int) else (1, str(value))
    return sorted(ports, key=key)


#: LAN-network keys that define the DHCP service for that network.
_DHCP_SCOPE_KEYS: tuple[str, ...] = (
    "id", "name", "purpose", "vlan", "vlanType", "vlans", "gatewaySubnet", "domain",
    "deviceType", "deviceMac", "mode", "dhcpSettings", "dhcpSettingsVO", "dhcpServer",
    "dhcpRelay", "dhcpL2RelayEnable", "dhcpGuard", "dhcpv6Guard", "dhcpServerNum",
    "totalIpNum", "existCustomDhcpOption", "existDhcpNextServer",
    "lanNetworkIpv6Config", "lanNeworkIpv6Config",
)


# Credential redaction lives in omada.redaction; these aliases keep the
# client's VPN/wireless getters (and existing imports) working.
_redact_secrets = redact_secrets


def _normalize_mac(mac: Any) -> str:
    """Normalize a MAC address for comparison (``aa:bb`` → ``AA-BB``)."""
    return str(mac).strip().upper().replace(":", "-")


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

class OmadaOpenApiClient:
    """HTTP client for the Omada Open API (Northbound API).

    Provides ``get_*`` methods consumed by
    :class:`~omada.service.OmadaService`.

    Parameters
    ----------
    base_url:
        Controller / cloud base URL.
    omadac_id:
        The Omada controller ID.
    access_token:
        A valid access token from :func:`openapi_login`.
    verify_ssl:
        Whether to verify TLS certificates.
    timeout:
        Request timeout in seconds.
    session:
        An authenticated :class:`requests.Session` (from
        :func:`openapi_login`).
    """

    def __init__(
        self,
        base_url: str,
        omadac_id: str,
        access_token: str,
        *,
        verify_ssl: bool = True,
        timeout: int = 30,
        session: requests.Session | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.omadac_id = omadac_id
        #: When True, credentials are returned as-is instead of redacted.
        #: Set via ``OmadaService(include_secrets=True)``.
        self.include_secrets = False
        self.access_token = access_token
        self.timeout = timeout

        if session is not None:
            self._session = session
        else:
            self._session = requests.Session()
            self._session.headers.update({
                "Authorization": f"AccessToken={access_token}",
                "Content-Type": "application/json",
            })
            if not verify_ssl:
                self._session.verify = False
                warnings.warn(
                    f"TLS certificate verification is disabled for {base_url}. "
                    "This makes the connection vulnerable to MITM attacks.",
                    urllib3.exceptions.InsecureRequestWarning,
                    stacklevel=2,
                )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _redact(self, data: Any) -> Any:
        """Redact credentials unless :attr:`include_secrets` is set."""
        return data if self.include_secrets else _redact_secrets(data)

    def _api_url(self, path: str, *, api_version: str = "v1") -> str:
        """Build a full URL from a relative Open API *path*."""
        prefix = f"/openapi/{api_version}/{self.omadac_id}/"
        relative = path.lstrip("/")
        return urljoin(self.base_url + prefix, relative)

    def _get(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        *,
        api_version: str = "v1",
    ) -> Any:
        """Perform a GET request and return the ``result`` payload."""
        url = self._api_url(path, api_version=api_version)
        logger.debug("OPENAPI GET %s params=%s", url, params)
        resp = self._session.get(
            url, params=params or {}, timeout=self.timeout,
        )
        resp.raise_for_status()
        body: dict[str, Any] = resp.json()

        logger.debug(
            "OpenAPI response for %s: status=%d, body keys=%s",
            path, resp.status_code,
            list(body.keys()) if isinstance(body, dict) else type(body).__name__,
        )

        if "errorCode" in body:
            error_code: int = body["errorCode"]
            if error_code != 0:
                raise OmadaAPIError(error_code, body.get("msg", "unknown error"))

        result = body.get("result", body)
        if isinstance(result, dict):
            logger.debug("OpenAPI result for %s: keys=%s", path, list(result.keys()))
        elif isinstance(result, list):
            logger.debug("OpenAPI result for %s: list with %d item(s)", path, len(result))
        return result

    def _get_paged(
        self,
        path: str,
        *,
        page_size: int = 100,
        max_pages: int = 200,
        api_version: str = "v1",
    ) -> list[dict[str, Any]]:
        """Fetch all pages for a paginated Open API endpoint.

        The Open API uses ``page`` and ``pageSize`` query parameters
        (as opposed to ``currentPage``/``currentPageSize``).
        """
        items: list[dict[str, Any]] = []
        for page in range(1, max_pages + 1):
            params = {"page": page, "pageSize": page_size}
            result = self._get(path, params=params, api_version=api_version)

            if isinstance(result, list):
                items.extend(result)
                break

            data = result.get("data", [])
            if not data and page == 1 and isinstance(result, dict):
                # Auto-detect: find any value that is a non-empty list of dicts
                for key, val in result.items():
                    if (
                        key not in ("totalRows", "currentPage", "currentSize")
                        and isinstance(val, list)
                        and val
                        and isinstance(val[0], dict)
                    ):
                        data = val
                        logger.debug(
                            "OpenAPI pagination for %s: auto-detected data "
                            "under '%s' key (%d item(s))",
                            path, key, len(val),
                        )
                        break

            items.extend(data)
            total_rows = result.get("totalRows", len(items))
            if len(items) >= total_rows:
                break
        else:
            logger.warning(
                "OpenAPI pagination reached max_pages=%d for %s; "
                "%d record(s) collected.",
                max_pages, path, len(items),
            )
        return items

    # ------------------------------------------------------------------
    # Public API methods
    # ------------------------------------------------------------------

    def get_devices(self, site_id: str) -> list[dict[str, Any]]:
        """Return the adopted devices for the given site."""
        return self._get_paged(f"sites/{site_id}/devices")

    def get_device_ports(self, site_id: str) -> list[dict[str, Any]]:
        """Return port configuration for every switch and gateway in the site.

        Each returned record is a port dict tagged with its owning device
        (``deviceName``, ``deviceMac``, ``deviceType``, ``deviceModel``).

        * Switches: ``GET sites/{siteId}/switches/ports/overview`` (one
          site-wide call: label, connection, type, operation, profile, native
          network).  Falls back to ``portList`` from
          ``GET sites/{siteId}/switches/{mac}`` for any switch missing there.
        * Gateways: ``portConfigs`` from ``GET sites/{siteId}/gateways/{mac}``,
          ``osgPortInfos`` from ``GET sites/{siteId}/gateways/{mac}/ports`` and
          link status from ``GET sites/{siteId}/gateways/{mac}/wan-status``,
          merged by port number.

        Devices of other types (e.g. access points) are skipped.  A failure
        for one device is logged and does not prevent the others.
        """
        fetchers = {
            "switch": self._get_switch_ports,
            "gateway": self._get_gateway_ports,
        }
        devices = self.get_devices(site_id)
        overview = self._get_switch_port_overview(site_id, devices)
        all_ports: list[dict[str, Any]] = []
        for device in devices:
            device_type = str(device.get("type", device.get("deviceType", ""))).lower()
            fetcher = fetchers.get(device_type)
            device_mac = device.get("mac", device.get("deviceMac", ""))
            if fetcher is None or not device_mac:
                continue
            device_name = device.get("name", device.get("deviceName", ""))
            try:
                if device_type == "switch" and _normalize_mac(device_mac) in overview:
                    ports = _sort_ports(overview[_normalize_mac(device_mac)])
                else:
                    ports = fetcher(site_id, str(device_mac))
            except (OmadaAPIError, requests.RequestException) as exc:
                logger.warning(
                    "Unable to enumerate ports for %s %s (%s): %s",
                    device_type, device_name or "unknown", device_mac, exc,
                )
                continue
            for port in ports:
                all_ports.append({
                    "deviceName": device_name,
                    "deviceMac": device_mac,
                    "deviceType": device_type,
                    "deviceModel": device.get("model", ""),
                    **port,
                })
        return all_ports

    def _get_switch_port_overview(
        self, site_id: str, devices: list[dict[str, Any]],
    ) -> dict[str, list[dict[str, Any]]]:
        """Return site-wide switch port overview grouped by normalized MAC.

        Returns an empty mapping when the site has no switches or the
        endpoint is unavailable (callers then fall back per switch).
        """
        has_switch = any(
            str(d.get("type", d.get("deviceType", ""))).lower() == "switch"
            for d in devices
        )
        if not has_switch:
            return {}
        try:
            records = self._get_paged(f"sites/{site_id}/switches/ports/overview")
        except (OmadaAPIError, requests.RequestException) as exc:
            logger.warning(
                "Switch port overview unavailable; falling back to "
                "per-switch lookup: %s", exc,
            )
            return {}
        grouped: dict[str, list[dict[str, Any]]] = {}
        for record in records:
            if isinstance(record, dict) and record.get("switchMac"):
                grouped.setdefault(_normalize_mac(record["switchMac"]), []).append(record)
        return grouped

    def _get_switch_ports(self, site_id: str, mac: str) -> list[dict[str, Any]]:
        """Return the ``portList`` of a switch."""
        info = self._get(f"sites/{site_id}/switches/{quote(mac, safe='')}")
        ports = info.get("portList", []) if isinstance(info, dict) else []
        return _sort_ports([p for p in ports or [] if isinstance(p, dict)])

    def _get_gateway_ports(self, site_id: str, mac: str) -> list[dict[str, Any]]:
        """Return gateway port configs merged with gateway port info."""
        base = f"sites/{site_id}/gateways/{quote(mac, safe='')}"
        merged: dict[Any, dict[str, Any]] = {}
        errors: list[Exception] = []

        try:
            info = self._get(base)
            configs = info.get("portConfigs", []) if isinstance(info, dict) else []
            for cfg in configs or []:
                if isinstance(cfg, dict):
                    merged.setdefault(cfg.get("port"), {}).update(cfg)
        except (OmadaAPIError, requests.RequestException) as exc:
            errors.append(exc)

        try:
            result = self._get(f"{base}/ports")
            infos = result.get("osgPortInfos", []) if isinstance(result, dict) else result
            for item in infos or []:
                if isinstance(item, dict):
                    entry = merged.setdefault(item.get("port"), {})
                    for key, value in item.items():
                        entry.setdefault(key, value)
        except (OmadaAPIError, requests.RequestException) as exc:
            errors.append(exc)

        # Link status per port.  Its ``status`` means connected/disconnected
        # (unlike portConfigs' enabled/disabled), so it is stored under
        # ``portStatus`` in the same shape the switch overview uses.
        try:
            result = self._get(f"{base}/wan-status")
            for item in result if isinstance(result, list) else []:
                if not isinstance(item, dict):
                    continue
                entry = merged.setdefault(item.get("port"), {"port": item.get("port")})
                for key in ("name", "type", "mode"):
                    if item.get(key) is not None:
                        entry.setdefault(key, item[key])
                entry["portStatus"] = {
                    "linkStatus": item.get("status"),
                    "linkSpeed": item.get("speed"),
                    "duplex": item.get("duplex"),
                }
        except (OmadaAPIError, requests.RequestException) as exc:
            errors.append(exc)

        if len(errors) == 3:
            raise errors[0]
        return _sort_ports(list(merged.values()))

    def get_acl_rules(self, site_id: str) -> list[dict[str, Any]]:
        """Return all ACL rules (gateway + switch) for the given site."""
        acls: list[dict[str, Any]] = []
        # Gateway ACLs
        try:
            gateway_acls = self._get_paged(f"sites/{site_id}/acls/osg-acls")
            for a in gateway_acls:
                a.setdefault("aclType", "gateway")
            acls.extend(gateway_acls)
        except OmadaAPIError as exc:
            logger.debug("Gateway ACLs unavailable: %s", exc)
        # Switch ACLs
        try:
            switch_acls = self._get_paged(f"sites/{site_id}/acls/osw-acls")
            for a in switch_acls:
                a.setdefault("aclType", "switch")
            acls.extend(switch_acls)
        except OmadaAPIError as exc:
            logger.debug("Switch ACLs unavailable: %s", exc)
        # EAP ACLs
        try:
            eap_acls = self._get_paged(f"sites/{site_id}/acls/eap-acls")
            for a in eap_acls:
                a.setdefault("aclType", "eap")
            acls.extend(eap_acls)
        except OmadaAPIError as exc:
            logger.debug("EAP ACLs unavailable: %s", exc)
        return acls

    def get_ip_groups(self, site_id: str) -> list[dict[str, Any]]:
        """Return IP group profiles (groupType=0) for the given site."""
        try:
            result = self._get(f"sites/{site_id}/profiles/groups/0")
            return result if isinstance(result, list) else []
        except OmadaAPIError:
            # Fallback: get all groups and filter
            result = self._get(f"sites/{site_id}/profiles/groups")
            if isinstance(result, list):
                return [g for g in result if g.get("type") == 0]
            return []

    def get_port_groups(self, site_id: str) -> list[dict[str, Any]]:
        """Return IP-Port group profiles (groupType=1) for the given site."""
        try:
            result = self._get(f"sites/{site_id}/profiles/groups/1")
            return result if isinstance(result, list) else []
        except OmadaAPIError:
            result = self._get(f"sites/{site_id}/profiles/groups")
            if isinstance(result, list):
                return [g for g in result if g.get("type") == 1]
            return []

    def get_networks(self, site_id: str) -> list[dict[str, Any]]:
        """Return all LAN networks for the given site."""
        try:
            result = self._get(f"sites/{site_id}/lan-networks/all")
            return result if isinstance(result, list) else []
        except OmadaAPIError:
            return self._get_paged(f"sites/{site_id}/lan-networks")

    def get_vlans(self, site_id: str) -> list[dict[str, Any]]:
        """Return VLAN configuration for the given site."""
        networks = self.get_networks(site_id)
        vlans = [n for n in networks if n.get("vlan") is not None or n.get("vlanId") is not None]
        return vlans if vlans else networks

    def get_switch_port_profiles(self, site_id: str) -> list[dict[str, Any]]:
        """Return switch port / LAN profiles for the given site."""
        try:
            return self._get_paged(f"sites/{site_id}/lan-profiles")
        except OmadaAPIError:
            pass
        try:
            return self._get_paged(
                f"sites/{site_id}/lan-profiles", api_version="v2",
            )
        except OmadaAPIError:
            pass
        try:
            return self._get_paged(f"sites/{site_id}/lan-switch-setting")
        except OmadaAPIError:
            return []

    def get_gateway_settings(self, site_id: str) -> dict[str, Any] | list[dict[str, Any]]:
        """Return gateway / WAN settings for the given site."""
        # Try internet ports-config first (most detailed)
        try:
            return self._get(f"sites/{site_id}/internet/ports-config")
        except OmadaAPIError:
            pass
        # Fallback to basic internet info
        try:
            return self._get(f"sites/{site_id}/internet/basic-info")
        except OmadaAPIError:
            pass
        # Virtual WANs
        try:
            return self._get(f"sites/{site_id}/setting/virtual-wans")
        except OmadaAPIError:
            return {}

    def get_ssids(self, site_id: str) -> list[dict[str, Any]]:
        """Return all SSIDs across all WLANs, with full per-SSID settings.

        The SSID list (``.../wlans/{wlanId}/ssids``) is only a summary, so each
        SSID is merged with its detail (``.../wireless-network/ssids/{ssidId}``,
        falling back to ``.../wlans/{wlanId}/ssids/{ssidId}``): security
        settings and RADIUS profile, rate limits, WLAN schedule, band
        steering, rate control, MAC filter, multicast, DHCP option 82,
        Hotspot 2.0.  Per-AP SSID overrides
        (``.../wireless-network/ssids/{ssidId}/overrides``) are added as
        ``apOverrides``.  Detail and override lookups are best-effort.
        Credentials (e.g. the WPA passphrase) are redacted.
        """
        try:
            wlans_result = self._get_paged(
                f"sites/{site_id}/wireless-network/wlans",
            )
        except OmadaAPIError:
            return []

        wlans = wlans_result if isinstance(wlans_result, list) else []

        ssids: list[dict[str, Any]] = []
        for wlan in wlans:
            wlan_id = wlan.get("wlanId", wlan.get("id", ""))
            if not wlan_id:
                continue
            try:
                wlan_ssids = self._get_paged(
                    f"sites/{site_id}/wireless-network/wlans/{wlan_id}/ssids",
                )
            except OmadaAPIError:
                continue
            for ssid in wlan_ssids:
                ssid.setdefault("wlanName", wlan.get("name", ""))
                ssid.setdefault("wlanId", wlan_id)
                ssids.append(self._enrich_ssid(site_id, str(wlan_id), ssid))

        return self._redact(ssids)

    def _enrich_ssid(self, site_id: str, wlan_id: str, ssid: dict[str, Any]) -> dict[str, Any]:
        """Merge SSID detail and AP overrides into a list record."""
        ssid_id = ssid.get("id", ssid.get("ssidId", ""))
        if not ssid_id:
            return ssid
        sid = quote(str(ssid_id), safe="")
        detail: Any = None
        for path in (
            f"sites/{site_id}/wireless-network/ssids/{sid}",
            f"sites/{site_id}/wireless-network/wlans/{quote(wlan_id, safe='')}/ssids/{sid}",
        ):
            try:
                detail = self._get(path)
                break
            except (OmadaAPIError, requests.RequestException) as exc:
                logger.debug("SSID detail unavailable via %s: %s", path, exc)
        if isinstance(detail, dict):
            ssid = {**ssid, **detail}
        try:
            overrides = self._get_paged(f"sites/{site_id}/wireless-network/ssids/{sid}/overrides")
            if overrides:
                ssid["apOverrides"] = overrides
        except (OmadaAPIError, requests.RequestException) as exc:
            logger.debug("SSID overrides unavailable for %s: %s", ssid.get("name"), exc)
        return ssid

    def get_dhcp_reservations(self, site_id: str) -> list[dict[str, Any]]:
        """Return DHCP reservations for the site.

        Endpoint: ``GET /sites/{siteId}/setting/service/dhcp``
        """
        return self._get_paged(f"sites/{site_id}/setting/service/dhcp")

    def get_port_forwarding(self, site_id: str) -> list[dict[str, Any]]:
        """Return gateway port forwarding rules for the site.

        Endpoint: ``GET /sites/{siteId}/nat/port-forwardings``
        """
        return self._get_paged(f"sites/{site_id}/nat/port-forwardings")

    def get_one_to_one_nat(self, site_id: str) -> list[dict[str, Any]]:
        """Return One-to-One NAT rules for the site.

        Endpoint: ``GET /sites/{siteId}/nat/one-to-one-nat``
        """
        return self._get_paged(f"sites/{site_id}/nat/one-to-one-nat")

    def get_alg_settings(self, site_id: str) -> dict[str, Any]:
        """Return NAT Application Layer Gateway (ALG) settings for the site.

        Endpoint: ``GET /sites/{siteId}/nat/alg``
        """
        result = self._get(f"sites/{site_id}/nat/alg")
        return result if isinstance(result, dict) else {}

    def get_static_routes(self, site_id: str) -> list[dict[str, Any]]:
        """Return gateway and switch static routes for the site.

        * Gateway: ``GET /sites/{siteId}/routing/static-routings`` (tagged
          ``routeSource: gateway``).  Interface IDs are resolved to names via
          ``GET /sites/{siteId}/routing/static-routings/interfaces`` and stored
          as ``interfaceName``.
        * Switches: ``GET /sites/{siteId}/switches/{mac}/staticRoutings`` for
          each switch (tagged ``routeSource: switch`` plus ``deviceName`` /
          ``deviceMac``).  Switches without L3 routing are skipped quietly.
        """
        routes: list[dict[str, Any]] = []

        try:
            gateway_routes = self._get_paged(f"sites/{site_id}/routing/static-routings")
        except (OmadaAPIError, requests.RequestException) as exc:
            logger.warning("Gateway static routes unavailable: %s", exc)
            gateway_routes = []
        if gateway_routes:
            interface_names = self._static_route_interface_names(site_id)
            for route in gateway_routes:
                route.setdefault("routeSource", "gateway")
                name = interface_names.get(str(route.get("interfaceId", "")))
                if name:
                    route.setdefault("interfaceName", name)
            routes.extend(gateway_routes)

        for device in self.get_devices(site_id):
            if str(device.get("type", device.get("deviceType", ""))).lower() != "switch":
                continue
            mac = device.get("mac", device.get("deviceMac", ""))
            if not mac:
                continue
            try:
                switch_routes = self._get_paged(
                    f"sites/{site_id}/switches/{quote(str(mac), safe='')}/staticRoutings",
                )
            except (OmadaAPIError, requests.RequestException) as exc:
                logger.debug("Static routes unavailable for switch %s: %s", mac, exc)
                continue
            for route in switch_routes:
                route["routeSource"] = "switch"
                route["deviceName"] = device.get("name", route.get("name", ""))
                route["deviceMac"] = mac
            routes.extend(switch_routes)

        return routes

    def _static_route_interface_names(self, site_id: str) -> dict[str, str]:
        """Return static-route interface ID → name; empty if unavailable."""
        try:
            result = self._get(f"sites/{site_id}/routing/static-routings/interfaces")
        except (OmadaAPIError, requests.RequestException) as exc:
            logger.debug("Static route interface list unavailable: %s", exc)
            return {}
        infos = result.get("interfaceInfoList", []) if isinstance(result, dict) else []
        return {
            str(i["id"]): str(i.get("name") or i["id"])
            for i in infos or []
            if isinstance(i, dict) and i.get("id")
        }

    def get_policy_routes(self, site_id: str) -> list[dict[str, Any]]:
        """Return gateway policy routing rules for the site.

        Endpoint: ``GET /sites/{siteId}/routing/policy-routings``
        """
        return self._get_paged(f"sites/{site_id}/routing/policy-routings")

    # ------------------------------------------------------------------
    # VPN (all secrets are redacted before being returned)
    # ------------------------------------------------------------------

    def get_site_to_site_vpns(self, site_id: str) -> list[dict[str, Any]]:
        """Return site-to-site (Auto / Manual IPsec) VPN tunnels.

        Endpoint: ``GET /sites/{siteId}/vpn/site-to-site-vpns``
        """
        return self._redact(self._get_paged(f"sites/{site_id}/vpn/site-to-site-vpns"))

    def get_remote_access_vpns(self, site_id: str) -> list[dict[str, Any]]:
        """Return client-to-site VPN servers and clients, tagged ``vpnRole``.

        Endpoints: ``GET /sites/{siteId}/vpn/client-to-site-vpn-servers`` and
        ``GET /sites/{siteId}/vpn/client-to-site-vpn-clients``.  If only one of
        them fails, the other's tunnels are still returned.
        """
        tunnels: list[dict[str, Any]] = []
        errors: list[Exception] = []
        for role, path in (
            ("server", "client-to-site-vpn-servers"),
            ("client", "client-to-site-vpn-clients"),
        ):
            try:
                items = self._get_paged(f"sites/{site_id}/vpn/{path}")
            except (OmadaAPIError, requests.RequestException) as exc:
                logger.warning("Remote-access VPN %ss unavailable: %s", role, exc)
                errors.append(exc)
                continue
            for item in items:
                item["vpnRole"] = role
            tunnels.extend(items)
        if len(errors) == 2:
            raise errors[0]
        return self._redact(tunnels)

    def get_wireguard(self, site_id: str) -> list[dict[str, Any]]:
        """Return WireGuard interfaces, each with its ``peers`` nested.

        Endpoints: ``GET /sites/{siteId}/vpn/wireguards`` and
        ``GET /sites/{siteId}/vpn/wireguard-peers``.
        """
        interfaces = self._get_paged(f"sites/{site_id}/vpn/wireguards")
        try:
            peers = self._get_paged(f"sites/{site_id}/vpn/wireguard-peers")
        except (OmadaAPIError, requests.RequestException) as exc:
            logger.warning("WireGuard peers unavailable: %s", exc)
            peers = []
        by_id = {str(i.get("id")): i for i in interfaces if isinstance(i, dict)}
        for iface in by_id.values():
            iface.setdefault("peers", [])
        for peer in peers:
            if not isinstance(peer, dict):
                continue
            iface_id = str(peer.get("interfaceId", ""))
            if iface_id not in by_id:
                # Peer bound to an interface missing from the list: keep it visible.
                by_id[iface_id] = {"id": iface_id, "name": peer.get("interfaceName", iface_id), "peers": []}
                interfaces.append(by_id[iface_id])
            by_id[iface_id]["peers"].append(peer)
        return self._redact(interfaces)

    def get_vpn_users(self, site_id: str) -> list[dict[str, Any]]:
        """Return VPN user accounts (passwords redacted).

        Endpoint: ``GET /sites/{siteId}/vpn/users``
        """
        return self._redact(self._get_paged(f"sites/{site_id}/vpn/users"))

    def get_ssl_vpn(self, site_id: str) -> dict[str, Any]:
        """Return the SSL VPN server configuration (passwords redacted).

        ``setting`` comes from ``GET /sites/{siteId}/vpn/ssl-vpn-server/setting``
        (a failure there propagates).  The related lists are fetched best-effort
        from ``…/user-groups``, ``…/users``, ``…/resources``,
        ``…/resource-groups`` and ``…/radius`` and stored as ``userGroups``,
        ``users``, ``resources``, ``resourceGroups`` and ``radiusServers``.
        """
        base = f"sites/{site_id}/vpn/ssl-vpn-server"
        setting = self._get(f"{base}/setting")
        config: dict[str, Any] = {"setting": setting if isinstance(setting, dict) else {}}
        for key, path, paged in (
            ("userGroups", "user-groups", True),
            ("users", "users", True),
            ("resources", "resources", True),
            ("resourceGroups", "resource-groups", True),
            ("radiusServers", "radius", False),
        ):
            try:
                result = self._get_paged(f"{base}/{path}") if paged else self._get(f"{base}/{path}")
            except (OmadaAPIError, requests.RequestException) as exc:
                logger.warning("SSL VPN %s unavailable: %s", path, exc)
                result = []
            config[key] = result if isinstance(result, list) else []
        return self._redact(config)

    def get_eogre_tunnel(self, site_id: str) -> dict[str, Any]:
        """Return the EoGRE tunnel settings.

        Endpoint: ``GET /sites/{siteId}/vpn/gre-tunnel``
        """
        result = self._get(f"sites/{site_id}/vpn/gre-tunnel")
        return result if isinstance(result, dict) else {}

    def get_ipsec_failover(self, site_id: str) -> list[dict[str, Any]]:
        """Return IPsec failover groups.

        Endpoint: ``GET /sites/{siteId}/vpn/ipsec_failovers``
        """
        return self._get_paged(f"sites/{site_id}/vpn/ipsec_failovers")

    # ------------------------------------------------------------------
    # DHCP
    # ------------------------------------------------------------------

    def get_dhcp_scopes(self, site_id: str) -> list[dict[str, Any]]:
        """Return the DHCP service definition of every LAN network.

        Extracted from the LAN network list (see :meth:`get_networks`): which
        device serves DHCP (gateway / switch / external / none), the gateway
        ``dhcpSettings`` (pools, lease time, DNS, gateway, domain, options),
        switch ``dhcpServer`` / ``dhcpRelay``, DHCP L2 relay (option 82) and
        DHCP guarding.  For networks with DHCP enabled, current pool usage
        from ``GET /sites/{siteId}/networks/{networkId}/dhcp-server-info`` is
        added as ``poolStatus`` (best-effort).
        """
        scopes: list[dict[str, Any]] = []
        for network in self.get_networks(site_id):
            if not isinstance(network, dict):
                continue
            scope = {key: network[key] for key in _DHCP_SCOPE_KEYS if key in network}
            settings = scope.get("dhcpSettings") or scope.get("dhcpSettingsVO") or {}
            serving = (isinstance(settings, dict) and settings.get("enable")) or scope.get("mode") == 1
            if serving and scope.get("id"):
                try:
                    info = self._get(
                        f"sites/{site_id}/networks/{quote(str(scope['id']), safe='')}/dhcp-server-info",
                    )
                    ranges = info.get("ranges") if isinstance(info, dict) else None
                    if isinstance(ranges, list):
                        scope["poolStatus"] = ranges
                except (OmadaAPIError, requests.RequestException) as exc:
                    logger.debug("DHCP pool status unavailable for %s: %s", scope.get("name"), exc)
            scopes.append(scope)
        return scopes

    def get_dhcp_leases(self, site_id: str) -> list[dict[str, Any]]:
        """Return current DHCP leases across all DHCP servers in the site.

        Endpoint: ``GET /sites/{siteId}/setting/service/dhcp/user-list``
        """
        return self._get_paged(f"sites/{site_id}/setting/service/dhcp/user-list")

    # ------------------------------------------------------------------
    # Wireless profiles and site wireless settings
    # ------------------------------------------------------------------

    def get_radius_profiles(self, site_id: str) -> list[dict[str, Any]]:
        """Return RADIUS profiles (shared secrets redacted).

        Endpoint: ``GET /sites/{siteId}/profiles/radius``
        """
        result = self._get(f"sites/{site_id}/profiles/radius")
        return self._redact(result if isinstance(result, list) else [])

    def get_portals(self, site_id: str) -> list[dict[str, Any]]:
        """Return guest portals, each merged with its detail (credentials redacted).

        Endpoints: ``GET /sites/{siteId}/portals`` and, per portal,
        ``GET /sites/{siteId}/portal/{portalId}`` (best-effort).
        """
        result = self._get(f"sites/{site_id}/portals")
        portals = result if isinstance(result, list) else []
        merged = []
        for portal in portals:
            if not isinstance(portal, dict):
                continue
            if portal.get("id"):
                try:
                    detail = self._get(f"sites/{site_id}/portal/{quote(str(portal['id']), safe='')}")
                    if isinstance(detail, dict):
                        portal = {**portal, **detail}
                except (OmadaAPIError, requests.RequestException) as exc:
                    logger.debug("Portal detail unavailable for %s: %s", portal.get("name"), exc)
            merged.append(portal)
        return self._redact(merged)

    def get_time_range_profiles(self, site_id: str) -> list[dict[str, Any]]:
        """Return time range (schedule) profiles.

        Endpoint: ``GET /sites/{siteId}/time-range-profiles``
        """
        result = self._get(f"sites/{site_id}/time-range-profiles")
        return result if isinstance(result, list) else []

    def get_rate_limit_profiles(self, site_id: str) -> list[dict[str, Any]]:
        """Return client rate limit profiles.

        Endpoint: ``GET /sites/{siteId}/rate-limit-profiles``
        """
        result = self._get(f"sites/{site_id}/rate-limit-profiles")
        return result if isinstance(result, list) else []

    def get_wireless_settings(self, site_id: str) -> dict[str, Any]:
        """Return site-wide wireless settings, each part best-effort.

        ``bandSteering`` (``/band-steering``), ``roaming`` (``/roaming``),
        ``mesh`` (``/mesh``) and ``multicastRateLimit``
        (``/multicast-rate-limit``).  Raises only if every part fails.
        """
        settings: dict[str, Any] = {}
        errors: list[Exception] = []
        for key, path in (
            ("bandSteering", "band-steering"),
            ("roaming", "roaming"),
            ("mesh", "mesh"),
            ("multicastRateLimit", "multicast-rate-limit"),
        ):
            try:
                result = self._get(f"sites/{site_id}/{path}")
            except (OmadaAPIError, requests.RequestException) as exc:
                logger.warning("Wireless %s setting unavailable: %s", path, exc)
                errors.append(exc)
                continue
            settings[key] = result if isinstance(result, dict) else {}
        if len(errors) == 4:
            raise errors[0]
        return settings

    def get_ap_radios(self, site_id: str) -> list[dict[str, Any]]:
        """Return the radio configuration (overrides) of every access point.

        Endpoint: ``GET /sites/{siteId}/aps/{apMac}/radio-config`` per AP
        (``type: ap``).  Each record carries ``deviceName``, ``deviceMac``,
        ``deviceModel`` and ``radios`` (keyed ``2g``, ``5g``, ``5g1``, ``5g2``,
        ``6g``).  APs whose config is unavailable are logged and skipped.
        """
        records: list[dict[str, Any]] = []
        for device in self.get_devices(site_id):
            if str(device.get("type", device.get("deviceType", ""))).lower() != "ap":
                continue
            mac = device.get("mac", device.get("deviceMac", ""))
            if not mac:
                continue
            try:
                config = self._get(f"sites/{site_id}/aps/{quote(str(mac), safe='')}/radio-config")
            except (OmadaAPIError, requests.RequestException) as exc:
                logger.warning("Radio config unavailable for AP %s (%s): %s", device.get("name", ""), mac, exc)
                continue
            radios: dict[str, Any] = {}
            if isinstance(config, dict):
                for key, value in config.items():
                    if key.startswith("radioSetting") and isinstance(value, dict):
                        radios[key[len("radioSetting"):]] = value
            records.append({
                "deviceName": device.get("name", ""),
                "deviceMac": mac,
                "deviceModel": device.get("model", ""),
                "radios": radios,
            })
        return records

    # ------------------------------------------------------------------
    # WAN failover and site services
    # ------------------------------------------------------------------

    def _collect(
        self, site_id: str, parts: tuple[tuple[str, str, bool], ...], label: str,
    ) -> dict[str, Any]:
        """Fetch several site endpoints into one dict, each part best-effort.

        *parts* holds ``(key, path, paged)``.  A failing part is logged and
        omitted; :class:`OmadaAPIError` is raised only if every part fails.
        """
        result: dict[str, Any] = {}
        errors: list[Exception] = []
        for key, path, paged in parts:
            url = f"sites/{site_id}/{path}" if path else f"sites/{site_id}"
            try:
                value = self._get_paged(url) if paged else self._get(url)
            except (OmadaAPIError, requests.RequestException) as exc:
                logger.warning("%s: %s unavailable: %s", label, path, exc)
                errors.append(exc)
                continue
            result[key] = value
        if errors and len(errors) == len(parts):
            raise errors[0]
        return result

    def get_wan_failover(self, site_id: str) -> dict[str, Any]:
        """Return WAN load balancing / failover config and WAN health.

        * ``loadBalance``: ``GET /sites/{siteId}/internet/load-balance``
          (weights, link backup, primary / backup WANs, backup mode, trigger).
        * ``internet``: ``GET /sites/{siteId}/internet/basic-info`` (WAN port
          list and the online-detection (health check) interval).
        * ``wanHealth``: per gateway, ``GET .../gateways/{mac}/wan-status``
          (online / internet state, latency, packet loss, health level).
          This is a status snapshot, not configuration; best-effort.
        """
        data = self._collect(site_id, (
            ("loadBalance", "internet/load-balance", False),
            ("internet", "internet/basic-info", False),
        ), "WAN failover")
        health: list[dict[str, Any]] = []
        for device in self.get_devices(site_id):
            if str(device.get("type", device.get("deviceType", ""))).lower() != "gateway":
                continue
            mac = device.get("mac", device.get("deviceMac", ""))
            if not mac:
                continue
            try:
                status = self._get(f"sites/{site_id}/gateways/{quote(str(mac), safe='')}/wan-status")
            except (OmadaAPIError, requests.RequestException) as exc:
                logger.debug("WAN status unavailable for gateway %s: %s", mac, exc)
                continue
            for port in status if isinstance(status, list) else []:
                if isinstance(port, dict):
                    health.append({"gatewayName": device.get("name", ""), **port})
        if health:
            data["wanHealth"] = health
        return self._redact(data)

    def get_dns_settings(self, site_id: str) -> dict[str, Any]:
        """Return DNS proxy, DNS cache, LAN DNS records and Dynamic DNS.

        Endpoints: ``/setting/service/dns-proxy``, ``/setting/service/dns-cache``,
        ``/setting/lan/dns`` (paged) and ``/setting/service/ddns`` (paged).
        DDNS passwords are redacted.
        """
        return self._redact(self._collect(site_id, (
            ("dnsProxy", "setting/service/dns-proxy", False),
            ("dnsCache", "setting/service/dns-cache", False),
            ("lanDns", "setting/lan/dns", True),
            ("ddns", "setting/service/ddns", True),
        ), "DNS settings"))

    def get_time_settings(self, site_id: str) -> dict[str, Any]:
        """Return site timezone, NTP servers, DST and gateway NTP status.

        ``site`` from ``GET /sites/{siteId}`` (only ``name``, ``region``,
        ``timeZone``, ``ntpServers``, ``scenario`` are kept), ``dst`` from
        ``/dst-info`` and ``ntpStatus`` from ``/setting/ntp``.
        """
        data = self._collect(site_id, (
            ("site", "", False),
            ("dst", "dst-info", False),
            ("ntpStatus", "setting/ntp", False),
        ), "Time settings")
        site = data.get("site")
        if isinstance(site, dict):
            data["site"] = {
                k: site[k] for k in ("name", "region", "timeZone", "ntpServers", "scenario") if k in site
            }
        return data

    def get_multicast_services(self, site_id: str) -> dict[str, Any]:
        """Return multicast and service-discovery settings.

        IGMP proxy (``/setting/service/igmp``), MLD proxy
        (``/setting/service/mld``), IPTV (``/setting/service/iptv``), UPnP
        (``/upnp``), mDNS / Bonjour rules (``/setting/service/mdns``, paged),
        Bonjour service profiles (``/profiles/bonjour-service``) and LAN
        multicast (IGMP / MLD) snooping (``/lan-multicasts``, paged).
        """
        data = self._collect(site_id, (
            ("igmp", "setting/service/igmp", False),
            ("mld", "setting/service/mld", False),
            ("iptv", "setting/service/iptv", False),
            ("upnp", "upnp", False),
            ("mdnsRules", "setting/service/mdns", True),
            ("bonjourServices", "profiles/bonjour-service", False),
            ("lanMulticasts", "lan-multicasts", True),
        ), "Multicast services")
        bonjour = data.get("bonjourServices")
        if isinstance(bonjour, dict):  # {"data": [...]} wrapper
            data["bonjourServices"] = bonjour.get("data", [])
        return data
