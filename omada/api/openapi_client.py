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
from urllib.parse import urljoin

import requests
import urllib3

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
        params={"client_id": client_id, "omadac_id": omadac_id},
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
            "omadac_id": omadac_id,
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


def openapi_discover_site_id(
    base_url: str,
    omadac_id: str,
    session: requests.Session,
    *,
    site_name: str = "",
    timeout: int = 30,
) -> str:
    """Discover a site ID via the Open API.

    Parameters
    ----------
    session:
        An authenticated session from :func:`openapi_login`.
    site_name:
        Human-readable site name to match (case-insensitive).

    Returns
    -------
    str
        The site ID.
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
                return site_id
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
        return site_id

    lines = ["Multiple sites found. Please select a site by name or id:"]
    for s in sites:
        sid = s.get("siteId", s.get("id", "?"))
        lines.append(f"  • {s.get('name', '?')}  (id: {sid})")
    raise RuntimeError("\n".join(lines))


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

class OmadaOpenApiClient:
    """HTTP client for the Omada Open API (Northbound API).

    Provides the same ``get_*`` method interface as
    :class:`~omada.api.client.OmadaClient` so it can be used as a
    drop-in replacement in :class:`~omada.service.OmadaService`.

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
            return self._get(f"sites/{site_id}/internet/basic")
        except OmadaAPIError:
            pass
        # Virtual WANs
        try:
            return self._get(f"sites/{site_id}/setting/virtual-wans")
        except OmadaAPIError:
            return {}

    def get_ssids(self, site_id: str) -> list[dict[str, Any]]:
        """Return all SSIDs across all WLANs for the given site."""
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
                for ssid in wlan_ssids:
                    ssid.setdefault("wlanName", wlan.get("name", ""))
                ssids.extend(wlan_ssids)
            except OmadaAPIError:
                pass

        return ssids

    def get_dhcp_reservations(self, site_id: str) -> list[dict[str, Any]]:
        """Return DHCP reservations for the site.

        Endpoint: ``GET /sites/{siteId}/setting/service/dhcp``
        """
        return self._get_paged(f"sites/{site_id}/setting/service/dhcp")
