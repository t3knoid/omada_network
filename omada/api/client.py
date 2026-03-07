"""Omada SDN Controller API client.

Supports the unofficial Omada SDN REST API (controller v5.x+).
Authentication uses a pre-obtained token passed via the ``Authorization``
header.  All path segments are built from the configurable ``base_url`` and
``controller_id`` so the client works with both self-hosted controllers and
cloud-managed instances.

The module also provides helper functions for **auto-discovery**:

* :func:`discover_controller_id` — ``GET /api/info``
* :func:`login` — ``POST /<omadacId>/api/v2/login``
* :func:`discover_site_id` — ``GET /<omadacId>/api/v2/sites``
"""

from __future__ import annotations

import logging
import warnings
from typing import Any
from urllib.parse import urljoin

import requests
import urllib3

logger = logging.getLogger(__name__)


class OmadaAPIError(Exception):
    """Raised when the Omada controller returns an error response."""

    def __init__(self, error_code: int, message: str) -> None:
        self.error_code = error_code
        super().__init__(f"Omada API error {error_code}: {message}")


# ---------------------------------------------------------------------------
# Auto-discovery helpers
# ---------------------------------------------------------------------------

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
    """Discover the controller ID (``omadacId``) from ``/api/info``.

    Returns
    -------
    str
        The ``omadacId`` value.

    Raises
    ------
    OmadaAPIError
        When the response indicates failure.
    RuntimeError
        When the ``omadacId`` field is missing from the response.
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
            "Could not determine controller ID: 'omadacId' not found in /api/info response"
        )
    logger.info("Discovered controller ID: %s", cid)
    return cid


def login(
    base_url: str,
    controller_id: str,
    username: str,
    password: str,
    *,
    verify_ssl: bool = True,
    timeout: int = 30,
) -> str:
    """Authenticate and return an API token.

    Parameters
    ----------
    base_url, controller_id:
        Controller connection details.
    username, password:
        Login credentials.  **Never** logged or included in error messages.

    Returns
    -------
    str
        The API access token.

    Raises
    ------
    OmadaAPIError
        When the login response indicates failure.
    RuntimeError
        When the token is missing from the response.
    """
    url = f"{base_url.rstrip('/')}/{controller_id}/api/v2/login"
    sess = _make_session(verify_ssl, base_url)
    resp = sess.post(
        url,
        json={"username": username, "password": password},
        timeout=timeout,
    )
    resp.raise_for_status()
    body = resp.json()
    error_code = body.get("errorCode", -1)
    if error_code != 0:
        raise OmadaAPIError(error_code, body.get("msg", "unknown error"))
    token = body.get("result", {}).get("token", "")
    if not token:
        raise RuntimeError("Login succeeded but no token was returned")
    logger.info("Login successful — token obtained")
    return token


def discover_site_id(
    base_url: str,
    controller_id: str,
    token: str,
    *,
    verify_ssl: bool = True,
    timeout: int = 30,
) -> str:
    """Auto-discover the site ID.

    If the controller has exactly one site, its ``id`` is returned.
    If there are multiple sites, a :class:`SystemExit` is raised with a
    message listing the available sites so the user can choose.

    Returns
    -------
    str
        The site ID.
    """
    url = (
        f"{base_url.rstrip('/')}/{controller_id}/api/v2/sites"
        "?currentPage=1&currentPageSize=1000"
    )
    sess = _make_session(verify_ssl, base_url)
    sess.headers.update({"Authorization": f"AccessToken={token}"})
    resp = sess.get(url, timeout=timeout)
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
        raise RuntimeError(
            "Unexpected response format from /api/v2/sites"
        )

    if not sites:
        raise RuntimeError("No sites found on the controller")

    if len(sites) == 1:
        site_id = sites[0].get("id", "")
        site_name = sites[0].get("name", "")
        logger.info("Auto-selected site: %s (%s)", site_name, site_id)
        return site_id

    # Multiple sites — list them and ask the user to specify
    lines = ["Multiple sites found. Please specify --site-id:"]
    for s in sites:
        lines.append(f"  • {s.get('name', '?')}  (id: {s.get('id', '?')})")
    raise SystemExit("\n".join(lines))


class OmadaClient:
    """Low-level HTTP client for the Omada SDN controller API.

    Parameters
    ----------
    base_url:
        Base URL of the controller, e.g. ``https://192.168.1.1:8043``.
    controller_id:
        The ``omadacId`` that prefixes every API path.
    token:
        A valid ``Authorization`` bearer token.
    verify_ssl:
        Whether to verify the controller's TLS certificate.  Defaults to
        ``True``; set to ``False`` for self-signed certificates.
    timeout:
        Request timeout in seconds.
    """

    def __init__(
        self,
        base_url: str,
        controller_id: str,
        token: str,
        *,
        verify_ssl: bool = True,
        timeout: int = 30,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.controller_id = controller_id
        self.token = token
        self.timeout = timeout

        self._session = requests.Session()
        self._session.headers.update(
            {
                "Authorization": f"AccessToken={token}",
                "Content-Type": "application/json",
            }
        )
        if not verify_ssl:
            self._session.verify = False
            # Emit a single process-level warning (respects -W flags and
            # warnings.filterwarnings) instead of globally silencing all
            # InsecureRequestWarnings for the whole process.
            warnings.warn(
                f"TLS certificate verification is disabled for {base_url}. "
                "This makes the connection vulnerable to MITM attacks.",
                urllib3.exceptions.InsecureRequestWarning,
                stacklevel=2,
            )
            logger.warning(
                "TLS certificate verification disabled for %s", base_url
            )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _api_url(self, path: str) -> str:
        """Build a full URL from a relative API *path*."""
        prefix = f"/{self.controller_id}/api/v2/"
        relative = path.lstrip("/")
        return urljoin(self.base_url + prefix, relative)

    def _get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        """Perform a GET request and return the ``result`` payload.

        Raises :class:`OmadaAPIError` when the response indicates failure.
        """
        url = self._api_url(path)
        logger.debug("GET %s params=%s", url, params)
        resp = self._session.get(
            url, params=params or {}, timeout=self.timeout
        )
        resp.raise_for_status()
        body: dict[str, Any] = resp.json()
        error_code: int = body.get("errorCode", -1)
        if error_code != 0:
            raise OmadaAPIError(error_code, body.get("msg", "unknown error"))
        return body.get("result", body)

    def _get_paged(
        self, path: str, *, page_size: int = 100, max_pages: int = 200
    ) -> list[dict[str, Any]]:
        """Fetch all pages for a paginated endpoint and return a flat list.

        Parameters
        ----------
        page_size:
            Number of records to request per API call.
        max_pages:
            Hard upper bound on the number of pages fetched.  Prevents an
            infinite loop when the API returns inconsistent ``totalRows``.
        """
        items: list[dict[str, Any]] = []
        for page in range(1, max_pages + 1):
            params = {"currentPage": page, "currentPageSize": page_size}
            result = self._get(path, params=params)
            # Result may be a list directly or wrapped in a dict with "data"
            if isinstance(result, list):
                items.extend(result)
                break
            data = result.get("data", [])
            items.extend(data)
            total_rows = result.get("totalRows", len(items))
            if len(items) >= total_rows:
                break
        else:
            logger.warning(
                "Pagination reached max_pages=%d for %s; %d record(s) collected. "
                "The API may be returning inconsistent totalRows.",
                max_pages,
                path,
                len(items),
            )
        return items

    # ------------------------------------------------------------------
    # Public API methods
    # ------------------------------------------------------------------

    def get_acl_rules(self, site_id: str) -> list[dict[str, Any]]:
        """Return all ACL rules for the given site."""
        return self._get_paged(f"sites/{site_id}/setting/acl/rules")

    def get_ip_groups(self, site_id: str) -> list[dict[str, Any]]:
        """Return all IP groups (object groups) for the given site."""
        return self._get_paged(
            f"sites/{site_id}/setting/profiles/groups/ip"
        )

    def get_port_groups(self, site_id: str) -> list[dict[str, Any]]:
        """Return all port groups for the given site."""
        return self._get_paged(
            f"sites/{site_id}/setting/profiles/groups/port"
        )

    def get_networks(self, site_id: str) -> list[dict[str, Any]]:
        """Return all LAN networks for the given site."""
        return self._get_paged(f"sites/{site_id}/setting/networks")

    def get_vlans(self, site_id: str) -> list[dict[str, Any]]:
        """Return VLAN configuration for the given site.

        VLANs are exposed as part of the LAN/networks endpoint on most
        controller versions.  The method also calls the dedicated VLAN
        endpoint where available and merges the results.
        """
        networks = self._get_paged(f"sites/{site_id}/setting/networks")
        # Filter networks that have a vlanId to surface VLAN data
        vlans = [n for n in networks if n.get("vlanId") is not None]
        # Fall back to full list when no VLAN IDs are present
        return vlans if vlans else networks

    def get_switch_port_profiles(self, site_id: str) -> list[dict[str, Any]]:
        """Return switch port profiles for the given site."""
        return self._get_paged(
            f"sites/{site_id}/setting/profiles/switchport"
        )

    def get_gateway_settings(self, site_id: str) -> dict[str, Any]:
        """Return gateway / WAN settings for the given site."""
        return self._get(f"sites/{site_id}/setting/gateways")

    def get_ssids(self, site_id: str) -> list[dict[str, Any]]:
        """Return all SSIDs across all WLANs for the given site."""
        # First retrieve all wlans
        try:
            wlans = self._get_paged(f"sites/{site_id}/setting/wlans")
        except OmadaAPIError:
            wlans = []

        ssids: list[dict[str, Any]] = []
        for wlan in wlans:
            wlan_id = wlan.get("id", "")
            try:
                wlan_ssids = self._get_paged(
                    f"sites/{site_id}/setting/wlans/{wlan_id}/ssids"
                )
                for ssid in wlan_ssids:
                    ssid.setdefault("wlanName", wlan.get("name", ""))
                ssids.extend(wlan_ssids)
            except OmadaAPIError:
                pass

        # If per-WLAN lookup fails, try a flat endpoint
        if not ssids:
            try:
                ssids = self._get_paged(f"sites/{site_id}/setting/ssids")
            except OmadaAPIError:
                pass

        return ssids

    def get_dhcp_reservations(self, site_id: str) -> list[dict[str, Any]]:
        """Return all DHCP reservations for the given site.

        Tries a site-level endpoint first; falls back to querying each
        network individually when the aggregated endpoint is unavailable.
        """
        try:
            return self._get_paged(
                f"sites/{site_id}/setting/dhcp/reservations"
            )
        except OmadaAPIError:
            pass

        # Per-network fallback
        networks = self.get_networks(site_id)
        reservations: list[dict[str, Any]] = []
        for net in networks:
            net_id = net.get("id", "")
            try:
                net_reservations = self._get_paged(
                    f"sites/{site_id}/setting/lan/networks/{net_id}/dhcp/reservations"
                )
                for r in net_reservations:
                    r.setdefault("networkName", net.get("name", ""))
                reservations.extend(net_reservations)
            except OmadaAPIError:
                pass
        return reservations
