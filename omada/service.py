"""Service layer that orchestrates data retrieval and export.

The :class:`OmadaService` class is the main entry-point for both the CLI and
the web UI.  It fetches data from the controller, persists it as YAML files,
and generates Markdown documentation.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from omada.api.client import OmadaClient
from omada.exporters.markdown_generator import MarkdownGenerator
from omada.exporters.yaml_exporter import YamlExporter

logger = logging.getLogger(__name__)


class OmadaService:
    """High-level service that coordinates API calls, YAML export, and docs.

    Parameters
    ----------
    base_url:
        Controller base URL.
    controller_id:
        The ``omadacId`` value.
    token:
        Valid API token.
    site_id:
        Site ID to query.
    output_dir:
        Directory where YAML and Markdown files will be written.
    verify_ssl:
        Whether to verify TLS certificates.
    """

    # Names used as YAML/Markdown file stems
    RESOURCE_NAMES = (
        "acl_rules",
        "ip_groups",
        "port_groups",
        "networks",
        "vlans",
        "switch_port_profiles",
        "gateway_settings",
        "ssids",
        "dhcp_reservations",
    )

    def __init__(
        self,
        base_url: str,
        controller_id: str,
        token: str,
        site_id: str,
        output_dir: str | Path = "docs",
        *,
        verify_ssl: bool = True,
    ) -> None:
        self.site_id = site_id
        self.output_dir = Path(output_dir)
        self._client = OmadaClient(
            base_url, controller_id, token, verify_ssl=verify_ssl
        )
        self._yaml = YamlExporter(self.output_dir)
        self._md = MarkdownGenerator(self.output_dir)

    # ------------------------------------------------------------------
    # Data fetching
    # ------------------------------------------------------------------

    def fetch_all(self) -> dict[str, Any]:
        """Fetch every resource type and return a combined dict."""
        logger.info("Fetching all resources for site '%s'…", self.site_id)
        data: dict[str, Any] = {}

        fetchers = {
            "acl_rules": lambda: self._client.get_acl_rules(self.site_id),
            "ip_groups": lambda: self._client.get_ip_groups(self.site_id),
            "port_groups": lambda: self._client.get_port_groups(self.site_id),
            "networks": lambda: self._client.get_networks(self.site_id),
            "vlans": lambda: self._client.get_vlans(self.site_id),
            "switch_port_profiles": lambda: self._client.get_switch_port_profiles(
                self.site_id
            ),
            "gateway_settings": lambda: self._client.get_gateway_settings(
                self.site_id
            ),
            "ssids": lambda: self._client.get_ssids(self.site_id),
            "dhcp_reservations": lambda: self._client.get_dhcp_reservations(
                self.site_id
            ),
        }

        for name, fetcher in fetchers.items():
            try:
                data[name] = fetcher()
                count = (
                    len(data[name])
                    if isinstance(data[name], list)
                    else 1
                )
                logger.info("  ✓ %s – %d record(s)", name, count)
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as exc:  # noqa: BLE001
                logger.warning("  ✗ %s – %s", name, exc)
                data[name] = []

        return data

    # ------------------------------------------------------------------
    # Export helpers
    # ------------------------------------------------------------------

    def export_yaml(self, data: dict[str, Any]) -> dict[str, Path]:
        """Write each resource as a YAML file and return file paths."""
        return self._yaml.export_all(data)

    def generate_docs(self, data: dict[str, Any]) -> dict[str, Path]:
        """Generate Markdown documentation and return file paths."""
        return self._md.generate_all(data)

    # ------------------------------------------------------------------
    # Convenience: run everything in one call
    # ------------------------------------------------------------------

    def run(self) -> dict[str, dict[str, Path]]:
        """Fetch data, export YAML, generate Markdown and return all paths."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        data = self.fetch_all()
        yaml_paths = self.export_yaml(data)
        doc_paths = self.generate_docs(data)
        logger.info("Done. YAML in %s, docs in %s", self.output_dir, self.output_dir)
        return {"yaml": yaml_paths, "docs": doc_paths}
