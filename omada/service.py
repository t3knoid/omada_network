"""Service layer that orchestrates data retrieval and export.

The :class:`OmadaService` class is the main entry-point for both the CLI and
the web UI.  It fetches data from the controller, persists it as YAML files,
and generates Markdown documentation.

The standalone :func:`generate_from_yaml` function performs the Markdown
generation step only, reading existing ``*.yaml`` files from a directory.
No API credentials are required.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import requests
import yaml

from omada.api.client import OmadaClient
from omada.exporters.markdown_generator import MarkdownGenerator
from omada.exporters.yaml_exporter import YamlExporter
from omada.registry import RESOURCES

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

    #: Ordered tuple of all resource names, derived from the registry.
    RESOURCE_NAMES: tuple[str, ...] = tuple(defn.name for defn in RESOURCES)

    def __init__(
        self,
        base_url: str,
        controller_id: str,
        token: str,
        site_id: str,
        output_dir: str | Path = "docs",
        *,
        verify_ssl: bool = True,
        session: requests.Session | None = None,
    ) -> None:
        self.site_id = site_id
        self.output_dir = Path(output_dir)
        self._client = OmadaClient(
            base_url, controller_id, token,
            verify_ssl=verify_ssl, session=session,
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

        for defn in RESOURCES:
            fetcher = getattr(self._client, defn.fetch_method)
            try:
                data[defn.name] = fetcher(self.site_id)
                count = (
                    len(data[defn.name])
                    if isinstance(data[defn.name], list)
                    else 1
                )
                logger.info("  ✓ %s – %d record(s)", defn.name, count)
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as exc:  # noqa: BLE001
                logger.warning("  ✗ %s – %s", defn.name, exc)
                data[defn.name] = []

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


# ---------------------------------------------------------------------------
# Standalone generate-from-YAML function (no API credentials needed)
# ---------------------------------------------------------------------------

def generate_from_yaml(
    input_dir: str | Path,
    output_dir: str | Path,
) -> dict[str, Path]:
    """Generate Markdown documentation by reading ``*.yaml`` files.

    Parameters
    ----------
    input_dir:
        Directory containing ``<resource_name>.yaml`` files.
    output_dir:
        Directory where Markdown files will be written (may be the same as
        *input_dir*).

    Returns
    -------
    dict[str, Path]
        Mapping of resource name → generated Markdown path.
    """
    input_dir = Path(input_dir)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    md_gen = MarkdownGenerator(output_dir)
    paths: dict[str, Path] = {}

    for yaml_path in sorted(input_dir.glob("*.yaml")):
        name = yaml_path.stem
        raw = yaml_path.read_text(encoding="utf-8")
        data = yaml.safe_load(raw)
        if data is None:
            data = []
        paths[name] = md_gen.generate(name, data)
        logger.info("Generated %s → %s", name, paths[name])

    if not paths:
        logger.warning("No *.yaml files found in '%s'", input_dir)

    return paths

