"""YAML exporter: writes each resource dict/list to a YAML file."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


class YamlExporter:
    """Exports resource data to YAML files.

    Parameters
    ----------
    output_dir:
        Directory where YAML files will be written.
    """

    def __init__(self, output_dir: str | Path) -> None:
        self.output_dir = Path(output_dir)

    def export(self, name: str, data: Any) -> Path:
        """Write *data* to ``<output_dir>/<name>.yaml`` and return the path."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        path = self.output_dir / f"{name}.yaml"
        with path.open("w", encoding="utf-8") as fh:
            yaml.dump(
                data,
                fh,
                allow_unicode=True,
                default_flow_style=False,
                sort_keys=False,
            )
        return path

    def export_all(self, data: dict[str, Any]) -> dict[str, Path]:
        """Export every key in *data* and return a mapping of name → path."""
        return {name: self.export(name, value) for name, value in data.items()}
