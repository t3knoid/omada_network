"""Markdown documentation generator.

For each resource type a Markdown file is produced containing a human-friendly
table derived from the YAML source-of-truth data.

Formatting rules (title, columns, sort order) are driven by the
:data:`~omada.registry.REGISTRY`, so adding a new resource requires only a
new :class:`~omada.registry.ResourceDefinition` entry — no edits here.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from omada.registry import REGISTRY


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _header(text: str) -> str:
    return f"# {text}\n\n"


def _sanitize(value: Any) -> str:
    """Flatten a value to a Markdown-safe string."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "✓" if value else "✗"
    text = str(value)
    # Escape pipe characters so they don't break table formatting
    return text.replace("|", "\\|").replace("\n", " ")


def _table(rows: list[dict[str, Any]]) -> str:
    """Render a list of dicts as a GitHub Flavoured Markdown table."""
    if not rows:
        return "_No records found._\n"

    # Collect all unique keys while preserving insertion order
    keys: list[str] = []
    for row in rows:
        for k in row:
            if k not in keys:
                keys.append(k)

    # Header row
    header = "| " + " | ".join(keys) + " |"
    separator = "| " + " | ".join("---" for _ in keys) + " |"
    body_lines = [
        "| " + " | ".join(_sanitize(row.get(k, "")) for k in keys) + " |"
        for row in rows
    ]
    return "\n".join([header, separator] + body_lines) + "\n"


def _column_header(key: str) -> str:
    """Convert a snake_case key to Title Case for use as a column header."""
    return re.sub(r"[_\-]+", " ", key).title()


def _wrap_single(data: Any) -> list[dict[str, Any]]:
    """Wrap non-list data in a list so _table() always receives a list."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return [data]
    return [{"value": data}]


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------

class MarkdownGenerator:
    """Generates Markdown documentation files from resource data.

    Formatting is driven by :data:`~omada.registry.REGISTRY`.  Unknown
    resources fall back to a generic table.

    Parameters
    ----------
    output_dir:
        Directory where Markdown files will be written.
    """

    def __init__(self, output_dir: str | Path) -> None:
        self.output_dir = Path(output_dir)

    def generate(self, name: str, data: Any, context: dict[str, Any] | None = None) -> Path:
        """Generate a Markdown file for *name* and return the path."""
        self.output_dir.mkdir(parents=True, exist_ok=True)

        defn = REGISTRY.get(name)
        if defn is not None:
            if defn.needs_context:
                rows = defn.row_formatter(data, context)
            else:
                rows = defn.row_formatter(data)
            # Sort rows by the configured stable key
            if defn.sort_key and rows:
                rows = sorted(
                    rows,
                    key=lambda r: str(r.get(defn.sort_key, "")).lower(),
                )
            content = _header(defn.title) + _table(rows)
        else:
            # Generic fallback for unknown resource types:
            # apply column-header formatting to raw snake_case keys.
            raw_rows = _wrap_single(data)
            formatted_rows = [
                {_column_header(k): v for k, v in row.items()}
                for row in raw_rows
            ]
            content = _header(_column_header(name)) + _table(formatted_rows)

        path = self.output_dir / f"{name}.md"
        path.write_text(content, encoding="utf-8")
        return path

    def generate_all(self, data: dict[str, Any]) -> dict[str, Path]:
        """Generate Markdown for every key in *data*."""
        return {name: self.generate(name, value, context=data) for name, value in data.items()}

