#!/usr/bin/env python3
"""Command-line interface for the Omada Network Documentation Generator.

All parameters can be supplied via environment variables (useful for
GitHub Actions secrets) or as command-line options.

Environment variable mapping
-----------------------------
OMADA_BASE_URL        → --base-url
OMADA_CONTROLLER_ID   → --controller-id
OMADA_TOKEN           → --token
OMADA_SITE_ID         → --site-id
OMADA_OUTPUT_DIR      → --output-dir
OMADA_NO_VERIFY_SSL   → --no-verify-ssl (set to any non-empty value)

Usage examples
--------------
# Passing options directly:
python cli.py --base-url https://192.168.1.1:8043 \\
              --controller-id abc123 \\
              --token mytoken \\
              --site-id site001

# Using environment variables (GitHub Actions):
# OMADA_BASE_URL=https://... OMADA_CONTROLLER_ID=... python cli.py

# Start the web server:
# python cli.py serve

# Regenerate Markdown from existing YAML (no API creds needed):
# python cli.py generate --input-dir docs
"""

from __future__ import annotations

import logging
import os
import sys

import click

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger(__name__)


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx: click.Context) -> None:
    """Omada Network Documentation Generator.

    Run without a sub-command to fetch and generate docs (equivalent to
    running the ``fetch`` sub-command with default options).
    """
    if ctx.invoked_subcommand is None:
        ctx.invoke(fetch)


@cli.command()
@click.option(
    "--base-url",
    default=lambda: _env("OMADA_BASE_URL"),
    show_default="$OMADA_BASE_URL",
    required=True,
    help="Base URL of the Omada controller, e.g. https://192.168.1.1:8043",
)
@click.option(
    "--controller-id",
    default=lambda: _env("OMADA_CONTROLLER_ID"),
    show_default="$OMADA_CONTROLLER_ID",
    required=True,
    help="Omada controller ID (omadacId).",
)
@click.option(
    "--token",
    default=lambda: _env("OMADA_TOKEN"),
    show_default="$OMADA_TOKEN",
    required=True,
    help="Valid API access token.",
)
@click.option(
    "--site-id",
    default=lambda: _env("OMADA_SITE_ID"),
    show_default="$OMADA_SITE_ID",
    required=True,
    help="Site ID to query.",
)
@click.option(
    "--output-dir",
    default=lambda: _env("OMADA_OUTPUT_DIR", "docs"),
    show_default="$OMADA_OUTPUT_DIR (default: docs)",
    help="Directory where YAML and Markdown files will be written.",
)
@click.option(
    "--no-verify-ssl",
    is_flag=True,
    default=lambda: bool(_env("OMADA_NO_VERIFY_SSL")),
    help="Disable TLS certificate verification (for self-signed certs).",
)
def fetch(
    base_url: str,
    controller_id: str,
    token: str,
    site_id: str,
    output_dir: str,
    no_verify_ssl: bool,
) -> None:
    """Fetch network data from the controller and generate documentation."""
    # Validate that required options are provided
    missing = []
    if not base_url:
        missing.append("--base-url / OMADA_BASE_URL")
    if not controller_id:
        missing.append("--controller-id / OMADA_CONTROLLER_ID")
    if not token:
        missing.append("--token / OMADA_TOKEN")
    if not site_id:
        missing.append("--site-id / OMADA_SITE_ID")
    if missing:
        raise click.UsageError(
            "Missing required value(s): " + ", ".join(missing)
        )

    from omada.service import OmadaService

    service = OmadaService(
        base_url=base_url,
        controller_id=controller_id,
        token=token,
        site_id=site_id,
        output_dir=output_dir,
        verify_ssl=not no_verify_ssl,
    )

    paths = service.run()

    click.echo("\nGenerated files:")
    for category, file_map in paths.items():
        click.echo(f"  [{category.upper()}]")
        for name, path in sorted(file_map.items()):
            click.echo(f"    {name}: {path}")


@cli.command()
@click.option(
    "--input-dir",
    default=lambda: _env("OMADA_OUTPUT_DIR", "docs"),
    show_default="$OMADA_OUTPUT_DIR (default: docs)",
    help="Directory containing *.yaml source files.",
)
@click.option(
    "--output-dir",
    default=None,
    help=(
        "Directory where Markdown files will be written.  "
        "Defaults to --input-dir when not specified."
    ),
)
def generate(input_dir: str, output_dir: str | None) -> None:
    """Generate Markdown documentation from existing YAML files.

    No API credentials are required — this command reads the ``*.yaml``
    files already present in INPUT_DIR and (re)generates the corresponding
    Markdown tables.

    Useful for local editing workflows and for regenerating docs from
    version-controlled YAML without connecting to the controller.
    """
    if output_dir is None:
        output_dir = input_dir

    from omada.service import generate_from_yaml

    paths = generate_from_yaml(input_dir, output_dir)

    if not paths:
        click.echo(f"No *.yaml files found in '{input_dir}'.", err=True)
        raise SystemExit(1)

    click.echo(f"\nGenerated {len(paths)} Markdown file(s) in '{output_dir}':")
    for name, path in sorted(paths.items()):
        click.echo(f"  {name}: {path}")


@cli.command()
@click.option("--host", default="127.0.0.1", help="Host to bind the web server.")
@click.option("--port", default=5000, type=int, help="Port to listen on.")
@click.option("--debug", is_flag=True, default=False, help="Enable Flask debug mode.")
@click.option(
    "--output-dir",
    default=lambda: _env("OMADA_OUTPUT_DIR", "docs"),
    help="Directory where generated files are stored.",
)
def serve(host: str, port: int, debug: bool, output_dir: str) -> None:
    """Start the web UI server."""
    from omada.web.app import create_app

    application = create_app(output_dir=output_dir)
    click.echo(f"Starting web UI on http://{host}:{port}  (output: {output_dir})")
    application.run(host=host, port=port, debug=debug)


if __name__ == "__main__":
    cli()
