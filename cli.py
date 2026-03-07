#!/usr/bin/env python3
"""Command-line interface for the Omada Network Documentation Generator.

All parameters can be supplied via environment variables (useful for
GitHub Actions secrets) or as command-line options.

Environment variable mapping
-----------------------------
OMADA_CONTROLLER      → --controller
OMADA_PORT            → --port  (default: 8043)
OMADA_CONTROLLER_ID   → --controller-id
OMADA_TOKEN           → --token
OMADA_SITE_ID         → --site-id
OMADA_USERNAME        → --username
OMADA_PASSWORD        → --password
OMADA_OUTPUT_DIR      → --output-dir
OMADA_VERIFY_SSL      → --verify-ssl (set to 1/true/yes/on to enable)

Usage examples
--------------
# Username/password authentication (auto-discovers controller-id, token, site-id):
python cli.py fetch --controller 192.168.1.1 \\
              --username admin --password secret

# Custom management port:
python cli.py fetch --controller 192.168.1.1 --port 443 \\
              --username admin --password secret

# Passing options directly (token mode):
python cli.py --controller 192.168.1.1 \\
              --controller-id abc123 \\
              --token mytoken \\
              --site-id site001

# Using environment variables (GitHub Actions):
# OMADA_CONTROLLER=192.168.1.1 OMADA_CONTROLLER_ID=... python cli.py

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


def _env_bool(name: str) -> bool:
    """Parse a boolean environment variable (case-insensitive).

    Truthy values: ``1``, ``true``, ``yes``, ``on``.
    Everything else (including empty / unset) is ``False``.
    """
    return os.environ.get(name, "").lower() in ("1", "true", "yes", "on")


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
    "--controller",
    default=lambda: _env("OMADA_CONTROLLER"),
    show_default="$OMADA_CONTROLLER",
    help="IP address or hostname of the Omada controller, e.g. 192.168.1.1",
)
@click.option(
    "--port",
    default=lambda: _env("OMADA_PORT", "8043"),
    show_default="$OMADA_PORT (default: 8043)",
    type=click.IntRange(1, 65535),
    help="Management port of the Omada controller.",
)
@click.option(
    "--controller-id",
    default=lambda: _env("OMADA_CONTROLLER_ID"),
    show_default="$OMADA_CONTROLLER_ID",
    help="Omada controller ID (omadacId). Auto-discovered when using --username/--password.",
)
@click.option(
    "--token",
    default=lambda: _env("OMADA_TOKEN"),
    show_default="$OMADA_TOKEN",
    help="Valid API access token. Auto-discovered when using --username/--password.",
)
@click.option(
    "--site-id",
    default=lambda: _env("OMADA_SITE_ID"),
    show_default="$OMADA_SITE_ID",
    help="Site ID to query. Auto-discovered when using --username/--password.",
)
@click.option(
    "--site-name",
    default=lambda: _env("OMADA_SITE_NAME"),
    show_default="$OMADA_SITE_NAME",
    help="Site name to query (case-insensitive). Used to select among multiple sites.",
)
@click.option(
    "--username",
    default=lambda: _env("OMADA_USERNAME"),
    show_default="$OMADA_USERNAME",
    help="Controller login username (enables auto-discovery of controller-id, token, and site-id).",
)
@click.option(
    "--password",
    envvar="OMADA_PASSWORD",
    prompt=True,
    hide_input=True,
    prompt_required=False,
    show_default=False,
    help="Controller login password.",
)
@click.option(
    "--output-dir",
    default=lambda: _env("OMADA_OUTPUT_DIR", "docs"),
    show_default="$OMADA_OUTPUT_DIR (default: docs)",
    help="Directory where YAML and Markdown files will be written.",
)
@click.option(
    "--verify-ssl",
    is_flag=True,
    default=lambda: _env_bool("OMADA_VERIFY_SSL"),
    help="Enable TLS certificate verification (disabled by default for self-signed certs).",
)
def fetch(
    controller: str,
    port: int,
    controller_id: str,
    token: str,
    site_id: str,
    site_name: str,
    username: str,
    password: str,
    output_dir: str,
    verify_ssl: bool,
) -> None:
    """Fetch network data from the controller and generate documentation."""
    if not controller:
        raise click.UsageError("Missing required value(s): --controller / OMADA_CONTROLLER")

    base_url = f"https://{controller}:{port}"

    # --- Auto-discovery when username/password are provided ---
    if username and password:
        from omada.api.client import (
            discover_controller_id,
            discover_site_id,
            login,
        )

        if not controller_id:
            controller_id = discover_controller_id(
                base_url, verify_ssl=verify_ssl
            )
        if not token:
            login_result = login(
                base_url, controller_id, username, password,
                verify_ssl=verify_ssl,
            )
            token = login_result.token
            login_session = login_result.session
            base_url = login_result.base_url
        else:
            login_session = None
        if not site_id:
            site_id = discover_site_id(
                base_url, controller_id, token, verify_ssl=verify_ssl,
                session=login_session, site_name=site_name,
            )

    # --- Validate that we have everything we need ---
    missing = []
    if not controller_id:
        missing.append("--controller-id / OMADA_CONTROLLER_ID")
    if not token:
        missing.append("--token / OMADA_TOKEN")
    if not site_id:
        missing.append("--site-id / OMADA_SITE_ID")
    if missing:
        raise click.UsageError(
            "Missing required value(s): " + ", ".join(missing)
            + "\n\nHint: provide --username and --password to auto-discover "
            "controller-id, token, and site-id."
        )

    from omada.service import OmadaService

    service = OmadaService(
        base_url=base_url,
        controller_id=controller_id,
        token=token,
        site_id=site_id,
        output_dir=output_dir,
        verify_ssl=verify_ssl,
        session=login_session if username and password else None,
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
