#!/usr/bin/env python3
"""Command-line interface for the Omada Network Documentation Generator.

All parameters can be supplied via environment variables (useful for
GitHub Actions secrets) or as command-line options.

Environment variable mapping
-----------------------------
OMADA_CONTROLLER      → --controller
OMADA_PORT            → --port  (default: 443)
OMADA_CONTROLLER_ID   → --controller-id
OMADA_CLIENT_ID       → --client-id
OMADA_CLIENT_SECRET   → --client-secret
OMADA_USERNAME        → --username  (Authorization Code mode)
OMADA_PASSWORD        → --password  (Authorization Code mode)
OMADA_SITE_NAME       → --site-name
OMADA_OUTPUT_DIR      → --output-dir
OMADA_VERIFY_SSL      → --verify-ssl (set to 1/true/yes/on to enable)
OMADA_LOG_LEVEL       → --log-level  (DEBUG, INFO, WARNING, ERROR)
OMADA_LOG_FILE        → --log-file   (path to log file; enables file logging)
OMADA_LOG_FORMAT      → log format string (default: "%(levelname)s %(message)s")

Authentication modes (both use the official Omada Open API)
-----------------------------------------------------------
Client Credentials Mode (default):
  python cli.py fetch --controller 192.168.1.1 \\
    --client-id MY_ID --client-secret MY_SECRET

Authorization Code Mode (adds --username / --password):
  python cli.py fetch --controller 192.168.1.1 \\
    --client-id MY_ID --client-secret MY_SECRET \\
    --username admin --password secret
"""

from __future__ import annotations

import logging
import os
import sys

import click

from omada.logging_config import setup_logging

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
@click.option(
    "-v", "--verbose",
    is_flag=True,
    default=False,
    help="Enable verbose/debug logging.",
)
@click.option(
    "--log-level",
    default=lambda: _env("OMADA_LOG_LEVEL", "INFO"),
    show_default="$OMADA_LOG_LEVEL (default: INFO)",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"], case_sensitive=False),
    help="Set the logging level.",
)
@click.option(
    "--log-file",
    default=lambda: _env("OMADA_LOG_FILE"),
    show_default="$OMADA_LOG_FILE (default: disabled)",
    help=(
        "Path to the log file.  When provided, logs are also written to "
        "this file using rotating file handling."
    ),
)
@click.pass_context
def cli(ctx: click.Context, verbose: bool, log_level: str, log_file: str) -> None:
    """Omada Network Documentation Generator.

    Run without a sub-command to fetch and generate docs (equivalent to
    running the ``fetch`` sub-command with default options).
    """
    effective_level = "DEBUG" if verbose else log_level.upper()
    setup_logging(
        level=effective_level,
        log_file=log_file or None,
        log_format=_env("OMADA_LOG_FORMAT") or None,
    )
    if ctx.invoked_subcommand is None:
        ctx.invoke(fetch)


# ---------------------------------------------------------------------------
# Shared CLI options for Open API authentication
# ---------------------------------------------------------------------------

def _openapi_options(fn):
    """Decorator that adds the common Open API CLI options."""
    fn = click.option(
        "--controller",
        default=lambda: _env("OMADA_CONTROLLER"),
        show_default="$OMADA_CONTROLLER",
        help="IP address or hostname of the Omada controller.",
    )(fn)
    fn = click.option(
        "--port",
        default=lambda: _env("OMADA_PORT", "443"),
        show_default="$OMADA_PORT (default: 443)",
        type=click.IntRange(1, 65535),
        help="Management / Open API port of the Omada controller.",
    )(fn)
    fn = click.option(
        "--controller-id",
        default=lambda: _env("OMADA_CONTROLLER_ID"),
        show_default="$OMADA_CONTROLLER_ID",
        help="Omada controller ID (omadacId). Auto-discovered from /api/info when omitted.",
    )(fn)
    fn = click.option(
        "--client-id",
        default=lambda: _env("OMADA_CLIENT_ID"),
        show_default="$OMADA_CLIENT_ID",
        help="Open API Client ID (required).",
    )(fn)
    fn = click.option(
        "--client-secret",
        default=lambda: _env("OMADA_CLIENT_SECRET"),
        show_default="$OMADA_CLIENT_SECRET",
        help="Open API Client Secret (required).",
    )(fn)
    fn = click.option(
        "--username",
        default=lambda: _env("OMADA_USERNAME"),
        show_default="$OMADA_USERNAME",
        help="Controller login username (enables Authorization Code mode).",
    )(fn)
    fn = click.option(
        "--password",
        default=lambda: _env("OMADA_PASSWORD"),
        show_default="$OMADA_PASSWORD",
        help="Controller login password (Authorization Code mode).",
    )(fn)
    fn = click.option(
        "--site-name",
        default=lambda: _env("OMADA_SITE_NAME"),
        show_default="$OMADA_SITE_NAME",
        help="Site name to query (case-insensitive).",
    )(fn)
    fn = click.option(
        "--verify-ssl",
        is_flag=True,
        default=lambda: _env_bool("OMADA_VERIFY_SSL"),
        help="Enable TLS certificate verification (disabled by default).",
    )(fn)
    return fn


def _build_client(
    controller: str,
    port: int,
    controller_id: str,
    client_id: str,
    client_secret: str,
    username: str,
    password: str,
    site_name: str,
    verify_ssl: bool,
):
    """Shared helper: authenticate, discover site, return (client, site_id).

    Raises :class:`click.UsageError` when required values are missing.
    """
    from omada.api.openapi_client import (
        OmadaOpenApiClient,
        discover_controller_id,
        openapi_auth_code_login,
        openapi_discover_site_id,
        openapi_login,
    )

    if not controller:
        raise click.UsageError("Missing required value: --controller / OMADA_CONTROLLER")
    if not client_id or not client_secret:
        raise click.UsageError(
            "Missing required value(s): --client-id / OMADA_CLIENT_ID and "
            "--client-secret / OMADA_CLIENT_SECRET"
        )

    base_url = f"https://{controller}:{port}"

    if not controller_id:
        controller_id = discover_controller_id(base_url, verify_ssl=verify_ssl)

    # Choose auth mode
    if username and not password:
        if not sys.stdin.isatty():
            raise click.UsageError(
                "Password required: set --password or OMADA_PASSWORD "
                "(interactive prompt unavailable — stdin is not a TTY)"
            )
        password = click.prompt("Password", hide_input=True)
    if password and not username:
        raise click.UsageError(
            "Missing required value: --username / OMADA_USERNAME for Authorization Code mode"
        )
    if username and password:
        # Authorization Code Mode
        login_result = openapi_auth_code_login(
            base_url,
            controller_id,
            client_id,
            client_secret,
            username,
            password,
            verify_ssl=verify_ssl,
        )
    else:
        # Client Credentials Mode
        login_result = openapi_login(
            base_url,
            controller_id,
            client_id,
            client_secret,
            verify_ssl=verify_ssl,
        )

    site_id = openapi_discover_site_id(
        login_result.base_url, controller_id, login_result.session,
        site_name=site_name,
    )

    api_client = OmadaOpenApiClient(
        login_result.base_url, controller_id, login_result.access_token,
        verify_ssl=verify_ssl,
        session=login_result.session,
    )

    return api_client, site_id, controller_id, login_result


@cli.command()
@_openapi_options
@click.option(
    "--output-dir",
    default=lambda: _env("OMADA_OUTPUT_DIR", "docs"),
    show_default="$OMADA_OUTPUT_DIR (default: docs)",
    help="Directory where YAML and Markdown files will be written.",
)
def fetch(
    controller: str,
    port: int,
    controller_id: str,
    client_id: str,
    client_secret: str,
    username: str,
    password: str,
    site_name: str,
    verify_ssl: bool,
    output_dir: str,
) -> None:
    """Fetch network data from the controller and generate documentation."""
    api_client, site_id, controller_id, login_result = _build_client(
        controller, port, controller_id,
        client_id, client_secret,
        username, password,
        site_name, verify_ssl,
    )

    mode = "Authorization Code" if username and password else "Client Credentials"

    from omada.service import OmadaService

    service = OmadaService(
        client=api_client,
        site_id=site_id,
        output_dir=output_dir,
    )

    paths = service.run()

    click.echo(f"\nGenerated files ({mode} mode):")
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

    application = create_app(output_dir=output_dir, configure_logging=False)
    click.echo(f"Starting web UI on http://{host}:{port}  (output: {output_dir})")
    application.run(host=host, port=port, debug=debug)


@cli.command()
@_openapi_options
def diagnose(
    controller: str,
    port: int,
    controller_id: str,
    client_id: str,
    client_secret: str,
    username: str,
    password: str,
    site_name: str,
    verify_ssl: bool,
) -> None:
    """Probe each API endpoint and report raw response structures.

    Use this command to debug missing or empty settings. It shows exactly
    what the controller returns for each resource endpoint.
    """
    api_client, site_id, controller_id, login_result = _build_client(
        controller, port, controller_id,
        client_id, client_secret,
        username, password,
        site_name, verify_ssl,
    )

    mode = "Authorization Code" if username and password else "Client Credentials"

    from omada.registry import RESOURCES

    click.echo(f"\n{'='*60}")
    click.echo(f"Diagnosing controller ({mode} mode): {login_result.base_url}")
    click.echo(f"Controller ID: {controller_id}")
    click.echo(f"Site ID: {site_id}")
    click.echo(f"{'='*60}\n")

    for defn in RESOURCES:
        click.echo(f"--- {defn.title} ({defn.name}) ---")
        click.echo(f"  Method: {defn.fetch_method}")
        try:
            fetcher = getattr(api_client, defn.fetch_method)
            data = fetcher(site_id)
            if isinstance(data, list):
                click.echo(f"  Result: {len(data)} record(s)")
                if data and isinstance(data[0], dict):
                    click.echo(f"    First record keys: {list(data[0].keys())}")
            elif isinstance(data, dict):
                click.echo(f"  Result: dict with keys {list(data.keys())}")
            else:
                click.echo(f"  Result: {type(data).__name__}")
        except Exception as exc:
            click.echo(f"  ✗ Error: {exc}")
        click.echo()

    click.echo("Diagnosis complete.")


if __name__ == "__main__":
    cli()
