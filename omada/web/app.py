"""Flask web application for the Omada Network Documentation Generator.

Provides a simple UI to configure the connection parameters, trigger a full
fetch-and-export run, browse the generated Markdown documentation, and
regenerate Markdown from existing YAML files without API credentials.

All state is encapsulated inside :func:`create_app` so each call returns a
fresh :class:`~flask.Flask` instance — no module-level singletons.
"""

from __future__ import annotations

import io
import logging
import os
import secrets
import zipfile
from pathlib import Path

import markdown as _markdown
from flask import (
    Flask,
    abort,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from markupsafe import Markup

from omada.logging_config import setup_logging
from omada.service import OmadaService, generate_from_yaml

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# CSRF helpers (session-based; no extra dependencies required)
# ---------------------------------------------------------------------------

def _csrf_token() -> str:
    """Return (and lazily create) the per-session CSRF token."""
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]


def _check_csrf() -> None:
    """Validate the submitted CSRF token; abort 400 on mismatch.

    When ``app.config["TESTING"]`` is ``True`` the check is skipped so
    unit tests can POST without carrying a session token.
    """
    if current_app.config.get("TESTING"):
        return
    token = session.get("_csrf_token", "")
    if not token or request.form.get("_csrf_token") != token:
        abort(400, "CSRF token missing or invalid")


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

def create_app(
    output_dir: str | Path | None = None,
    *,
    configure_logging: bool = True,
) -> Flask:
    """Create and return a configured Flask application.

    Parameters
    ----------
    output_dir:
        Directory for generated YAML / Markdown files.
    configure_logging:
        When ``True`` (the default), :func:`setup_logging` is called using
        ``OMADA_LOG_*`` environment variables.  Pass ``False`` when the
        caller has already configured logging (e.g. the CLI ``serve``
        command) to avoid overriding those settings.
    """
    if configure_logging:
        setup_logging(
            level=os.environ.get("OMADA_LOG_LEVEL", "INFO").strip() or "INFO",
            log_file=os.environ.get("OMADA_LOG_FILE", "").strip() or None,
            log_format=os.environ.get("OMADA_LOG_FORMAT", "").strip() or None,
        )

    app = Flask(__name__)
    _secret_key = os.environ.get("FLASK_SECRET_KEY")
    if _secret_key:
        app.secret_key = _secret_key
    else:
        app.secret_key = os.urandom(24)
        logger.warning(
            "FLASK_SECRET_KEY is not set. Using an ephemeral random key — "
            "sessions and CSRF tokens will be invalidated on every server restart. "
            "Set FLASK_SECRET_KEY to a stable value for persistent deployments."
        )

    if output_dir is None:
        output_dir = os.environ.get("OUTPUT_DIR", "docs")
    app.config["OUTPUT_DIR"] = Path(output_dir)

    # Make csrf_token() available in every template
    app.jinja_env.globals["csrf_token"] = _csrf_token

    # ----------------------------------------------------------------
    # Template filters
    # ----------------------------------------------------------------

    @app.template_filter("markdown")
    def markdown_filter(text: str) -> Markup:
        """Jinja2 filter that converts Markdown text to safe HTML."""
        html = _markdown.markdown(
            text,
            extensions=["tables", "fenced_code", "nl2br"],
        )
        return Markup(html)

    # ----------------------------------------------------------------
    # Routes
    # ----------------------------------------------------------------

    @app.route("/", methods=["GET"])
    def index():
        """Landing page with the configuration form."""
        docs = _list_docs(current_app.config["OUTPUT_DIR"])
        form = session.get("_form_values", {})
        return render_template("index.html", docs=docs, form=form)

    @app.route("/run", methods=["POST"])
    def run():
        """Handle form submission: fetch data and generate documentation."""
        _check_csrf()
        output_dir_ = current_app.config["OUTPUT_DIR"]

        controller_host = request.form.get("controller", "").strip()
        port_str = request.form.get("port", "443").strip() or "443"
        verify_ssl = request.form.get("verify_ssl") == "on"
        auth_mode = request.form.get("auth_mode", "client_credentials")

        # Read credentials from the correct tab's inputs based on auth_mode
        if auth_mode == "auth_code":
            client_id = request.form.get("ac_client_id", "").strip()
            client_secret = request.form.get("ac_client_secret", "").strip()
            controller_id = request.form.get("ac_controller_id", "").strip()
            site_name = request.form.get("ac_site_name", "").strip()
            username = request.form.get("ac_username", "").strip()
            password = request.form.get("ac_password", "")
        else:
            client_id = request.form.get("client_id", "").strip()
            client_secret = request.form.get("client_secret", "").strip()
            controller_id = request.form.get("controller_id", "").strip()
            site_name = request.form.get("site_name", "").strip()
            username = ""
            password = ""

        # Persist non-sensitive form values in session (never store passwords or secrets)
        session["_form_values"] = {
            "controller": controller_host,
            "port": port_str,
            "verify_ssl": verify_ssl,
            "auth_mode": auth_mode,
            "client_id": client_id,
            "client_secret": "",
            "controller_id": controller_id,
            "site_name": site_name,
            "ac_client_id": client_id if auth_mode == "auth_code" else "",
            "ac_client_secret": "",
            "ac_controller_id": controller_id if auth_mode == "auth_code" else "",
            "ac_site_name": site_name if auth_mode == "auth_code" else "",
            "ac_username": username if auth_mode == "auth_code" else "",
        }
        if not controller_host:
            flash("Missing required field: Controller IP / Hostname", "danger")
            return redirect(url_for("index"))

        if not client_id or not client_secret:
            flash("Missing required fields: Client ID and Client Secret", "danger")
            return redirect(url_for("index"))

        try:
            port = int(port_str)
            if not (1 <= port <= 65535):
                raise ValueError("out of range")
        except ValueError:
            flash(
                f"Invalid port: '{port_str}'. Must be an integer between 1 and 65535.",
                "danger",
            )
            return redirect(url_for("index"))

        base_url = f"https://{controller_host}:{port}"

        try:
            from omada.api.openapi_client import (
                OmadaOpenApiClient,
                discover_controller_id,
                openapi_auth_code_login,
                openapi_discover_site_id,
                openapi_login,
            )

            if not controller_id:
                controller_id = discover_controller_id(
                    base_url, verify_ssl=verify_ssl,
                )

            if auth_mode == "auth_code":
                if not username or not password:
                    flash(
                        "Missing required fields: Username and Password "
                        "(required for Authorization Code mode)",
                        "danger",
                    )
                    return redirect(url_for("index"))
                login_result = openapi_auth_code_login(
                    base_url, controller_id, client_id, client_secret,
                    username, password,
                    verify_ssl=verify_ssl,
                )
            else:
                login_result = openapi_login(
                    base_url, controller_id, client_id, client_secret,
                    verify_ssl=verify_ssl,
                )

            site_id = openapi_discover_site_id(
                login_result.base_url, controller_id, login_result.session,
                site_name=site_name,
            )

            api_client = OmadaOpenApiClient(
                login_result.base_url, controller_id,
                login_result.access_token,
                verify_ssl=verify_ssl,
                session=login_result.session,
            )

            service = OmadaService(
                client=api_client,
                site_id=site_id,
                output_dir=output_dir_,
            )
            paths = service.run()
            doc_count = len(paths.get("docs", {}))
            yaml_count = len(paths.get("yaml", {}))
            flash(
                f"Success! Generated {doc_count} Markdown doc(s) and "
                f"{yaml_count} YAML file(s) in '{output_dir_}'.",
                "success",
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:  # noqa: BLE001
            logger.exception("Error running Omada service")
            flash(f"Error: {exc}", "danger")

        return redirect(url_for("index"))

    @app.route("/regenerate", methods=["POST"])
    def regenerate():
        """Regenerate Markdown docs from existing YAML files (no API creds needed)."""
        _check_csrf()
        output_dir_ = current_app.config["OUTPUT_DIR"]

        if not output_dir_.is_dir():
            flash(
                f"Output directory '{output_dir_}' does not exist.  "
                "Run a fetch first to create YAML files.",
                "warning",
            )
            return redirect(url_for("index"))

        try:
            paths = generate_from_yaml(output_dir_, output_dir_)
            if paths:
                flash(
                    f"Regenerated {len(paths)} Markdown doc(s) from YAML in '{output_dir_}'.",
                    "success",
                )
            else:
                flash(f"No *.yaml files found in '{output_dir_}'.", "warning")
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:  # noqa: BLE001
            logger.exception("Error regenerating docs from YAML")
            flash(f"Error: {exc}", "danger")

        return redirect(url_for("index"))

    @app.route("/docs/<path:filename>")
    def view_doc(filename: str):
        """Render a generated Markdown documentation file as HTML."""
        output_dir_ = current_app.config["OUTPUT_DIR"]
        # Security: prevent path traversal outside OUTPUT_DIR
        try:
            doc_path = (output_dir_ / filename).resolve()
            doc_path.relative_to(output_dir_.resolve())
        except ValueError:
            flash("Access denied.", "danger")
            return redirect(url_for("index"))

        if not doc_path.is_file():
            flash(f"Document '{filename}' not found.", "warning")
            return redirect(url_for("index"))

        content = doc_path.read_text(encoding="utf-8")
        return render_template(
            "doc_view.html",
            filename=filename,
            content=content,
            docs=_list_docs(output_dir_),
        )

    @app.route("/download/<path:filename>")
    def download_doc(filename: str):
        """Download a single generated Markdown file."""
        output_dir_ = current_app.config["OUTPUT_DIR"]
        try:
            doc_path = (output_dir_ / filename).resolve()
            doc_path.relative_to(output_dir_.resolve())
        except ValueError:
            flash("Access denied.", "danger")
            return redirect(url_for("index"))

        if not doc_path.is_file():
            flash(f"Document '{filename}' not found.", "warning")
            return redirect(url_for("index"))

        return send_file(
            doc_path,
            as_attachment=True,
            download_name=filename,
        )

    @app.route("/download", methods=["POST"])
    def download_selected():
        """Download selected files; ZIP if multiple."""
        _check_csrf()
        output_dir_ = current_app.config["OUTPUT_DIR"]
        filenames = request.form.getlist("filenames")

        if not filenames:
            flash("No files selected for download.", "warning")
            return redirect(url_for("index"))

        # Validate all paths before proceeding
        valid_paths: list[tuple[str, Path]] = []
        for fname in filenames:
            try:
                doc_path = (output_dir_ / fname).resolve()
                doc_path.relative_to(output_dir_.resolve())
            except ValueError:
                flash("Access denied.", "danger")
                return redirect(url_for("index"))
            if not doc_path.is_file():
                flash(f"Document '{fname}' not found.", "warning")
                return redirect(url_for("index"))
            valid_paths.append((fname, doc_path))

        if len(valid_paths) == 1:
            fname, doc_path = valid_paths[0]
            return send_file(
                doc_path,
                as_attachment=True,
                download_name=fname,
            )

        # Multiple files: create a ZIP archive in memory
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for fname, doc_path in valid_paths:
                zf.write(doc_path, arcname=fname)
        buf.seek(0)
        return send_file(
            buf,
            as_attachment=True,
            download_name="omada_docs.zip",
            mimetype="application/zip",
        )

    return app


def _list_docs(output_dir: Path) -> list[str]:
    """Return a sorted list of generated Markdown file names."""
    if not output_dir.is_dir():
        return []
    return sorted(p.name for p in output_dir.glob("*.md"))
