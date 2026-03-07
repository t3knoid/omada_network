"""Flask web application for the Omada Network Documentation Generator.

Provides a simple UI to configure the connection parameters, trigger a full
fetch-and-export run, browse the generated Markdown documentation, and
regenerate Markdown from existing YAML files without API credentials.

All state is encapsulated inside :func:`create_app` so each call returns a
fresh :class:`~flask.Flask` instance — no module-level singletons.
"""

from __future__ import annotations

import logging
import os
import secrets
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
    session,
    url_for,
)
from markupsafe import Markup

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

def create_app(output_dir: str | Path | None = None) -> Flask:
    """Create and return a configured Flask application.

    Parameters
    ----------
    output_dir:
        Directory where YAML and Markdown files live.  Falls back to the
        ``OUTPUT_DIR`` environment variable, then ``docs``.
    """
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
        return render_template("index.html", docs=docs)

    @app.route("/run", methods=["POST"])
    def run():
        """Handle form submission: fetch data and generate documentation."""
        _check_csrf()
        output_dir_ = current_app.config["OUTPUT_DIR"]

        controller_host = request.form.get("controller", "").strip()
        port_str = request.form.get("port", "8043").strip() or "8043"
        controller_id = request.form.get("controller_id", "")
        token = request.form.get("token", "")
        site_id = request.form.get("site_id", "")
        site_name = request.form.get("site_name", "").strip()
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        verify_ssl = request.form.get("verify_ssl") == "on"
        auth_mode = request.form.get("auth_mode", "token")

        if not controller_host:
            flash("Missing required field: Controller IP / Hostname", "danger")
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
            # Auto-discovery when using login mode
            if auth_mode == "login":
                if not username or not password:
                    flash("Missing required fields: username, password", "danger")
                    return redirect(url_for("index"))

                from omada.api.client import (
                    discover_controller_id,
                    discover_site_id,
                    login as omada_login,
                )

                if not controller_id:
                    controller_id = discover_controller_id(
                        base_url, verify_ssl=verify_ssl
                    )
                if not token:
                    login_result = omada_login(
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
                        base_url, controller_id, token,
                        verify_ssl=verify_ssl,
                        session=login_session,
                        site_name=site_name,
                    )
            else:
                missing = []
                if not controller_id:
                    missing.append("controller_id")
                if not token:
                    missing.append("token")
                if not site_id:
                    missing.append("site_id")
                if missing:
                    flash(
                        f"Missing required fields: {', '.join(missing)}",
                        "danger",
                    )
                    return redirect(url_for("index"))

            service = OmadaService(
                base_url=base_url,
                controller_id=controller_id,
                token=token,
                site_id=site_id,
                output_dir=output_dir_,
                verify_ssl=verify_ssl,
                session=(
                    login_session
                    if auth_mode == "login" and username and password
                    else None
                ),
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

    return app


def _list_docs(output_dir: Path) -> list[str]:
    """Return a sorted list of generated Markdown file names."""
    if not output_dir.is_dir():
        return []
    return sorted(p.name for p in output_dir.glob("*.md"))

