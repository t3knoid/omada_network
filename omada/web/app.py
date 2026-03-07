"""Flask web application for the Omada Network Documentation Generator.

Provides a simple UI to configure the connection parameters, trigger a full
fetch-and-export run, and browse the generated Markdown documentation.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

import markdown as _markdown
from flask import Flask, flash, redirect, render_template, request, url_for
from markupsafe import Markup

from omada.service import OmadaService

logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(24))

OUTPUT_DIR = Path(os.environ.get("OUTPUT_DIR", "docs"))


@app.template_filter("markdown")
def markdown_filter(text: str) -> Markup:
    """Jinja2 filter that converts Markdown text to safe HTML."""
    html = _markdown.markdown(
        text,
        extensions=["tables", "fenced_code", "nl2br"],
    )
    return Markup(html)


def _service_from_form(form: dict) -> OmadaService:
    return OmadaService(
        base_url=form["base_url"],
        controller_id=form["controller_id"],
        token=form["token"],
        site_id=form["site_id"],
        output_dir=OUTPUT_DIR,
        verify_ssl=form.get("verify_ssl") == "on",
    )


@app.route("/", methods=["GET"])
def index():
    """Landing page with the configuration form."""
    docs = _list_docs()
    return render_template("index.html", docs=docs)


@app.route("/run", methods=["POST"])
def run():
    """Handle form submission: fetch data and generate documentation."""
    required = ("base_url", "controller_id", "token", "site_id")
    missing = [f for f in required if not request.form.get(f)]
    if missing:
        flash(f"Missing required fields: {', '.join(missing)}", "danger")
        return redirect(url_for("index"))

    try:
        service = _service_from_form(request.form)
        paths = service.run()
        doc_count = len(paths.get("docs", {}))
        yaml_count = len(paths.get("yaml", {}))
        flash(
            f"Success! Generated {doc_count} Markdown doc(s) and "
            f"{yaml_count} YAML file(s) in '{OUTPUT_DIR}'.",
            "success",
        )
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:  # noqa: BLE001
        logger.exception("Error running Omada service")
        flash(f"Error: {exc}", "danger")

    return redirect(url_for("index"))


@app.route("/docs/<path:filename>")
def view_doc(filename: str):
    """Render a generated Markdown documentation file as HTML."""
    doc_path = OUTPUT_DIR / filename
    if not doc_path.is_file():
        flash(f"Document '{filename}' not found.", "warning")
        return redirect(url_for("index"))

    content = doc_path.read_text(encoding="utf-8")
    return render_template(
        "doc_view.html",
        filename=filename,
        content=content,
        docs=_list_docs(),
    )


def _list_docs() -> list[str]:
    """Return a sorted list of generated Markdown file names."""
    if not OUTPUT_DIR.is_dir():
        return []
    return sorted(p.name for p in OUTPUT_DIR.glob("*.md"))


def create_app() -> Flask:
    """Application factory (useful for testing)."""
    return app
