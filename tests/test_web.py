"""Tests for the Flask web application."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from omada.web.app import create_app


@pytest.fixture()
def app_client(tmp_path: Path):
    app = create_app()
    app.config["TESTING"] = True
    # Point the app at a temp dir
    import omada.web.app as web_app
    original = web_app.OUTPUT_DIR
    web_app.OUTPUT_DIR = tmp_path
    with app.test_client() as client:
        yield client
    web_app.OUTPUT_DIR = original


class TestIndexRoute:
    def test_index_returns_200(self, app_client) -> None:
        resp = app_client.get("/")
        assert resp.status_code == 200

    def test_index_contains_form(self, app_client) -> None:
        resp = app_client.get("/")
        html = resp.data.decode()
        assert "base_url" in html
        assert "controller_id" in html
        assert "token" in html
        assert "site_id" in html


class TestRunRoute:
    def test_run_missing_fields_flashes_error(self, app_client) -> None:
        resp = app_client.post(
            "/run",
            data={"base_url": "https://localhost"},
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b"Missing required fields" in resp.data

    def test_run_success_flashes_message(self, app_client, tmp_path: Path) -> None:
        import omada.web.app as web_app
        web_app.OUTPUT_DIR = tmp_path

        form_data = {
            "base_url": "https://192.168.1.1:8043",
            "controller_id": "abc123",
            "token": "mytoken",
            "site_id": "site001",
        }

        mock_paths = {
            "yaml": {"acl_rules": tmp_path / "acl_rules.yaml"},
            "docs": {"acl_rules": tmp_path / "acl_rules.md"},
        }

        with patch("omada.web.app.OmadaService") as MockService:
            MockService.return_value.run.return_value = mock_paths
            resp = app_client.post("/run", data=form_data, follow_redirects=True)

        assert resp.status_code == 200
        assert b"Success" in resp.data

    def test_run_service_error_flashes_error(self, app_client) -> None:
        form_data = {
            "base_url": "https://192.168.1.1:8043",
            "controller_id": "abc123",
            "token": "mytoken",
            "site_id": "site001",
        }
        with patch("omada.web.app.OmadaService") as MockService:
            MockService.return_value.run.side_effect = Exception("Connection refused")
            resp = app_client.post("/run", data=form_data, follow_redirects=True)
        assert b"Error" in resp.data


class TestDocViewRoute:
    def test_view_existing_doc(self, app_client, tmp_path: Path) -> None:
        import omada.web.app as web_app
        web_app.OUTPUT_DIR = tmp_path
        doc = tmp_path / "acl_rules.md"
        doc.write_text("# ACL Rules\n\n| Name |\n| --- |\n| rule1 |\n")

        resp = app_client.get("/docs/acl_rules.md")
        assert resp.status_code == 200
        assert b"ACL Rules" in resp.data

    def test_view_missing_doc_redirects(self, app_client) -> None:
        resp = app_client.get("/docs/nonexistent.md", follow_redirects=True)
        assert resp.status_code == 200
        assert b"not found" in resp.data
