"""Tests for the Flask web application."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from omada.web.app import create_app


@pytest.fixture()
def app_client(tmp_path: Path):
    """Test client backed by a fresh app instance with output_dir=tmp_path."""
    app = create_app(output_dir=tmp_path)
    app.config["TESTING"] = True  # also disables CSRF check
    with app.test_client() as client:
        yield client


class TestIndexRoute:
    def test_index_returns_200(self, app_client) -> None:
        resp = app_client.get("/")
        assert resp.status_code == 200

    def test_index_contains_form(self, app_client) -> None:
        resp = app_client.get("/")
        html = resp.data.decode()
        assert "controller" in html
        assert "controller_id" in html
        assert "token" in html
        assert "site_id" in html

    def test_index_contains_csrf_token_field(self, app_client) -> None:
        resp = app_client.get("/")
        html = resp.data.decode()
        assert "_csrf_token" in html


class TestRunRoute:
    def test_run_missing_fields_flashes_error(self, app_client) -> None:
        resp = app_client.post(
            "/run",
            data={"controller": "192.168.1.1", "auth_mode": "token"},
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b"Missing required fields" in resp.data

    def test_run_success_flashes_message(self, app_client, tmp_path: Path) -> None:
        form_data = {
            "controller": "192.168.1.1",
            "port": "8043",
            "controller_id": "abc123",
            "token": "mytoken",
            "site_id": "site001",
            "auth_mode": "token",
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
            "controller": "192.168.1.1",
            "port": "8043",
            "controller_id": "abc123",
            "token": "mytoken",
            "site_id": "site001",
            "auth_mode": "token",
        }
        with patch("omada.web.app.OmadaService") as MockService:
            MockService.return_value.run.side_effect = Exception("Connection refused")
            resp = app_client.post("/run", data=form_data, follow_redirects=True)
        assert b"Error" in resp.data

    def test_run_csrf_enforced_outside_testing(self, tmp_path: Path) -> None:
        """Without TESTING=True a POST without _csrf_token must return 400."""
        app = create_app(output_dir=tmp_path)
        app.config["TESTING"] = False
        # Use a fixed secret key so sessions work deterministically
        app.secret_key = "test-secret"
        with app.test_client() as client:
            resp = client.post(
                "/run",
                data={
                    "controller": "192.168.1.1",
                    "port": "8043",
                    "controller_id": "abc123",
                    "token": "mytoken",
                    "site_id": "site001",
                },
            )
        assert resp.status_code == 400

    def test_run_login_mode_auto_discovers(self, app_client, tmp_path: Path) -> None:
        """Login mode should auto-discover controller-id, token, site-id."""
        form_data = {
            "controller": "192.168.1.1",
            "port": "8043",
            "username": "admin",
            "password": "secret",
            "auth_mode": "login",
        }

        mock_paths = {
            "yaml": {"acl_rules": tmp_path / "acl_rules.yaml"},
            "docs": {"acl_rules": tmp_path / "acl_rules.md"},
        }

        mock_login_result = MagicMock()
        mock_login_result.token = "tok"
        mock_login_result.session = MagicMock()
        mock_login_result.base_url = "https://192.168.1.1:8043"

        with (
            patch("omada.api.client.discover_controller_id", return_value="cid"),
            patch("omada.api.client.login", return_value=mock_login_result),
            patch("omada.api.client.discover_site_id", return_value="sid"),
            patch("omada.web.app.OmadaService") as MockService,
        ):
            MockService.return_value.run.return_value = mock_paths
            resp = app_client.post("/run", data=form_data, follow_redirects=True)

        assert resp.status_code == 200
        assert b"Success" in resp.data

    def test_run_login_mode_missing_credentials_flashes_error(self, app_client) -> None:
        """Login mode without username/password should flash an error."""
        form_data = {
            "controller": "192.168.1.1",
            "auth_mode": "login",
        }
        resp = app_client.post("/run", data=form_data, follow_redirects=True)
        assert resp.status_code == 200
        assert b"Missing required fields" in resp.data


class TestRegenerateRoute:
    def test_regenerate_no_yaml_files_flashes_warning(
        self, app_client
    ) -> None:
        # app_client already points to tmp_path which is empty
        resp = app_client.post("/regenerate", follow_redirects=True)
        assert resp.status_code == 200
        assert b"No *.yaml files found" in resp.data

    def test_regenerate_with_yaml_files(self, tmp_path: Path) -> None:
        import yaml

        (tmp_path / "acl_rules.yaml").write_text(
            yaml.dump([{"name": "r1"}]), encoding="utf-8"
        )

        app = create_app(output_dir=tmp_path)
        app.config["TESTING"] = True
        with app.test_client() as client:
            resp = client.post("/regenerate", follow_redirects=True)

        assert resp.status_code == 200
        assert b"Regenerated" in resp.data
        assert (tmp_path / "acl_rules.md").exists()

    def test_regenerate_missing_output_dir_flashes_warning(
        self, tmp_path: Path
    ) -> None:
        app = create_app(output_dir=tmp_path / "nonexistent")
        app.config["TESTING"] = True
        with app.test_client() as client:
            resp = client.post("/regenerate", follow_redirects=True)
        assert resp.status_code == 200
        assert b"does not exist" in resp.data

    def test_regenerate_csrf_enforced_outside_testing(self, tmp_path: Path) -> None:
        app = create_app(output_dir=tmp_path)
        app.config["TESTING"] = False
        app.secret_key = "test-secret"
        with app.test_client() as client:
            resp = client.post("/regenerate")
        assert resp.status_code == 400


class TestDocViewPathTraversal:
    def test_path_traversal_is_blocked(self, app_client) -> None:
        # Attempt to traverse outside output dir
        resp = app_client.get("/docs/../../../etc/passwd", follow_redirects=True)
        # Flask normalises the path, so the file won't exist — but should not
        # return the contents of an arbitrary file; should redirect with error
        assert resp.status_code == 200
        assert b"not found" in resp.data or b"Access denied" in resp.data

    def test_view_existing_doc(self, app_client, tmp_path: Path) -> None:
        doc = tmp_path / "acl_rules.md"
        doc.write_text("# ACL Rules\n\n| Name |\n| --- |\n| rule1 |\n")

        resp = app_client.get("/docs/acl_rules.md")
        assert resp.status_code == 200
        assert b"ACL Rules" in resp.data

    def test_view_missing_doc_redirects(self, app_client) -> None:
        resp = app_client.get("/docs/nonexistent.md", follow_redirects=True)
        assert resp.status_code == 200
        assert b"not found" in resp.data

