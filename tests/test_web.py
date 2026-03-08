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
        assert "client_id" in html
        assert "client_secret" in html

    def test_index_contains_csrf_token_field(self, app_client) -> None:
        resp = app_client.get("/")
        html = resp.data.decode()
        assert "_csrf_token" in html

    def test_index_contains_auth_mode_tabs(self, app_client) -> None:
        resp = app_client.get("/")
        html = resp.data.decode()
        assert "Client Credentials" in html
        assert "Authorization Code" in html


class TestRunRoute:
    def test_run_missing_client_creds_flashes_error(self, app_client) -> None:
        resp = app_client.post(
            "/run",
            data={
                "controller": "192.168.1.1",
                "auth_mode": "client_credentials",
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200
        assert b"Missing required fields" in resp.data

    def test_run_client_credentials_success(self, app_client, tmp_path: Path) -> None:
        form_data = {
            "controller": "192.168.1.1",
            "port": "8043",
            "client_id": "my-id",
            "client_secret": "my-secret",
            "auth_mode": "client_credentials",
        }

        mock_paths = {
            "yaml": {"acl_rules": tmp_path / "acl_rules.yaml"},
            "docs": {"acl_rules": tmp_path / "acl_rules.md"},
        }

        mock_lr = MagicMock()
        mock_lr.access_token = "AT-tok"
        mock_lr.session = MagicMock()
        mock_lr.base_url = "https://192.168.1.1:8043"

        with (
            patch("omada.web.app.OmadaService") as MockService,
            patch("omada.api.openapi_client.discover_controller_id", return_value="cid"),
            patch("omada.api.openapi_client.openapi_login", return_value=mock_lr),
            patch("omada.api.openapi_client.openapi_discover_site_id", return_value="sid"),
            patch("omada.api.openapi_client.OmadaOpenApiClient"),
        ):
            MockService.return_value.run.return_value = mock_paths
            resp = app_client.post("/run", data=form_data, follow_redirects=True)

        assert resp.status_code == 200
        assert b"Success" in resp.data

    def test_run_auth_code_success(self, app_client, tmp_path: Path) -> None:
        form_data = {
            "controller": "192.168.1.1",
            "port": "8043",
            "ac_client_id": "my-id",
            "ac_client_secret": "my-secret",
            "ac_username": "admin",
            "ac_password": "secret",
            "auth_mode": "auth_code",
        }

        mock_paths = {
            "yaml": {"acl_rules": tmp_path / "acl_rules.yaml"},
            "docs": {"acl_rules": tmp_path / "acl_rules.md"},
        }

        mock_lr = MagicMock()
        mock_lr.access_token = "AT-tok"
        mock_lr.session = MagicMock()
        mock_lr.base_url = "https://192.168.1.1:8043"

        with (
            patch("omada.web.app.OmadaService") as MockService,
            patch("omada.api.openapi_client.discover_controller_id", return_value="cid"),
            patch("omada.api.openapi_client.openapi_auth_code_login", return_value=mock_lr) as mock_ac,
            patch("omada.api.openapi_client.openapi_discover_site_id", return_value="sid"),
            patch("omada.api.openapi_client.OmadaOpenApiClient"),
        ):
            MockService.return_value.run.return_value = mock_paths
            resp = app_client.post("/run", data=form_data, follow_redirects=True)

        assert resp.status_code == 200
        assert b"Success" in resp.data
        mock_ac.assert_called_once()

    def test_run_auth_code_missing_username_flashes_error(self, app_client) -> None:
        form_data = {
            "controller": "192.168.1.1",
            "ac_client_id": "my-id",
            "ac_client_secret": "my-secret",
            "auth_mode": "auth_code",
        }
        with patch("omada.api.openapi_client.discover_controller_id", return_value="cid"):
            resp = app_client.post("/run", data=form_data, follow_redirects=True)
        assert resp.status_code == 200
        assert b"Username and Password" in resp.data

    def test_run_service_error_flashes_error(self, app_client) -> None:
        form_data = {
            "controller": "192.168.1.1",
            "port": "8043",
            "client_id": "my-id",
            "client_secret": "my-secret",
            "auth_mode": "client_credentials",
        }
        mock_lr = MagicMock()
        mock_lr.access_token = "AT-tok"
        mock_lr.session = MagicMock()
        mock_lr.base_url = "https://192.168.1.1:8043"

        with (
            patch("omada.api.openapi_client.discover_controller_id", return_value="cid"),
            patch("omada.api.openapi_client.openapi_login", return_value=mock_lr),
            patch("omada.api.openapi_client.openapi_discover_site_id", return_value="sid"),
            patch("omada.api.openapi_client.OmadaOpenApiClient"),
            patch("omada.web.app.OmadaService") as MockService,
        ):
            MockService.return_value.run.side_effect = Exception("Connection refused")
            resp = app_client.post("/run", data=form_data, follow_redirects=True)
        assert b"Error" in resp.data

    def test_run_csrf_enforced_outside_testing(self, tmp_path: Path) -> None:
        """Without TESTING=True a POST without _csrf_token must return 400."""
        app = create_app(output_dir=tmp_path)
        app.config["TESTING"] = False
        app.secret_key = "test-secret"
        with app.test_client() as client:
            resp = client.post(
                "/run",
                data={
                    "controller": "192.168.1.1",
                    "port": "8043",
                    "client_id": "my-id",
                    "client_secret": "my-secret",
                },
            )
        assert resp.status_code == 400

    @pytest.mark.parametrize("bad_port", ["abc", "0", "65536", "-1", "3.14"])
    def test_run_invalid_port_flashes_error(self, app_client, bad_port: str) -> None:
        form_data = {
            "controller": "192.168.1.1",
            "port": bad_port,
            "auth_mode": "client_credentials",
            "client_id": "my-id",
            "client_secret": "my-secret",
        }
        resp = app_client.post("/run", data=form_data, follow_redirects=True)
        assert resp.status_code == 200
        assert b"Invalid port" in resp.data


class TestRegenerateRoute:
    def test_regenerate_no_yaml_files_flashes_warning(
        self, app_client
    ) -> None:
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
        resp = app_client.get("/docs/../../../etc/passwd", follow_redirects=True)
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

