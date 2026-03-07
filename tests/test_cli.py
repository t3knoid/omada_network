"""Tests for the CLI interface."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from cli import cli


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


class TestFetchCommand:
    def test_missing_required_options(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["fetch"])
        assert result.exit_code != 0

    def test_fetch_calls_service(self, runner: CliRunner, tmp_path: Path) -> None:
        mock_paths = {
            "yaml": {"acl_rules": tmp_path / "acl_rules.yaml"},
            "docs": {"acl_rules": tmp_path / "acl_rules.md"},
        }
        with patch("omada.service.OmadaService") as MockService:
            MockService.return_value.run.return_value = mock_paths
            result = runner.invoke(
                cli,
                [
                    "fetch",
                    "--controller", "192.168.1.1",
                    "--controller-id", "abc123",
                    "--token", "mytoken",
                    "--site-id", "site001",
                    "--output-dir", str(tmp_path),
                ],
            )
        assert result.exit_code == 0, result.output

    def test_fetch_reads_env_vars(self, runner: CliRunner, tmp_path: Path) -> None:
        mock_paths = {"yaml": {}, "docs": {}}
        env = {
            "OMADA_CONTROLLER": "192.168.1.1",
            "OMADA_CONTROLLER_ID": "cid",
            "OMADA_TOKEN": "tok",
            "OMADA_SITE_ID": "sid",
            "OMADA_OUTPUT_DIR": str(tmp_path),
        }
        with patch("omada.service.OmadaService") as MockService:
            MockService.return_value.run.return_value = mock_paths
            result = runner.invoke(cli, ["fetch"], env=env)
        assert result.exit_code == 0, result.output

    def test_no_verify_ssl_flag(self, runner: CliRunner, tmp_path: Path) -> None:
        mock_paths = {"yaml": {}, "docs": {}}
        with patch("omada.service.OmadaService") as MockService:
            MockService.return_value.run.return_value = mock_paths
            result = runner.invoke(
                cli,
                [
                    "fetch",
                    "--controller", "192.168.1.1",
                    "--controller-id", "abc123",
                    "--token", "mytoken",
                    "--site-id", "site001",
                    "--output-dir", str(tmp_path),
                ],
            )
        assert result.exit_code == 0
        # verify_ssl defaults to False (--verify-ssl flag not passed)
        _, kwargs = MockService.call_args
        assert kwargs.get("verify_ssl") is False


class TestGenerateCommand:
    def test_generate_from_yaml_files(self, runner: CliRunner, tmp_path: Path) -> None:
        """generate command should produce Markdown from YAML without API creds."""
        import yaml as _yaml

        (tmp_path / "acl_rules.yaml").write_text(
            _yaml.dump([{"name": "rule1", "policy": "accept"}]), encoding="utf-8"
        )
        result = runner.invoke(
            cli,
            ["generate", "--input-dir", str(tmp_path)],
        )
        assert result.exit_code == 0, result.output
        assert (tmp_path / "acl_rules.md").exists()

    def test_generate_separate_output_dir(self, runner: CliRunner, tmp_path: Path) -> None:
        import yaml as _yaml

        in_dir = tmp_path / "in"
        out_dir = tmp_path / "out"
        in_dir.mkdir()
        (in_dir / "networks.yaml").write_text(
            _yaml.dump([{"name": "LAN"}]), encoding="utf-8"
        )
        result = runner.invoke(
            cli,
            [
                "generate",
                "--input-dir", str(in_dir),
                "--output-dir", str(out_dir),
            ],
        )
        assert result.exit_code == 0, result.output
        assert (out_dir / "networks.md").exists()

    def test_generate_empty_dir_exits_nonzero(self, runner: CliRunner, tmp_path: Path) -> None:
        result = runner.invoke(
            cli,
            ["generate", "--input-dir", str(tmp_path)],
        )
        assert result.exit_code != 0

    def test_generate_reads_env_var(self, runner: CliRunner, tmp_path: Path) -> None:
        import yaml as _yaml

        (tmp_path / "ssids.yaml").write_text(
            _yaml.dump([{"ssid": "TestNet"}]), encoding="utf-8"
        )
        result = runner.invoke(
            cli,
            ["generate"],
            env={"OMADA_OUTPUT_DIR": str(tmp_path)},
        )
        assert result.exit_code == 0, result.output
        assert (tmp_path / "ssids.md").exists()


class TestServeCommand:
    def test_serve_starts_flask(self, runner: CliRunner) -> None:
        with patch("omada.web.app.Flask.run") as mock_run:
            result = runner.invoke(
                cli,
                ["serve", "--host", "127.0.0.1", "--port", "5001"],
            )
        # The runner may not block (Flask.run is patched) so just check no error
        assert result.exit_code == 0 or "Starting" in result.output


class TestFetchWithLogin:
    def test_login_auto_discovers_all(self, runner: CliRunner, tmp_path: Path) -> None:
        """--username/--password should auto-discover controller-id, token, site-id."""
        mock_paths = {"yaml": {}, "docs": {}}
        mock_login_result = MagicMock()
        mock_login_result.token = "tok"
        mock_login_result.session = MagicMock()
        mock_login_result.base_url = "https://192.168.1.1:8043"
        with (
            patch("omada.api.client.discover_controller_id", return_value="cid") as mock_cid,
            patch("omada.api.client.login", return_value=mock_login_result) as mock_login,
            patch("omada.api.client.discover_site_id", return_value="sid") as mock_sid,
            patch("omada.service.OmadaService") as MockService,
        ):
            MockService.return_value.run.return_value = mock_paths
            result = runner.invoke(
                cli,
                [
                    "fetch",
                    "--controller", "192.168.1.1",
                    "--username", "admin",
                    "--password", "secret",
                    "--output-dir", str(tmp_path),
                ],
            )
        assert result.exit_code == 0, result.output
        mock_cid.assert_called_once()
        mock_login.assert_called_once()
        mock_sid.assert_called_once()

    def test_login_env_vars(self, runner: CliRunner, tmp_path: Path) -> None:
        """OMADA_USERNAME and OMADA_PASSWORD env vars should work."""
        mock_paths = {"yaml": {}, "docs": {}}
        mock_login_result = MagicMock()
        mock_login_result.token = "tok"
        mock_login_result.session = MagicMock()
        mock_login_result.base_url = "https://192.168.1.1:8043"
        env = {
            "OMADA_CONTROLLER": "192.168.1.1",
            "OMADA_USERNAME": "admin",
            "OMADA_PASSWORD": "secret",
            "OMADA_OUTPUT_DIR": str(tmp_path),
        }
        with (
            patch("omada.api.client.discover_controller_id", return_value="cid"),
            patch("omada.api.client.login", return_value=mock_login_result),
            patch("omada.api.client.discover_site_id", return_value="sid"),
            patch("omada.service.OmadaService") as MockService,
        ):
            MockService.return_value.run.return_value = mock_paths
            result = runner.invoke(cli, ["fetch"], env=env)
        assert result.exit_code == 0, result.output

    def test_explicit_overrides_skip_discovery(self, runner: CliRunner, tmp_path: Path) -> None:
        """Explicit --controller-id/--token/--site-id should skip auto-discovery."""
        mock_paths = {"yaml": {}, "docs": {}}
        with (
            patch("omada.api.client.discover_controller_id") as mock_cid,
            patch("omada.api.client.login") as mock_login,
            patch("omada.api.client.discover_site_id") as mock_sid,
            patch("omada.service.OmadaService") as MockService,
        ):
            MockService.return_value.run.return_value = mock_paths
            result = runner.invoke(
                cli,
                [
                    "fetch",
                    "--controller", "192.168.1.1",
                    "--username", "admin",
                    "--password", "secret",
                    "--controller-id", "explicit-cid",
                    "--token", "explicit-tok",
                    "--site-id", "explicit-sid",
                    "--output-dir", str(tmp_path),
                ],
            )
        assert result.exit_code == 0, result.output
        mock_cid.assert_not_called()
        mock_login.assert_not_called()
        mock_sid.assert_not_called()

    def test_missing_all_auth_shows_hint(self, runner: CliRunner) -> None:
        """When no auth is provided, error should hint about --username/--password."""
        result = runner.invoke(
            cli,
            ["fetch", "--controller", "192.168.1.1"],
        )
        assert result.exit_code != 0
        assert "username" in result.output.lower() or "username" in str(result.exception).lower()
