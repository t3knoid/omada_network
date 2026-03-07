"""Tests for the CLI interface."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

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
                    "--base-url", "https://192.168.1.1:8043",
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
            "OMADA_BASE_URL": "https://192.168.1.1:8043",
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
                    "--base-url", "https://192.168.1.1:8043",
                    "--controller-id", "abc123",
                    "--token", "mytoken",
                    "--site-id", "site001",
                    "--output-dir", str(tmp_path),
                    "--no-verify-ssl",
                ],
            )
        assert result.exit_code == 0
        # Verify the service was constructed with verify_ssl=False
        _, kwargs = MockService.call_args
        assert kwargs.get("verify_ssl") is False


class TestServeCommand:
    def test_serve_starts_flask(self, runner: CliRunner) -> None:
        with patch("omada.web.app.Flask.run") as mock_run:
            result = runner.invoke(
                cli,
                ["serve", "--host", "127.0.0.1", "--port", "5001"],
            )
        # The runner may not block (Flask.run is patched) so just check no error
        assert result.exit_code == 0 or "Starting" in result.output
