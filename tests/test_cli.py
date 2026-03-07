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
