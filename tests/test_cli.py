"""Tests for the CLI interface."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import click
import pytest
from click.testing import CliRunner

from cli import _build_client, _env_bool, cli


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


def _mock_login_result():
    lr = MagicMock()
    lr.access_token = "AT-tok"
    lr.session = MagicMock()
    lr.base_url = "https://192.168.1.1:8043"
    return lr


class TestFetchCommand:
    def test_missing_required_options(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["fetch"])
        assert result.exit_code != 0

    def test_fetch_client_credentials(self, runner: CliRunner, tmp_path: Path) -> None:
        """Client Credentials mode: --client-id + --client-secret, no username."""
        mock_paths = {"yaml": {}, "docs": {}}
        lr = _mock_login_result()
        with (
            patch("omada.api.openapi_client.discover_controller_id", return_value="cid"),
            patch("omada.api.openapi_client.openapi_login", return_value=lr),
            patch("omada.api.openapi_client.openapi_discover_site_id", return_value="sid"),
            patch("omada.api.openapi_client.OmadaOpenApiClient") as MockClient,
            patch("omada.service.OmadaService") as MockService,
        ):
            MockService.return_value.run.return_value = mock_paths
            result = runner.invoke(
                cli,
                [
                    "fetch",
                    "--controller", "192.168.1.1",
                    "--client-id", "my-id",
                    "--client-secret", "my-secret",
                    "--output-dir", str(tmp_path),
                ],
            )
        assert result.exit_code == 0, result.output

    def test_fetch_auth_code_mode(self, runner: CliRunner, tmp_path: Path) -> None:
        """Authorization Code mode: --username + --password trigger 3-step."""
        mock_paths = {"yaml": {}, "docs": {}}
        lr = _mock_login_result()
        with (
            patch("omada.api.openapi_client.discover_controller_id", return_value="cid"),
            patch("omada.api.openapi_client.openapi_auth_code_login", return_value=lr) as mock_ac,
            patch("omada.api.openapi_client.openapi_discover_site_id", return_value="sid"),
            patch("omada.api.openapi_client.OmadaOpenApiClient"),
            patch("omada.service.OmadaService") as MockService,
        ):
            MockService.return_value.run.return_value = mock_paths
            result = runner.invoke(
                cli,
                [
                    "fetch",
                    "--controller", "192.168.1.1",
                    "--client-id", "my-id",
                    "--client-secret", "my-secret",
                    "--username", "admin",
                    "--password", "secret",
                    "--output-dir", str(tmp_path),
                ],
            )
        assert result.exit_code == 0, result.output
        mock_ac.assert_called_once()

    def test_fetch_reads_env_vars(self, runner: CliRunner, tmp_path: Path) -> None:
        mock_paths = {"yaml": {}, "docs": {}}
        lr = _mock_login_result()
        env = {
            "OMADA_CONTROLLER": "192.168.1.1",
            "OMADA_CLIENT_ID": "my-id",
            "OMADA_CLIENT_SECRET": "my-secret",
            "OMADA_OUTPUT_DIR": str(tmp_path),
        }
        with (
            patch("omada.api.openapi_client.discover_controller_id", return_value="cid"),
            patch("omada.api.openapi_client.openapi_login", return_value=lr),
            patch("omada.api.openapi_client.openapi_discover_site_id", return_value="sid"),
            patch("omada.api.openapi_client.OmadaOpenApiClient"),
            patch("omada.service.OmadaService") as MockService,
        ):
            MockService.return_value.run.return_value = mock_paths
            result = runner.invoke(cli, ["fetch"], env=env)
        assert result.exit_code == 0, result.output

    def test_explicit_controller_id_skips_discovery(self, runner: CliRunner, tmp_path: Path) -> None:
        mock_paths = {"yaml": {}, "docs": {}}
        lr = _mock_login_result()
        with (
            patch("omada.api.openapi_client.discover_controller_id") as mock_disc,
            patch("omada.api.openapi_client.openapi_login", return_value=lr),
            patch("omada.api.openapi_client.openapi_discover_site_id", return_value="sid"),
            patch("omada.api.openapi_client.OmadaOpenApiClient"),
            patch("omada.service.OmadaService") as MockService,
        ):
            MockService.return_value.run.return_value = mock_paths
            result = runner.invoke(
                cli,
                [
                    "fetch",
                    "--controller", "192.168.1.1",
                    "--controller-id", "explicit-cid",
                    "--client-id", "my-id",
                    "--client-secret", "my-secret",
                    "--output-dir", str(tmp_path),
                ],
            )
        assert result.exit_code == 0, result.output
        mock_disc.assert_not_called()

    def test_missing_client_credentials_shows_error(self, runner: CliRunner) -> None:
        result = runner.invoke(
            cli,
            ["fetch", "--controller", "192.168.1.1"],
        )
        assert result.exit_code != 0
        assert "client" in result.output.lower()


class TestEnvBool:
    @pytest.mark.parametrize("value", ["1", "true", "True", "TRUE", "yes", "Yes", "on", "ON"])
    def test_truthy_values(self, value: str, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TEST_FLAG", value)
        assert _env_bool("TEST_FLAG") is True

    @pytest.mark.parametrize("value", ["0", "false", "False", "no", "off", "", "random"])
    def test_falsy_values(self, value: str, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TEST_FLAG", value)
        assert _env_bool("TEST_FLAG") is False

    def test_unset_is_false(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("TEST_FLAG", raising=False)
        assert _env_bool("TEST_FLAG") is False


class TestGenerateCommand:
    def test_generate_from_yaml_files(self, runner: CliRunner, tmp_path: Path) -> None:
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
        assert result.exit_code == 0 or "Starting" in result.output


class TestPasswordPromptBehaviour:
    """Tests for password prompt suppression and non-TTY guard."""

    def test_client_credentials_no_password_prompt(self, runner: CliRunner, tmp_path: Path) -> None:
        """Client Credentials mode must not prompt for a password."""
        mock_paths = {"yaml": {}, "docs": {}}
        lr = _mock_login_result()
        with (
            patch("omada.api.openapi_client.discover_controller_id", return_value="cid"),
            patch("omada.api.openapi_client.openapi_login", return_value=lr) as mock_login,
            patch("omada.api.openapi_client.openapi_discover_site_id", return_value="sid"),
            patch("omada.api.openapi_client.OmadaOpenApiClient"),
            patch("omada.service.OmadaService") as MockService,
        ):
            MockService.return_value.run.return_value = mock_paths
            result = runner.invoke(
                cli,
                [
                    "fetch",
                    "--controller", "192.168.1.1",
                    "--client-id", "my-id",
                    "--client-secret", "my-secret",
                    "--output-dir", str(tmp_path),
                ],
            )
        assert result.exit_code == 0, result.output
        assert "Password" not in result.output
        mock_login.assert_called_once()

    def test_password_prompt_when_username_provided_tty(self) -> None:
        """When --username is set but --password is missing, prompt interactively."""
        lr = _mock_login_result()
        with (
            patch("omada.api.openapi_client.discover_controller_id", return_value="cid"),
            patch("omada.api.openapi_client.openapi_auth_code_login", return_value=lr) as mock_ac,
            patch("omada.api.openapi_client.openapi_discover_site_id", return_value="sid"),
            patch("omada.api.openapi_client.OmadaOpenApiClient"),
            patch("sys.stdin") as mock_stdin,
            patch("click.prompt", return_value="secret") as mock_prompt,
        ):
            mock_stdin.isatty.return_value = True
            _build_client(
                controller="192.168.1.1",
                port=443,
                controller_id="cid",
                client_id="my-id",
                client_secret="my-secret",
                username="admin",
                password="",
                site_name="",
                verify_ssl=False,
            )
        mock_prompt.assert_called_once_with("Password", hide_input=True)
        mock_ac.assert_called_once()

    def test_non_tty_raises_usage_error(self) -> None:
        """Non-TTY stdin must raise UsageError, not Click Abort."""
        with (
            patch("omada.api.openapi_client.discover_controller_id", return_value="cid"),
            patch("sys.stdin") as mock_stdin,
        ):
            mock_stdin.isatty.return_value = False
            with pytest.raises(click.UsageError, match="Password required.*stdin is not a TTY"):
                _build_client(
                    controller="192.168.1.1",
                    port=443,
                    controller_id="cid",
                    client_id="my-id",
                    client_secret="my-secret",
                    username="admin",
                    password="",
                    site_name="",
                    verify_ssl=False,
                )

    def test_password_via_env_var(self, runner: CliRunner, tmp_path: Path) -> None:
        """OMADA_PASSWORD env var should be used without prompting."""
        mock_paths = {"yaml": {}, "docs": {}}
        lr = _mock_login_result()
        env = {
            "OMADA_CONTROLLER": "192.168.1.1",
            "OMADA_CLIENT_ID": "my-id",
            "OMADA_CLIENT_SECRET": "my-secret",
            "OMADA_USERNAME": "admin",
            "OMADA_PASSWORD": "env-secret",
            "OMADA_OUTPUT_DIR": str(tmp_path),
        }
        with (
            patch("omada.api.openapi_client.discover_controller_id", return_value="cid"),
            patch("omada.api.openapi_client.openapi_auth_code_login", return_value=lr) as mock_ac,
            patch("omada.api.openapi_client.openapi_discover_site_id", return_value="sid"),
            patch("omada.api.openapi_client.OmadaOpenApiClient"),
            patch("omada.service.OmadaService") as MockService,
        ):
            MockService.return_value.run.return_value = mock_paths
            result = runner.invoke(cli, ["fetch"], env=env)
        assert result.exit_code == 0, result.output
        assert "Password" not in result.output
        mock_ac.assert_called_once()
