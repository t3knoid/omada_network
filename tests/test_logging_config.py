"""Tests for the centralized logging configuration module."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from omada.logging_config import (
    DEFAULT_BACKUP_COUNT,
    DEFAULT_FORMAT,
    DEFAULT_LOG_FILE,
    DEFAULT_MAX_BYTES,
    setup_logging,
)


@pytest.fixture(autouse=True)
def _reset_root_logger():
    """Ensure each test starts with a clean root logger."""
    root = logging.getLogger()
    original_handlers = root.handlers[:]
    original_level = root.level
    yield
    root.handlers = original_handlers
    root.setLevel(original_level)


class TestSetupLoggingConsoleOnly:
    """Console-only logging (default, no log file)."""

    def test_default_level_is_info(self) -> None:
        setup_logging()
        root = logging.getLogger()
        assert root.level == logging.INFO

    def test_console_handler_attached(self) -> None:
        setup_logging()
        root = logging.getLogger()
        stream_handlers = [
            h for h in root.handlers if isinstance(h, logging.StreamHandler)
            and not isinstance(h, logging.FileHandler)
        ]
        assert len(stream_handlers) == 1

    def test_no_file_handler_by_default(self) -> None:
        setup_logging()
        root = logging.getLogger()
        file_handlers = [
            h for h in root.handlers if isinstance(h, logging.FileHandler)
        ]
        assert len(file_handlers) == 0

    def test_custom_level(self) -> None:
        setup_logging(level="DEBUG")
        assert logging.getLogger().level == logging.DEBUG

    def test_custom_format(self) -> None:
        fmt = "%(asctime)s %(name)s %(message)s"
        setup_logging(log_format=fmt)
        root = logging.getLogger()
        handler = root.handlers[0]
        # Verify the formatter uses the custom format by formatting a record.
        record = logging.LogRecord("test", logging.INFO, "", 0, "hello", (), None)
        formatted = handler.formatter.format(record)
        assert "test" in formatted
        assert "hello" in formatted

    def test_invalid_level_falls_back_to_info(self) -> None:
        setup_logging(level="BOGUS")
        assert logging.getLogger().level == logging.INFO

    def test_no_duplicate_handlers_on_repeat_calls(self) -> None:
        setup_logging()
        setup_logging()
        root = logging.getLogger()
        assert len(root.handlers) == 1


class TestSetupLoggingWithFile:
    """File logging (RotatingFileHandler)."""

    def test_file_handler_created(self, tmp_path: Path) -> None:
        log_file = str(tmp_path / "test.log")
        setup_logging(log_file=log_file)
        root = logging.getLogger()
        file_handlers = [
            h for h in root.handlers if isinstance(h, logging.FileHandler)
        ]
        assert len(file_handlers) == 1

    def test_log_file_written(self, tmp_path: Path) -> None:
        log_file = tmp_path / "app.log"
        setup_logging(log_file=str(log_file), level="INFO")
        logging.getLogger("test").info("hello from test")
        # Flush handlers
        for h in logging.getLogger().handlers:
            h.flush()
        assert log_file.exists()
        content = log_file.read_text(encoding="utf-8")
        assert "hello from test" in content

    def test_log_directory_created(self, tmp_path: Path) -> None:
        log_file = tmp_path / "nested" / "dir" / "app.log"
        setup_logging(log_file=str(log_file))
        assert log_file.parent.exists()

    def test_both_console_and_file_handlers(self, tmp_path: Path) -> None:
        log_file = str(tmp_path / "test.log")
        setup_logging(log_file=log_file)
        root = logging.getLogger()
        assert len(root.handlers) == 2

    def test_empty_log_file_disables_file_logging(self) -> None:
        setup_logging(log_file="")
        root = logging.getLogger()
        file_handlers = [
            h for h in root.handlers if isinstance(h, logging.FileHandler)
        ]
        assert len(file_handlers) == 0

    def test_invalid_path_falls_back_to_console(self, tmp_path: Path) -> None:
        # Use a path where the parent itself is a file, not a directory,
        # which is invalid on every platform.
        blocker = tmp_path / "not_a_dir"
        blocker.write_text("x")
        setup_logging(log_file=str(blocker / "sub" / "test.log"))
        root = logging.getLogger()
        file_handlers = [
            h for h in root.handlers if isinstance(h, logging.FileHandler)
        ]
        assert len(file_handlers) == 0
        # Console handler should still be present
        assert len(root.handlers) >= 1


class TestSetupLoggingRotation:
    """Rotation parameters are forwarded to RotatingFileHandler."""

    def test_rotation_params(self, tmp_path: Path) -> None:
        from logging.handlers import RotatingFileHandler

        log_file = str(tmp_path / "rot.log")
        setup_logging(log_file=log_file, max_bytes=1024, backup_count=2)
        root = logging.getLogger()
        rfh = [h for h in root.handlers if isinstance(h, RotatingFileHandler)]
        assert len(rfh) == 1
        assert rfh[0].maxBytes == 1024
        assert rfh[0].backupCount == 2


class TestSetupLoggingEnvVarsViaCli:
    """CLI reads env vars and passes them as arguments to setup_logging()."""

    def test_cli_reads_env_log_level(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Verify setup_logging() respects level passed in (CLI would read env)."""
        setup_logging(level="WARNING")
        assert logging.getLogger().level == logging.WARNING

    def test_cli_reads_env_log_file(self, tmp_path: Path) -> None:
        """Verify setup_logging() creates file handler when log_file is passed."""
        log_file = str(tmp_path / "env.log")
        setup_logging(log_file=log_file)
        root = logging.getLogger()
        file_handlers = [
            h for h in root.handlers if isinstance(h, logging.FileHandler)
        ]
        assert len(file_handlers) == 1

    def test_cli_reads_env_log_format(self) -> None:
        """Verify setup_logging() respects log_format passed in (CLI would read env)."""
        setup_logging(log_format="%(name)s: %(message)s")
        handler = logging.getLogger().handlers[0]
        # Verify format by formatting a test record.
        record = logging.LogRecord("mymod", logging.INFO, "", 0, "msg", (), None)
        formatted = handler.formatter.format(record)
        assert "mymod: msg" == formatted

    def test_empty_log_file_disables_file_logging(self) -> None:
        setup_logging(log_file="")
        root = logging.getLogger()
        file_handlers = [
            h for h in root.handlers if isinstance(h, logging.FileHandler)
        ]
        assert len(file_handlers) == 0


class TestDefaults:
    """Verify module-level defaults are sensible."""

    def test_default_format(self) -> None:
        assert DEFAULT_FORMAT == "%(levelname)s %(message)s"

    def test_default_log_file_path(self) -> None:
        assert "omada_network.log" in DEFAULT_LOG_FILE

    def test_default_max_bytes(self) -> None:
        assert DEFAULT_MAX_BYTES == 5 * 1024 * 1024

    def test_default_backup_count(self) -> None:
        assert DEFAULT_BACKUP_COUNT == 3
