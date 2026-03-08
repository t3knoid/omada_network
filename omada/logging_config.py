"""Centralized logging configuration for the Omada Network tools.

Provides :func:`setup_logging` which configures the root logger with a
console handler (``stderr``) and, optionally, a rotating file handler.

Configuration may be driven by CLI options, environment variables, or
direct function arguments.  Environment variable mapping:

    OMADA_LOG_LEVEL   → log level (DEBUG, INFO, WARNING, ERROR)
    OMADA_LOG_FILE    → path to the log file (empty = file logging disabled)
    OMADA_LOG_FORMAT  → custom format string for log messages

See :func:`setup_logging` for the full list of parameters and their defaults.
"""

from __future__ import annotations

import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

#: Default log format used by both console and file handlers.
DEFAULT_FORMAT = "%(levelname)s %(message)s"

#: Default log file path when file logging is enabled.
DEFAULT_LOG_FILE = os.path.join("logs", "omada_network.log")

#: Default maximum log file size before rotation (5 MB).
DEFAULT_MAX_BYTES = 5 * 1024 * 1024

#: Default number of rotated backup files to keep.
DEFAULT_BACKUP_COUNT = 3


def setup_logging(
    *,
    level: str = "INFO",
    log_file: str | None = None,
    log_format: str | None = None,
    max_bytes: int = DEFAULT_MAX_BYTES,
    backup_count: int = DEFAULT_BACKUP_COUNT,
) -> None:
    """Configure root logger with console and optional file handlers.

    Parameters
    ----------
    level:
        Logging level name (``DEBUG``, ``INFO``, ``WARNING``, ``ERROR``).
        Overridden by the ``OMADA_LOG_LEVEL`` environment variable when set.
    log_file:
        Path to the log file.  When *not* ``None`` and not empty, a
        :class:`~logging.handlers.RotatingFileHandler` is attached to the
        root logger.  Overridden by ``OMADA_LOG_FILE`` when set.
        Pass an empty string to explicitly disable file logging.
    log_format:
        :mod:`logging` format string.  Overridden by ``OMADA_LOG_FORMAT``
        when set.  Defaults to :data:`DEFAULT_FORMAT`.
    max_bytes:
        Maximum size (in bytes) of the log file before rotation.
    backup_count:
        Number of rotated backup files to retain.
    """
    # Environment variables take precedence over function arguments.
    env_level = os.environ.get("OMADA_LOG_LEVEL", "").strip().upper()
    if env_level:
        level = env_level

    env_file = os.environ.get("OMADA_LOG_FILE")
    if env_file is not None:
        log_file = env_file.strip()

    env_fmt = os.environ.get("OMADA_LOG_FORMAT")
    if env_fmt is not None:
        log_format = env_fmt

    # Resolve effective values.
    numeric_level = getattr(logging, level, None)
    if not isinstance(numeric_level, int):
        numeric_level = logging.INFO

    fmt = log_format or DEFAULT_FORMAT
    formatter = logging.Formatter(fmt)

    root = logging.getLogger()
    root.setLevel(numeric_level)

    # Remove any pre-existing handlers (e.g. from basicConfig) so that
    # calling setup_logging() multiple times doesn't duplicate output.
    root.handlers.clear()

    # --- Console handler (always present) ---
    console = logging.StreamHandler(sys.stderr)
    console.setLevel(numeric_level)
    console.setFormatter(formatter)
    root.addHandler(console)

    # --- File handler (opt-in) ---
    if log_file:
        _add_file_handler(root, log_file, formatter, numeric_level,
                          max_bytes, backup_count)


def _add_file_handler(
    root: logging.Logger,
    log_file: str,
    formatter: logging.Formatter,
    level: int,
    max_bytes: int,
    backup_count: int,
) -> None:
    """Attach a :class:`RotatingFileHandler` to *root*, creating dirs as needed."""
    log_path = Path(log_file)
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        handler = RotatingFileHandler(
            str(log_path),
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
        handler.setLevel(level)
        handler.setFormatter(formatter)
        root.addHandler(handler)
    except OSError as exc:
        # Fall back to console-only logging with a clear warning.
        root.warning(
            "Could not open log file '%s': %s. "
            "Continuing with console logging only.",
            log_file,
            exc,
        )
