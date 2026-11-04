"""Shared pytest fixtures."""

from __future__ import annotations

import pytest
import requests


@pytest.fixture(autouse=True)
def _block_real_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail fast instead of hanging if a test forgets to stub an HTTP call.

    Real ``requests`` traffic raises ``ConnectionError`` immediately, which the
    client's best-effort lookups treat as "endpoint unavailable".  Tests that
    mock sessions or ``_get`` / ``_get_paged`` / ``_post`` are unaffected.
    """
    def _no_network(self, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        raise requests.ConnectionError("Network access is disabled in tests")

    monkeypatch.setattr(requests.Session, "send", _no_network)


@pytest.fixture(autouse=True)
def _no_real_waiting(monkeypatch: pytest.MonkeyPatch) -> None:
    """Request pacing and rate-limit backoff don't actually sleep in tests."""
    monkeypatch.setattr("omada.api.openapi_client._sleep", lambda seconds: None)
