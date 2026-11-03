"""Tests for omada.redaction."""

from __future__ import annotations

import pytest

from omada.redaction import REDACTED, contains_secrets, is_secret_key, redact_secrets


@pytest.mark.parametrize("key", [
    "password", "clientPassword", "overridePassword", "radiusPwd", "accountingServerPwd",
    "coaPassword", "builtInServerSecret", "clientSecret", "authToken", "securityKey",
    "preSharedKey", "presharedKey", "privateKey",
])
def test_credential_keys_detected(key: str) -> None:
    assert is_secret_key(key)


@pytest.mark.parametrize("key", [
    "publicKey", "username", "name", "sid", "pskSetting", "radiusProfileId", "nasId", 42,
])
def test_non_credential_keys_not_detected(key) -> None:
    assert not is_secret_key(key)


def test_redacts_nested_strings_only() -> None:
    data = {
        "pskSetting": {"securityKey": "pass", "versionPsk": 4},
        "hidePwd": True,             # boolean flag, not a secret value
        "accountPassword": False,
        "password": "",              # empty: nothing configured, nothing to hide
        "servers": [{"radiusPwd": "s3cret", "radiusServerIp": "10.0.0.5"}],
        "publicKey": "PUB=",
    }
    result = redact_secrets(data)
    assert result == {
        "pskSetting": {"securityKey": REDACTED, "versionPsk": 4},
        "hidePwd": True,
        "accountPassword": False,
        "password": "",
        "servers": [{"radiusPwd": REDACTED, "radiusServerIp": "10.0.0.5"}],
        "publicKey": "PUB=",
    }
    assert data["pskSetting"]["securityKey"] == "pass"  # input not mutated


def test_passes_through_scalars() -> None:
    assert redact_secrets("text") == "text"
    assert redact_secrets(None) is None
    assert redact_secrets([1, 2]) == [1, 2]


def test_contains_secrets() -> None:
    assert contains_secrets({"pskSetting": {"securityKey": "pass"}})
    assert contains_secrets([{"servers": [{"radiusPwd": "x"}]}])
    assert not contains_secrets({"pskSetting": {"securityKey": REDACTED}})
    assert not contains_secrets({"password": "", "hidePwd": True, "publicKey": "PUB="})
    assert not contains_secrets("password")

