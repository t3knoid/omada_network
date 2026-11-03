"""Credential redaction for exported data.

Every resource passes through :func:`redact_secrets` before it is written to
YAML or Markdown (see :meth:`omada.service.OmadaService.fetch_all`), so a
credential returned by any controller endpoint never reaches the exports.

A value is redacted when its key looks like a credential (see
:data:`SECRET_KEY_PATTERN`) **and** it is a non-empty string.  Booleans such
as ``hidePwd`` / ``accountPassword`` and nested objects such as
``pskSetting`` are left alone (their contents are still inspected), and the
key is kept so the export shows that a secret is configured.

Redaction can be switched off with ``OmadaService(include_secrets=True)``
(CLI ``--include-secrets`` / web UI checkbox) to produce a restorable
backup; :func:`contains_secrets` then lets the Markdown generator flag every
file that holds plaintext credentials.
"""

from __future__ import annotations

import re
from typing import Any

REDACTED = "<redacted>"

#: Key names (case-insensitive substring) treated as credentials, e.g.
#: ``password``, ``clientPassword``, ``radiusPwd``, ``builtInServerSecret``,
#: ``clientSecret``, ``authToken``, ``securityKey``, ``preSharedKey``,
#: ``privateKey``.
SECRET_KEY_PATTERN = re.compile(
    r"password|passwd|pwd|secret|token|securitykey|presharedkey|privatekey",
    re.IGNORECASE,
)


def is_secret_key(key: Any) -> bool:
    """Return True when *key* names a credential."""
    return isinstance(key, str) and bool(SECRET_KEY_PATTERN.search(key))


def redact_secrets(data: Any) -> Any:
    """Return a copy of *data* with non-empty credential strings redacted."""
    if isinstance(data, dict):
        return {
            k: (REDACTED if is_secret_key(k) and isinstance(v, str) and v else redact_secrets(v))
            for k, v in data.items()
        }
    if isinstance(data, list):
        return [redact_secrets(v) for v in data]
    return data


def contains_secrets(data: Any) -> bool:
    """Return True if *data* holds any plaintext (non-redacted) credential."""
    if isinstance(data, dict):
        return any(
            (is_secret_key(k) and isinstance(v, str) and v and v != REDACTED) or contains_secrets(v)
            for k, v in data.items()
        )
    if isinstance(data, list):
        return any(contains_secrets(v) for v in data)
    return False
