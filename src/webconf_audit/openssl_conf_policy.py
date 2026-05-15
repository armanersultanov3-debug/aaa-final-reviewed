"""Helpers for parsing OpenSSL ``SSL_CONF`` option strings.

Used by Nginx ``ssl_conf_command Options`` and Lighttpd
``ssl.openssl.ssl-conf-cmd`` rules to determine the final explicit
state of options such as ``Compression`` or ``UnsafeLegacyRenegotiation``.
"""

from __future__ import annotations

import re
import shlex

_OPTION_SPLIT_RE = re.compile(r"[\s,]+")


def ssl_conf_option_state(value: str, option_name: str) -> bool | None:
    """Return the final explicit state of an OpenSSL SSL_CONF Options token."""
    target = option_name.lower()
    state: bool | None = None
    for token in _iter_option_tokens(value):
        if not token:
            continue
        action = token[0] if token[0] in "+-" else ""
        name = token[1:] if action else token
        if name.lower() == target:
            state = action != "-"
    return state


def _iter_option_tokens(value: str) -> list[str]:
    parts = _shell_split(value)
    tokens: list[str] = []
    for part in parts:
        tokens.extend(
            token
            for token in (_clean_token(item) for item in _OPTION_SPLIT_RE.split(part))
            if token
        )
    return tokens


def _shell_split(value: str) -> list[str]:
    try:
        return shlex.split(value)
    except ValueError:
        return [value]


def _clean_token(value: str) -> str:
    token = value.strip()
    if len(token) >= 2 and token[0] == token[-1] and token[0] in {'"', "'"}:
        token = token[1:-1].strip()
    return token


__all__ = ["ssl_conf_option_state"]
