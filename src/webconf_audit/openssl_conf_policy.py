from __future__ import annotations

import re

_OPTION_SPLIT_RE = re.compile(r"[\s,]+")


def ssl_conf_option_state(value: str, option_name: str) -> bool | None:
    """Return the final explicit state of an OpenSSL SSL_CONF Options token."""
    target = option_name.lower()
    state: bool | None = None
    for raw_token in _OPTION_SPLIT_RE.split(value):
        token = _clean_token(raw_token)
        if not token:
            continue
        action = token[0] if token[0] in "+-" else ""
        name = token[1:] if action else token
        if name.lower() == target:
            state = action != "-"
    return state


def _clean_token(value: str) -> str:
    token = value.strip()
    if len(token) >= 2 and token[0] == token[-1] and token[0] in {'"', "'"}:
        token = token[1:-1].strip()
    return token


__all__ = ["ssl_conf_option_state"]
