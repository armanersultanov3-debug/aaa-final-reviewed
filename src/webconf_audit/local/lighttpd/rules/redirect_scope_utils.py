"""Rule module: redirect scope utils.

Location: ``src/webconf_audit/local/lighttpd/rules/redirect_scope_utils.py``.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from webconf_audit.local.lighttpd.parser import (
    LighttpdAssignmentNode,
    LighttpdBlockNode,
    LighttpdConfigAst,
)
from webconf_audit.local.lighttpd.rules.rule_utils import collect_modules

_REDIRECT_METADATA_ASSIGNMENTS = frozenset(
    {
        "server.bind",
        "server.modules",
        "server.port",
    }
)
_WHOLE_PATTERNS = frozenset(
    {
        "^",
        "^/",
        "^/(.*)$",
        "^/(.*)",
        "^.*$",
        "^(.*)$",
        "^(.*)",
        ".*",
    }
)
_REDIRECT_PAIR_RE = re.compile(
    r"""["'](?P<pattern>[^"']+)["']\s*=>\s*["'](?P<target>[^"']+)["']"""
)


def is_redirect_only_config(config_ast: LighttpdConfigAst) -> bool:
    if "mod_redirect" not in collect_modules(config_ast):
        return False

    has_whole_https_redirect = False
    for node in config_ast.nodes:
        if isinstance(node, LighttpdBlockNode):
            return False
        if not isinstance(node, LighttpdAssignmentNode):
            return False
        if node.name == "url.redirect":
            if not redirect_value_targets_whole_https(node.value):
                return False
            has_whole_https_redirect = True
            continue
        if node.name not in _REDIRECT_METADATA_ASSIGNMENTS:
            return False

    return has_whole_https_redirect


def redirect_value_targets_whole_https(value: str) -> bool:
    saw_pair = False
    cursor = 0
    for match in _REDIRECT_PAIR_RE.finditer(value):
        if not _only_pair_separators(value[cursor : match.start()]):
            return False
        if not (
            _is_whole_pattern(match.group("pattern"))
            and _is_https_target(match.group("target"))
        ):
            return False
        saw_pair = True
        cursor = match.end()
    return saw_pair and _only_pair_separators(value[cursor:])


def _only_pair_separators(value: str) -> bool:
    return all(char in " \t\r\n()," for char in value)


def _is_whole_pattern(value: str) -> bool:
    return value.strip() in _WHOLE_PATTERNS


def _is_https_target(value: str) -> bool:
    return urlparse(value.strip()).scheme.lower() == "https"


__all__ = ["is_redirect_only_config", "redirect_value_targets_whole_https"]
