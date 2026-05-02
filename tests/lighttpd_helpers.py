import re
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

from webconf_audit.local.lighttpd import analyze_lighttpd_config
from webconf_audit.local.lighttpd.include import resolve_includes
from webconf_audit.local.lighttpd.parser import (
    LighttpdAssignmentNode,
    LighttpdBlockNode,
    LighttpdCondition,
    LighttpdDirectiveNode,
    LighttpdParseError,
    parse_lighttpd_config,
)
from webconf_audit.local.lighttpd.effective import build_effective_config
from webconf_audit.local.lighttpd.rules.mod_cgi_enabled import find_mod_cgi_enabled
from webconf_audit.local.lighttpd.rules.server_tag_not_blank import find_server_tag_not_blank
from webconf_audit.local.lighttpd.rules.ssl_engine_not_enabled import (
    find_ssl_engine_not_enabled,
)
from webconf_audit.local.normalizers.lighttpd_normalizer import _parse_header_tuple
from webconf_audit.local.lighttpd.shell import execute_include_shell
from webconf_audit.local.lighttpd.variables import _quote, expand_variables
from webconf_audit.models import AnalysisResult


def _fake_shell_include_result(result: str | None) -> Callable[..., str | None]:
    def _runner(*_args: object, **_kwargs: object) -> str | None:
        return result

    return _runner


def _raise_regex_error(*_args: object, **_kwargs: object) -> list[str]:
    raise re.error("malformed character range")


def _collect_mod_cgi(*_args: object, **_kwargs: object) -> set[str]:
    return {"mod_cgi"}


__all__ = [
    "AnalysisResult",
    "Callable",
    "LighttpdAssignmentNode",
    "LighttpdBlockNode",
    "LighttpdCondition",
    "LighttpdDirectiveNode",
    "LighttpdParseError",
    "Path",
    "_collect_mod_cgi",
    "_fake_shell_include_result",
    "_parse_header_tuple",
    "_quote",
    "_raise_regex_error",
    "analyze_lighttpd_config",
    "build_effective_config",
    "execute_include_shell",
    "expand_variables",
    "find_mod_cgi_enabled",
    "find_server_tag_not_blank",
    "find_ssl_engine_not_enabled",
    "parse_lighttpd_config",
    "pytest",
    "re",
    "resolve_includes",
    "sys"
]
