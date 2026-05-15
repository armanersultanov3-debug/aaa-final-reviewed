"""Lighttpd ``var.*`` variable expansion for the parsed AST.

Substitutes ``var.<name>`` references, environment lookups, and
literal string concatenations so directive values match what Lighttpd
itself would see at runtime. Emits analysis issues for unresolved
references rather than crashing.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from pathlib import Path

from webconf_audit.local.lighttpd.parser import (
    LighttpdAssignmentNode,
    LighttpdAstNode,
    LighttpdBlockNode,
    LighttpdConfigAst,
)
from webconf_audit.models import AnalysisIssue, SourceLocation

_VAR_PREFIX = "var."
_ENV_PREFIX = "env."

# Matches a single token in a concatenation expression:
# either a quoted string ("..." or '...') or a bare identifier (var.name).
_CONCAT_TOKEN = re.compile(
    r"""
    \s*
    (?:
        "((?:[^"\\]|\\.)*)"    # double-quoted string
      | '((?:[^'\\]|\\.)*)'    # single-quoted string
      | ([a-zA-Z_][a-zA-Z0-9_.\-]*)  # bare identifier (var.name)
    )
    \s*
    """,
    re.VERBOSE,
)


def expand_variables(
    config_ast: LighttpdConfigAst,
    *,
    environ: Mapping[str, str] | None = None,
    builtins: Mapping[str, str] | None = None,
) -> list[AnalysisIssue]:
    variables: dict[str, str] = _builtin_variables(config_ast)
    if builtins is not None:
        variables.update(builtins)
    environment = os.environ if environ is None else environ
    issues: list[AnalysisIssue] = []
    _expand_nodes(config_ast.nodes, variables, environment, issues)
    return issues


def _builtin_variables(config_ast: LighttpdConfigAst) -> dict[str, str]:
    cwd = (
        str(Path(config_ast.main_file_path).resolve().parent)
        if config_ast.main_file_path is not None
        else str(Path.cwd())
    )
    return {
        "var.CWD": cwd,
        "var.PID": str(os.getpid()),
    }


def _expand_nodes(
    nodes: list[LighttpdAstNode],
    variables: dict[str, str],
    environ: Mapping[str, str],
    issues: list[AnalysisIssue],
) -> None:
    for node in nodes:
        if isinstance(node, LighttpdBlockNode):
            _expand_nodes(node.children, variables, environ, issues)
            continue

        if not isinstance(node, LighttpdAssignmentNode):
            continue

        if node.name.startswith(_VAR_PREFIX):
            _collect_variable(node, variables, environ, issues)
        else:
            _expand_value(node, variables, environ, issues)


def _collect_variable(
    node: LighttpdAssignmentNode,
    variables: dict[str, str],
    environ: Mapping[str, str],
    issues: list[AnalysisIssue],
) -> None:
    resolved = _resolve_expression(node.value, variables, environ, node, issues)
    if resolved is None:
        return

    if node.operator == "+=" and node.name in variables:
        variables[node.name] = variables[node.name] + resolved
    else:
        # Both "=" and ":=" set the value directly.
        variables[node.name] = resolved

    node.value = _quote(variables[node.name])


def _expand_value(
    node: LighttpdAssignmentNode,
    variables: dict[str, str],
    environ: Mapping[str, str],
    issues: list[AnalysisIssue],
) -> None:
    if not _references_variable(node.value):
        return

    resolved = _resolve_expression(node.value, variables, environ, node, issues)
    if resolved is not None:
        node.value = _quote(resolved)


def _references_variable(value: str) -> bool:
    return _VAR_PREFIX in value or _ENV_PREFIX in value


def _unescape_quoted_string(value: str, *, quote: str) -> str:
    result: list[str] = []
    escaped = False

    for char in value:
        if escaped:
            if char == quote or char == "\\":
                result.append(char)
            else:
                result.append(f"\\{char}")
            escaped = False
            continue

        if char == "\\":
            escaped = True
            continue

        result.append(char)

    if escaped:
        result.append("\\")

    return "".join(result)


def _resolve_expression(
    expression: str,
    variables: dict[str, str],
    environ: Mapping[str, str],
    node: LighttpdAssignmentNode,
    issues: list[AnalysisIssue],
) -> str | None:
    """Resolve a value expression like: var.x + "/path" or "literal".

    Returns the unquoted resolved string, or None if resolution failed.
    """
    parts: list[str] = []
    pos = 0
    text = expression.strip()

    while pos < len(text):
        match = _CONCAT_TOKEN.match(text, pos)
        if match is None:
            # Unparseable remainder — leave value as-is.
            return None

        double_quoted, single_quoted, bare_ident = match.groups()

        if double_quoted is not None:
            parts.append(_unescape_quoted_string(double_quoted, quote='"'))
        elif single_quoted is not None:
            parts.append(_unescape_quoted_string(single_quoted, quote="'"))
        elif bare_ident is not None:
            if bare_ident in variables:
                parts.append(variables[bare_ident])
            elif bare_ident.startswith(_ENV_PREFIX):
                env_name = bare_ident[len(_ENV_PREFIX) :]
                if env_name in environ:
                    parts.append(environ[env_name])
                else:
                    _append_undefined_issue(bare_ident, node, issues)
                    return None
            elif bare_ident.startswith(_VAR_PREFIX):
                _append_undefined_issue(bare_ident, node, issues)
                return None
            else:
                # Bare identifier that is not a var.* reference — not expandable.
                return None

        pos = match.end()

        # Skip optional '+' concatenation operator.
        rest = text[pos:].lstrip()
        if rest.startswith("+"):
            pos = pos + (len(text) - pos - len(rest)) + 1
        elif rest:
            # Unexpected content after token without '+' — leave value as-is.
            return None

    return "".join(parts)


def _append_undefined_issue(
    name: str,
    node: LighttpdAssignmentNode,
    issues: list[AnalysisIssue],
) -> None:
    issues.append(
        AnalysisIssue(
            code="lighttpd_undefined_variable",
            level="warning",
            message=f"Undefined variable reference: {name}",
            location=SourceLocation(
                mode="local",
                kind="file",
                file_path=node.source.file_path,
                line=node.source.line,
            ),
        )
    )


def _quote(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


__all__ = ["expand_variables"]
