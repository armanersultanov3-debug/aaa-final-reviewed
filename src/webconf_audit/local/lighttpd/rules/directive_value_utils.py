"""Rule module: directive value utils.

Location: ``src/webconf_audit/local/lighttpd/rules/directive_value_utils.py``.
"""

from __future__ import annotations

from collections.abc import Iterator

from webconf_audit.local.lighttpd.conditions import LighttpdRequestContext
from webconf_audit.local.lighttpd.effective import (
    LighttpdEffectiveConfig,
    LighttpdEffectiveDirective,
)
from webconf_audit.local.lighttpd.parser import (
    LighttpdAssignmentNode,
    LighttpdConfigAst,
)
from webconf_audit.local.lighttpd.rules.rule_utils import iter_all_nodes, unquote
from webconf_audit.models import SourceLocation


def iter_effective_assignments(
    config_ast: LighttpdConfigAst,
    directive_name: str,
    *,
    effective_config: LighttpdEffectiveConfig | None = None,
    merged_directives: dict[str, LighttpdEffectiveDirective] | None = None,
    request_context: LighttpdRequestContext | None = None,
) -> Iterator[LighttpdEffectiveDirective | LighttpdAssignmentNode]:
    if merged_directives is not None and request_context is not None:
        directive = merged_directives.get(directive_name)
        if directive is not None:
            yield directive
        return

    if effective_config is not None:
        global_directive = effective_config.global_directives.get(directive_name)
        if global_directive is not None:
            yield global_directive
        for scope in effective_config.conditional_scopes:
            directive = scope.directives.get(directive_name)
            if directive is not None:
                yield directive
        return

    for node in iter_all_nodes(config_ast):
        if isinstance(node, LighttpdAssignmentNode) and node.name == directive_name:
            yield node


def configured_value(
    directive: LighttpdEffectiveDirective | LighttpdAssignmentNode,
) -> str:
    return unquote(directive.value).strip()


def parse_int_value(
    directive: LighttpdEffectiveDirective | LighttpdAssignmentNode,
) -> int | None:
    try:
        return int(configured_value(directive))
    except ValueError:
        return None


def directive_location(
    directive: LighttpdEffectiveDirective | LighttpdAssignmentNode,
    *,
    fallback: SourceLocation | None = None,
) -> SourceLocation:
    if directive.source.file_path is None or directive.source.line is None:
        if fallback is not None:
            return fallback
        return SourceLocation(
            mode="local",
            kind="file",
            file_path=directive.source.file_path or "<unknown>",
            line=directive.source.line or 0,
            details="Source location unavailable in Lighttpd AST.",
        )

    return SourceLocation(
        mode="local",
        kind="file",
        file_path=directive.source.file_path,
        line=directive.source.line,
    )


__all__ = [
    "configured_value",
    "directive_location",
    "iter_effective_assignments",
    "parse_int_value",
]
