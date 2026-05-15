"""Rule module: server directive utils.

Location: ``src/webconf_audit/local/apache/rules/server_directive_utils.py``.
"""

from __future__ import annotations

from collections.abc import Iterator

from webconf_audit.local.apache.effective import (
    ApacheVirtualHostContext,
    EffectiveDirective,
    build_server_effective_config,
    extract_virtualhost_contexts,
)
from webconf_audit.local.apache.parser import ApacheConfigAst
from webconf_audit.models import Finding, SourceLocation


def iter_effective_server_directives(
    config_ast: ApacheConfigAst,
    directive_name: str,
) -> Iterator[tuple[ApacheVirtualHostContext | None, EffectiveDirective | None]]:
    contexts = extract_virtualhost_contexts(config_ast)
    if not contexts:
        yield None, build_server_effective_config(config_ast).directives.get(
            directive_name.lower()
        )
        return

    for context in contexts:
        yield context, build_server_effective_config(
            config_ast,
            virtualhost_context=context,
        ).directives.get(directive_name.lower())


def parse_single_positive_int(args: list[str]) -> int | None:
    if len(args) != 1:
        return None
    try:
        value = int(args[0])
    except ValueError:
        return None
    if value <= 0:
        return None
    return value


def directive_location(directive: EffectiveDirective) -> SourceLocation:
    return SourceLocation(
        mode="local",
        kind="file",
        file_path=directive.origin.source.file_path,
        line=directive.origin.source.line,
    )


def default_location(config_ast: ApacheConfigAst) -> SourceLocation | None:
    if not config_ast.nodes:
        return None

    source = config_ast.nodes[0].source
    return SourceLocation(
        mode="local",
        kind="file",
        file_path=source.file_path,
        line=source.line,
    )


def virtualhost_label(context: ApacheVirtualHostContext | None) -> str:
    if context is None:
        return "global"
    return context.server_name or context.listen_address or "<unnamed>"


def configured_value(directive: EffectiveDirective) -> str:
    if not directive.args:
        return "<missing value>"
    if isinstance(directive.args[0], list):
        return " ".join(" ".join(entry) for entry in directive.args)
    return " ".join(directive.args)


def deduplicate_findings_by_location(findings: list[Finding]) -> list[Finding]:
    deduplicated: list[Finding] = []
    seen: set[tuple[str | None, int | None]] = set()
    for finding in findings:
        key = (
            finding.location.file_path if finding.location else None,
            finding.location.line if finding.location else None,
        )
        if key in seen:
            continue
        seen.add(key)
        deduplicated.append(finding)
    return deduplicated


__all__ = [
    "configured_value",
    "deduplicate_findings_by_location",
    "default_location",
    "directive_location",
    "iter_effective_server_directives",
    "parse_single_positive_int",
    "virtualhost_label",
]
