"""Shared helper for effective-config-aware directive checks.

Provides a generic pattern for rules that need to check whether a
directive token (e.g. ``Options Indexes``, ``IndexOptions FancyIndexing``)
is effectively enabled after VirtualHost and Directory inheritance.

Usage::

    from webconf_audit.local.apache.rules.effective_directive_check import (
        check_effective_directive_token,
    )

    findings = check_effective_directive_token(
        config_ast,
        directive_name="options",
        positive_tokens={"indexes", "+indexes"},
        disabled_value="-indexes",
        build_finding=my_finding_builder,
    )
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from pathlib import Path

from webconf_audit.local.apache.effective import (
    ApacheVirtualHostContext,
    EffectiveDirective,
    build_effective_config,
    build_server_effective_config,
    extract_virtualhost_contexts,
    find_scoped_directive,
)
from webconf_audit.local.apache.parser import (
    ApacheBlockNode,
    ApacheConfigAst,
    ApacheDirectiveNode,
)
from webconf_audit.local.apache.rules.server_directive_utils import (
    iter_effective_server_directives,
    virtualhost_label,
)
from webconf_audit.models import Finding

FindingBuilder = Callable[[EffectiveDirective, str], Finding]

_TRANSPARENT_WRAPPER_BLOCKS = frozenset(
    {"if", "ifdefine", "ifmodule", "ifversion", "else", "elseif"}
)


def iter_vhosts_missing_directive(
    config_ast: ApacheConfigAst,
    directive_name: str,
) -> Iterable[ApacheVirtualHostContext]:
    """Yield VirtualHosts where the directive is missing after server inheritance."""
    virtualhosts = extract_virtualhost_contexts(config_ast)
    if not virtualhosts:
        return

    lowered_name = directive_name.lower()
    if build_server_effective_config(config_ast).directives.get(lowered_name) is not None:
        return

    for context in virtualhosts:
        if find_scoped_directive(context.node.children, lowered_name) is None:
            yield context


def group_unsafe_effective_by_source(
    config_ast: ApacheConfigAst,
    directive_name: str,
    is_unsafe: Callable[[EffectiveDirective], bool],
) -> list[tuple[EffectiveDirective, list[ApacheVirtualHostContext]]]:
    """Group affected vhosts by the directive source that materialised the
    unsafe effective value.

    Returns a list of (source_directive, affected_contexts), one entry per
    distinct (file_path, line) source of an unsafe effective value across all
    vhost contexts. Affected contexts is the list of vhosts that inherit or
    declare that exact source.
    """
    grouped: dict[
        tuple[str | None, int | None],
        tuple[EffectiveDirective, list[ApacheVirtualHostContext]],
    ] = {}

    for context, directive in iter_effective_server_directives(
        config_ast,
        directive_name,
    ):
        if context is None or directive is None or not is_unsafe(directive):
            continue

        key = (directive.origin.source.file_path, directive.origin.source.line)
        if key not in grouped:
            grouped[key] = (directive, [])
        grouped[key][1].append(context)

    return list(grouped.values())


def unsafe_effective_group_metadata(
    directive: EffectiveDirective,
    affected_contexts: list[ApacheVirtualHostContext],
) -> dict[str, object]:
    """Build metadata for an unsafe effective directive source group."""
    assert affected_contexts, "Expected at least one affected context"

    if directive.origin.layer == "global":
        return {
            "scope_name": virtualhost_label(None),
            "affected_scopes": [
                virtualhost_label(context) for context in affected_contexts
            ],
        }

    return {"scope_name": virtualhost_label(affected_contexts[0])}


def check_effective_directive_token(
    config_ast: ApacheConfigAst,
    *,
    directive_name: str,
    positive_tokens: frozenset[str],
    disabled_value: str | None,
    build_finding: FindingBuilder,
) -> list[Finding]:
    """Check effective config for a directive token across all scopes.

    Checks three levels:
    1. Server-level effective config (global or per-VH) — catches directives
       set at VirtualHost level without a ``<Directory>`` wrapper.
    2. Per-``<Directory>`` effective config — catches overrides at directory scope.
    3. Per-``<Location>`` effective config — catches directives in Location blocks.

    Parameters
    ----------
    config_ast:
        Parsed Apache configuration AST.
    directive_name:
        Lowercase directive name to look up in effective config.
    positive_tokens:
        Lowercase arg values that mean "enabled".
    disabled_value:
        Lowercase arg value that means "disabled".
    build_finding:
        Callable ``(effective_directive, context_name) -> Finding``.
    """
    virtualhosts = extract_virtualhost_contexts(config_ast)

    if not virtualhosts:
        return _check_for_context(
            config_ast,
            virtualhost_context=None,
            directive_name=directive_name,
            positive_tokens=positive_tokens,
            disabled_value=disabled_value,
            build_finding=build_finding,
        )

    findings: list[Finding] = []
    seen: set[tuple[str | None, int | None]] = set()
    for context in virtualhosts:
        for f in _check_for_context(
            config_ast,
            virtualhost_context=context,
            directive_name=directive_name,
            positive_tokens=positive_tokens,
            disabled_value=disabled_value,
            build_finding=build_finding,
        ):
            key = (
                f.location.file_path if f.location else None,
                f.location.line if f.location else None,
            )
            if key not in seen:
                seen.add(key)
                findings.append(f)
    return findings


def _check_for_context(
    config_ast: ApacheConfigAst,
    *,
    virtualhost_context: ApacheVirtualHostContext | None,
    directive_name: str,
    positive_tokens: frozenset[str],
    disabled_value: str | None,
    build_finding: FindingBuilder,
) -> list[Finding]:
    findings = _server_level_findings(
        config_ast,
        virtualhost_context=virtualhost_context,
        directive_name=directive_name,
        positive_tokens=positive_tokens,
        disabled_value=disabled_value,
        build_finding=build_finding,
    )
    findings.extend(
        _directory_scope_findings(
            config_ast,
            virtualhost_context=virtualhost_context,
            directive_name=directive_name,
            positive_tokens=positive_tokens,
            disabled_value=disabled_value,
            build_finding=build_finding,
        )
    )
    findings.extend(
        _location_scope_findings(
            config_ast,
            virtualhost_context=virtualhost_context,
            directive_name=directive_name,
            positive_tokens=positive_tokens,
            disabled_value=disabled_value,
            build_finding=build_finding,
        )
    )
    return _deduplicate_findings_by_location(findings)


def _server_level_findings(
    config_ast: ApacheConfigAst,
    *,
    virtualhost_context: ApacheVirtualHostContext | None,
    directive_name: str,
    positive_tokens: frozenset[str],
    disabled_value: str | None,
    build_finding: FindingBuilder,
) -> list[Finding]:
    server_effective = build_server_effective_config(
        config_ast,
        virtualhost_context=virtualhost_context,
    )
    directive = server_effective.directives.get(directive_name)
    if directive is None or not _has_token(
        directive,
        positive_tokens,
        disabled_value,
    ):
        return []

    context_name = "virtualhost" if virtualhost_context else "global"
    return [build_finding(directive, context_name)]


def _directory_scope_findings(
    config_ast: ApacheConfigAst,
    *,
    virtualhost_context: ApacheVirtualHostContext | None,
    directive_name: str,
    positive_tokens: frozenset[str],
    disabled_value: str | None,
    build_finding: FindingBuilder,
) -> list[Finding]:
    findings: list[Finding] = []
    directory_blocks = _collect_directory_blocks(
        config_ast.nodes,
        virtualhost_context=virtualhost_context,
    )
    for block in directory_blocks:
        dir_path = _directory_path(block)
        if dir_path is None:
            continue

        effective = build_effective_config(
            config_ast,
            str(dir_path),
            virtualhost_context=virtualhost_context,
        )
        directive = effective.directives.get(directive_name)
        if directive is not None and _has_token(
            directive,
            positive_tokens,
            disabled_value,
        ):
            findings.append(build_finding(directive, "directory"))
    return findings


def _location_scope_findings(
    config_ast: ApacheConfigAst,
    *,
    virtualhost_context: ApacheVirtualHostContext | None,
    directive_name: str,
    positive_tokens: frozenset[str],
    disabled_value: str | None,
    build_finding: FindingBuilder,
) -> list[Finding]:
    findings: list[Finding] = []
    base_effective = build_effective_config(
        config_ast,
        "/",
        virtualhost_context=virtualhost_context,
    )
    for loc_scope in base_effective.location_scopes:
        directive = loc_scope.directives.get(directive_name)
        if directive is not None and _has_token(
            directive,
            positive_tokens,
            disabled_value,
        ):
            findings.append(build_finding(directive, "location"))
    return findings


def _deduplicate_findings_by_location(findings: list[Finding]) -> list[Finding]:
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


def _has_token(
    directive: EffectiveDirective,
    positive_tokens: frozenset[str],
    disabled_value: str | None,
) -> bool:
    if not directive.args:
        return False
    if isinstance(directive.args[0], list):
        return False
    if disabled_value is not None and any(
        arg.lower() == disabled_value for arg in directive.args
    ):
        return False
    for arg in directive.args:
        lowered = arg.lower()
        if lowered in positive_tokens:
            return True
    return False


def _collect_directory_blocks(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
    virtualhost_context: ApacheVirtualHostContext | None,
) -> list[ApacheBlockNode]:
    """Collect Directory blocks relevant to the given context."""
    blocks: list[ApacheBlockNode] = []
    for node in nodes:
        if not isinstance(node, ApacheBlockNode):
            continue
        name = node.name.lower()

        if name == "virtualhost":
            if virtualhost_context is not None and node is virtualhost_context.node:
                blocks.extend(
                    _collect_directory_blocks(node.children, virtualhost_context=None)
                )
            continue

        if name == "directory":
            blocks.append(node)

        if name in _TRANSPARENT_WRAPPER_BLOCKS:
            blocks.extend(
                _collect_directory_blocks(
                    node.children, virtualhost_context=virtualhost_context
                )
            )
    return blocks


def _directory_path(block: ApacheBlockNode) -> Path | None:
    if not block.args:
        return None
    raw = block.args[0]
    if raw.startswith("~"):
        return None
    return Path(raw)


__all__ = [
    "check_effective_directive_token",
    "group_unsafe_effective_by_source",
    "iter_vhosts_missing_directive",
    "unsafe_effective_group_metadata",
]
