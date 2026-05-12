from __future__ import annotations

from webconf_audit.local.apache.effective import (
    EffectiveDirective,
    extract_virtualhost_contexts,
)
from webconf_audit.local.apache.parser import ApacheConfigAst
from webconf_audit.local.apache.rules.effective_directive_check import (
    directive_effective_cause_key,
    group_unsafe_effective_by_source,
    unsafe_effective_group_metadata,
)
from webconf_audit.local.apache.rules.server_directive_utils import (
    directive_location,
    iter_effective_server_directives,
)
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "apache.log_level_too_restrictive"
_TOO_RESTRICTIVE_LEVELS = frozenset({"emerg", "alert", "crit", "error"})


@rule(
    rule_id=RULE_ID,
    title="LogLevel is too restrictive",
    severity="low",
    description="Apache LogLevel suppresses operational events needed for audit trails.",
    recommendation="Use at least warn, notice, or info verbosity for error logging.",
    category="local",
    server_type="apache",
    order=346,
)
def find_log_level_too_restrictive(config_ast: ApacheConfigAst) -> list[Finding]:
    if not extract_virtualhost_contexts(config_ast):
        directive = _single_server_directive(config_ast)
        if directive is None or not _is_too_restrictive_log_level(directive):
            return []
        return [_build_finding(directive, metadata={})]

    findings: list[Finding] = []
    for directive, affected_contexts in group_unsafe_effective_by_source(
        config_ast,
        "loglevel",
        _is_too_restrictive_log_level,
    ):
        findings.append(
            _build_finding(
                directive,
                metadata=unsafe_effective_group_metadata(
                    directive,
                    affected_contexts,
                ),
            )
        )

    return findings


def _single_server_directive(config_ast: ApacheConfigAst) -> EffectiveDirective | None:
    for _context, directive in iter_effective_server_directives(config_ast, "loglevel"):
        return directive
    return None


def _build_finding(
    directive: EffectiveDirective,
    *,
    metadata: dict[str, object],
) -> Finding:
    restrictive_levels = sorted(
        level
        for level in _configured_levels(directive)
        if level in _TOO_RESTRICTIVE_LEVELS
    )
    return Finding(
        rule_id=RULE_ID,
        title="LogLevel is too restrictive",
        severity="low",
        description=(
            "Apache LogLevel suppresses audit-relevant events: "
            + ", ".join(restrictive_levels)
        ),
        recommendation="Use at least warn, notice, or info verbosity.",
        location=directive_location(directive),
        metadata=metadata,
        effective_cause_key=directive_effective_cause_key(directive),
    )


def _is_too_restrictive_log_level(directive: EffectiveDirective) -> bool:
    return bool(_configured_levels(directive) & _TOO_RESTRICTIVE_LEVELS)


def _configured_levels(directive: EffectiveDirective) -> set[str]:
    levels: set[str] = set()
    for arg in directive.args:
        if isinstance(arg, list):
            continue
        token = arg.lower()
        if ":" in token:
            token = token.rsplit(":", 1)[1]
        levels.add(token)
    return levels


__all__ = ["find_log_level_too_restrictive"]
