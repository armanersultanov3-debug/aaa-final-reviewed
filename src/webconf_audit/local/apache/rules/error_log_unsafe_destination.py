from __future__ import annotations

from webconf_audit.local.apache.effective import (
    ApacheVirtualHostContext,
    EffectiveDirective,
    extract_virtualhost_contexts,
)
from webconf_audit.local.apache.parser import ApacheConfigAst
from webconf_audit.local.apache.rules.effective_directive_check import (
    group_unsafe_effective_by_source,
)
from webconf_audit.local.apache.rules.server_directive_utils import (
    directive_location,
    iter_effective_server_directives,
    virtualhost_label,
)
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "apache.error_log_unsafe_destination"


@rule(
    rule_id=RULE_ID,
    title="ErrorLog destination is unsafe",
    severity="low",
    description="Apache ErrorLog discards error events or has no destination.",
    recommendation="Write ErrorLog to a real file or managed logging sink.",
    category="local",
    server_type="apache",
    order=345,
)
def find_error_log_unsafe_destination(config_ast: ApacheConfigAst) -> list[Finding]:
    if not extract_virtualhost_contexts(config_ast):
        directive = _single_server_directive(config_ast)
        if directive is None or not _is_unsafe_error_log_destination(directive):
            return []
        return [_build_finding(directive, metadata={})]

    findings: list[Finding] = []
    for directive, affected_contexts in group_unsafe_effective_by_source(
        config_ast,
        "errorlog",
        _is_unsafe_error_log_destination,
    ):
        findings.append(
            _build_finding(
                directive,
                metadata=_group_metadata(directive, affected_contexts),
            )
        )

    return findings


def _single_server_directive(config_ast: ApacheConfigAst) -> EffectiveDirective | None:
    for _context, directive in iter_effective_server_directives(config_ast, "errorlog"):
        return directive
    return None


def _build_finding(
    directive: EffectiveDirective,
    *,
    metadata: dict[str, object],
) -> Finding:
    return Finding(
        rule_id=RULE_ID,
        title="ErrorLog destination is unsafe",
        severity="low",
        description=(
            "Apache ErrorLog points to /dev/null or omits a destination, "
            "so server error events may be discarded."
        ),
        recommendation="Set ErrorLog to a real file or managed logging sink.",
        location=directive_location(directive),
        metadata=metadata,
    )


def _group_metadata(
    directive: EffectiveDirective,
    affected_contexts: list[ApacheVirtualHostContext],
) -> dict[str, object]:
    if directive.origin.layer == "global":
        return {
            "scope_name": virtualhost_label(None),
            "affected_scopes": [
                virtualhost_label(context) for context in affected_contexts
            ],
        }

    return {"scope_name": virtualhost_label(affected_contexts[0])}


def _is_unsafe_error_log_destination(directive: EffectiveDirective) -> bool:
    if not directive.args:
        return True
    destination = directive.args[0]
    if isinstance(destination, list):
        return False
    return destination.lower() == "/dev/null"


__all__ = ["find_error_log_unsafe_destination"]
