from __future__ import annotations

from webconf_audit.local.apache.parser import ApacheConfigAst
from webconf_audit.local.apache.rules._log_policy_utils import (
    ResolvedCustomLogFormat,
    iter_effective_custom_log_formats,
)
from webconf_audit.local.apache.rules.server_directive_utils import (
    virtualhost_label,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "apache.missing_log_format"


@rule(
    rule_id=RULE_ID,
    title="CustomLog references undefined LogFormat",
    severity="low",
    description="Apache CustomLog uses a named format that is not defined.",
    recommendation="Define a matching LogFormat or use a known built-in format.",
    category="local",
    server_type="apache",
    order=347,
)
def find_missing_log_format(config_ast: ApacheConfigAst) -> list[Finding]:
    findings: list[Finding] = []
    affected_scopes: set[int | str] = set()

    for resolved in iter_effective_custom_log_formats(config_ast):
        if resolved.kind not in {"missing_named", "missing_default"}:
            continue

        scope_key = id(resolved.context) if resolved.context is not None else "global"
        if scope_key in affected_scopes:
            continue
        affected_scopes.add(scope_key)
        findings.append(_build_finding(resolved))

    return findings


def _build_finding(resolved: ResolvedCustomLogFormat) -> Finding:
    metadata = {"format_name": resolved.format_name}
    if resolved.context is not None:
        metadata["scope_name"] = virtualhost_label(resolved.context)

    if resolved.kind == "missing_default":
        description = (
            "CustomLog has no inline format, and no default LogFormat is defined "
            "in the applicable server scope."
        )
    else:
        description = (
            f"CustomLog references undefined LogFormat '{resolved.format_name}'."
        )

    return Finding(
        rule_id=RULE_ID,
        title="CustomLog references undefined LogFormat",
        severity="low",
        description=description,
        recommendation="Define a matching LogFormat or use a known built-in format.",
        location=SourceLocation(
            mode="local",
            kind="file",
            file_path=resolved.custom_log.source.file_path,
            line=resolved.custom_log.source.line,
        ),
        metadata=metadata,
    )


__all__ = ["find_missing_log_format"]
