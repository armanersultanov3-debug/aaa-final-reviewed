from __future__ import annotations

from webconf_audit.header_policy import permissions_policy_is_safe
from webconf_audit.local.apache.parser import ApacheConfigAst
from webconf_audit.local.apache.rules.security_header_utils import (
    ApacheHeaderOutcome,
    ApacheHeaderSetting,
    iter_effective_header_scopes,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "apache.permissions_policy_runtime_quality"
TITLE = "Permissions-Policy is not emitted with runtime-safe quality"
DESCRIPTION = (
    "Apache emits Permissions-Policy only on successful responses or through "
    "another runtime path that can drop the header."
)
RECOMMENDATION = (
    "Use 'Header always set Permissions-Policy ...' so the policy survives "
    "error responses and other non-2xx paths."
)


@rule(
    rule_id=RULE_ID,
    title=TITLE,
    severity="low",
    description=DESCRIPTION,
    recommendation=RECOMMENDATION,
    category="local",
    server_type="apache",
    tags=("headers",),
    order=376,
)
def find_permissions_policy_runtime_quality(
    config_ast: ApacheConfigAst,
) -> list[Finding]:
    findings: list[Finding] = []
    for scope in iter_effective_header_scopes(config_ast, "Permissions-Policy"):
        if not scope.auditable:
            continue
        problematic = _first_problematic_outcome(scope.outcomes)
        if problematic is None:
            continue

        _, setting = problematic
        findings.append(
            Finding(
                rule_id=RULE_ID,
                title=TITLE,
                severity="low",
                description=(
                    f"Apache scope '{scope.label}' sets Permissions-Policy via "
                    "a response path that is not guaranteed for error/redirect "
                    "responses."
                ),
                recommendation=RECOMMENDATION,
                location=SourceLocation(
                    mode="local",
                    kind="file",
                    file_path=setting.source.file_path,
                    line=setting.source.line,
                ),
                metadata={"scope_name": scope.label},
            )
        )

    return findings


def _first_problematic_outcome(
    outcomes: list[ApacheHeaderOutcome],
) -> tuple[ApacheHeaderOutcome, ApacheHeaderSetting] | None:
    for outcome in outcomes:
        if not outcome.onsuccess or outcome.always:
            continue
        if not _outcome_has_safe_value(outcome):
            continue
        return outcome, outcome.onsuccess[-1]
    return None


def _outcome_has_safe_value(outcome: ApacheHeaderOutcome) -> bool:
    settings = outcome.always or outcome.onsuccess
    if not settings:
        return False
    rendered = _render_settings(settings)
    return permissions_policy_is_safe(rendered)


def _render_settings(settings: list[ApacheHeaderSetting]) -> str | None:
    values = [setting.value for setting in settings if setting.value is not None]
    if not values:
        return None
    return ", ".join(values)


__all__ = ["find_permissions_policy_runtime_quality"]
