"""apache.os_root_access_not_denied -- OS-root Directory baseline is missing or permissive."""

from __future__ import annotations

from webconf_audit.local.apache.authorization import (
    ApacheRootAuthorizationAssessment,
    evaluate_root_authorization,
)
from webconf_audit.local.apache.parser import ApacheConfigAst
from webconf_audit.local.apache.rules._block_policy_utils import default_location
from webconf_audit.models import AnalysisIssue, Finding, SourceLocation
from webconf_audit.rule_registry import StandardReference, rule
from webconf_audit.standards import cwe, owasp_top10_2021

RULE_ID = "apache.os_root_access_not_denied"
_ISSUE_CODE = "apache_root_authorization_indeterminate"


@rule(
    rule_id=RULE_ID,
    title="OS-root Directory scope does not deny access by default",
    severity="medium",
    description=(
        "Apache does not prove an effective deny-all authorization baseline for "
        "the OS-root '<Directory />' scope."
    ),
    recommendation=(
        "Define an OS-root '<Directory />' baseline that effectively denies all "
        "requests, then re-open only narrower directories that must serve content."
    ),
    category="local",
    server_type="apache",
    standards=(
        cwe(284),
        owasp_top10_2021("A05:2021"),
        StandardReference(
            standard="CIS",
            reference="Apache HTTP Server 2.4 v2.3.0 §4.1",
            url="https://www.cisecurity.org/benchmark/apache_http_server",
            coverage="direct",
            note=(
                "Validates a visible OS-root '<Directory />' authorization "
                "baseline and conservative same-path merge behavior."
            ),
        ),
    ),
    order=318,
)
def find_os_root_access_not_denied(
    config_ast: ApacheConfigAst,
    *,
    issues: list[AnalysisIssue] | None = None,
) -> list[Finding]:
    assessment = evaluate_root_authorization(config_ast, issues=issues)
    if assessment.effective.decision == "indeterminate":
        _append_indeterminate_issue(assessment, issues)
        return []

    if not assessment.root_blocks:
        return [_missing_root_finding(config_ast)]

    if assessment.effective.decision in {"not_defined", "not_deny_all"}:
        return [_permissive_root_finding(assessment)]

    return []


def _missing_root_finding(config_ast: ApacheConfigAst) -> Finding:
    return Finding(
        rule_id=RULE_ID,
        title="OS-root Directory scope does not deny access by default",
        severity="medium",
        description=(
            "Apache config does not define an OS-root '<Directory />' scope "
            "with an effective deny-all authorization baseline."
        ),
        recommendation=(
            "Add an OS-root '<Directory />' scope with 'Require all denied' "
            "before narrower Directory scopes selectively re-open content."
        ),
        location=default_location(config_ast),
    )


def _permissive_root_finding(
    assessment: ApacheRootAuthorizationAssessment,
) -> Finding:
    location = _assessment_location(assessment)
    if assessment.effective.decision == "not_defined":
        detail = (
            "replaces or defines the OS-root Directory scope without any "
            "effective authorization policy"
        )
    else:
        detail = (
            "effectively authorizes at least one request path or merge branch "
            "at the OS-root Directory scope"
        )

    return Finding(
        rule_id=RULE_ID,
        title="OS-root Directory scope does not deny access by default",
        severity="medium",
        description=(
            "This configuration "
            f"{detail}. CIS Apache hardening expects '<Directory />' to deny "
            "all requests by default."
        ),
        recommendation=(
            "Set the effective OS-root '<Directory />' authorization to "
            "'Require all denied' and keep any necessary access in narrower "
            "Directory scopes."
        ),
        location=location,
        metadata={
            "authorization_syntax": assessment.effective.syntax,
            "auth_merging": assessment.effective.auth_merging,
            "reasons": list(assessment.effective.reasons),
        },
    )


def _append_indeterminate_issue(
    assessment: ApacheRootAuthorizationAssessment,
    issues: list[AnalysisIssue] | None,
) -> None:
    if issues is None:
        return
    if any(issue.code == _ISSUE_CODE for issue in issues):
        return

    reasons = ", ".join(assessment.effective.reasons) or "unknown reason"
    refs = ", ".join(_format_refs(assessment)) or "no source location"
    issues.append(
        AnalysisIssue(
            code=_ISSUE_CODE,
            level="warning",
            message=(
                "Apache OS-root authorization baseline could not be determined "
                "conclusively."
            ),
            details=f"Reasons: {reasons}. Evidence blockers: {refs}.",
            location=_assessment_location(assessment),
            metadata={
                "rule_id": RULE_ID,
                "authorization_syntax": assessment.effective.syntax,
                "auth_merging": assessment.effective.auth_merging,
                "include_graph_complete": assessment.include_graph_complete,
                "reasons": list(assessment.effective.reasons),
                "unsupported_constructs": [
                    {
                        "file_path": ref.file_path,
                        "line": ref.line,
                        "details": ref.details,
                    }
                    for ref in assessment.unsupported_constructs
                ],
            },
        )
    )


def _assessment_location(
    assessment: ApacheRootAuthorizationAssessment,
) -> SourceLocation | None:
    if assessment.effective.evidence:
        ref = assessment.effective.evidence[-1]
        return SourceLocation(
            mode="local",
            kind="file",
            file_path=ref.file_path,
            line=ref.line,
            details=ref.details,
        )

    if assessment.unsupported_constructs:
        ref = assessment.unsupported_constructs[0]
        return SourceLocation(
            mode="local",
            kind="file",
            file_path=ref.file_path,
            line=ref.line,
            details=ref.details,
        )

    if assessment.root_blocks:
        block = assessment.root_blocks[-1]
        return SourceLocation(
            mode="local",
            kind="file",
            file_path=block.source.file_path,
            line=block.source.line,
        )

    return None


def _format_refs(
    assessment: ApacheRootAuthorizationAssessment,
) -> list[str]:
    refs: list[str] = []
    for ref in assessment.unsupported_constructs:
        text = ref.file_path
        if ref.line is not None:
            text = f"{text}:{ref.line}"
        if ref.details:
            text = f"{text} ({ref.details})"
        refs.append(text)
    return refs


__all__ = ["find_os_root_access_not_denied"]
