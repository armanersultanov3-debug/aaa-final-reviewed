import json
from enum import Enum
from pathlib import Path
from typing import cast

import click
import typer

from webconf_audit.assessment import (
    AssessmentBuildError,
    AnalysisReportLoadError,
    build_control_assessment,
    load_analysis_report,
    verify_assessment_inputs,
)
from webconf_audit.assessment_models import AssessmentIssue, ControlAssessmentReport
from webconf_audit.assessment_renderers import (
    render_assessment_json,
    render_assessment_text,
)
from webconf_audit.audit_policy import (
    AuditPolicyLoadError,
    AuditPolicyResolveError,
    load_audit_policy,
    resolve_audit_policy,
    validate_audit_policy,
)
from webconf_audit.baselines import apply_baseline_diff, load_baseline_file, write_baseline_file
from webconf_audit.coverage_ledger import (
    CoverageLedgerLoadError,
    load_coverage_ledger,
    write_coverage_output,
)
from webconf_audit.external import (
    analyze_external_target,
    analyze_external_tls_inventory,
)
from webconf_audit.local.apache import analyze_apache_config
from webconf_audit.local.iis import analyze_iis_config
from webconf_audit.local.lighttpd import analyze_lighttpd_config
from webconf_audit.local.nginx import analyze_nginx_config
from webconf_audit.models import AnalysisIssue, AnalysisResult, Severity, SourceLocation
from webconf_audit.policy_models import AuditPolicyIssue, AuditTarget, ResolvedAuditPolicy
from webconf_audit.report import JsonFormatter, ReportData, TextFormatter, deduplicate_findings
from webconf_audit.rule_registry import RuleCategory, RuleMeta, StandardReference, registry
from webconf_audit.suppressions import apply_suppressions, load_suppression_file

app = typer.Typer(help="Web server configuration security audit tool")
policy_app = typer.Typer(help="Validate and inspect explicit audit policy files.")


class OutputFormat(str, Enum):
    text = "text"
    json = "json"


class GroupBy(str, Enum):
    severity = "severity"
    standard = "standard"


class FailOnSeverity(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


_SEVERITY_RANK: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

_GROUPING_SEQUENCE_META_KEY = "grouping_sequence"


def _suppressions_option() -> str | None:
    return typer.Option(
        None,
        "--suppressions",
        help="Override the suppression YAML file path.",
    )


def _baseline_option() -> str | None:
    return typer.Option(
        None,
        "--baseline",
        help="Compare current findings against a baseline JSON file.",
    )


def _write_baseline_option() -> str | None:
    return typer.Option(
        None,
        "--write-baseline",
        help="Write the current active findings as a baseline JSON file.",
    )


def _fail_on_new_option() -> FailOnSeverity | None:
    return typer.Option(
        None,
        "--fail-on-new",
        help="Exit 2 when new findings at or above this severity exist.",
    )


def _group_by_option() -> GroupBy:
    return typer.Option(
        GroupBy.severity,
        "--group-by",
        help="Text report grouping: severity or standard.",
        callback=_record_group_by_option,
    )


def _group_repeated_option() -> bool:
    return typer.Option(
        False,
        "--group-repeated/--no-group-repeated",
        help="Group repeated findings in text reports while preserving each location.",
        callback=_record_group_repeated_option,
    )


def _enable_policy_review_option() -> bool:
    return typer.Option(
        False,
        "--enable-policy-review/--no-enable-policy-review",
        help=(
            "Include opt-in rules tagged 'policy-review'. These surface "
            "configuration choices that require manual operator judgment "
            "(e.g. log format selection, rate-limit value review, CSP "
            "policy review) and are excluded by default to avoid noise. "
            "All such findings are severity 'info' and do not affect "
            "--fail-on at higher thresholds."
        ),
    )


def _policy_option() -> str | None:
    return typer.Option(
        None,
        "--policy",
        help="Apply an explicit audit policy YAML file.",
    )


def _group_by_cause_option() -> bool:
    return typer.Option(
        False,
        "--group-by-cause",
        help="Group findings by shared effective cause in text and JSON reports.",
        callback=_record_group_by_cause_option,
    )


def _output_result(
    result: AnalysisResult,
    fmt: OutputFormat = OutputFormat.text,
    fail_on: FailOnSeverity | None = None,
    suppressions_path: str | None = None,
    baseline_path: str | None = None,
    write_baseline_path: str | None = None,
    fail_on_new: FailOnSeverity | None = None,
    group_by: GroupBy = GroupBy.severity,
    group_repeated: bool = False,
    group_by_cause: bool = False,
    grouping_sequence: list[str] | None = None,
) -> None:
    _ensure_all_rules_loaded()
    if group_by is None:
        group_by = GroupBy.severity
    if grouping_sequence is None:
        ctx = click.get_current_context(silent=True)
        grouping_sequence = list(_grouping_sequence(ctx)) if ctx is not None else []
    group_by, group_repeated, group_by_cause = _resolve_grouping_options(
        group_by=group_by,
        group_repeated=group_repeated,
        group_by_cause=group_by_cause,
        grouping_sequence=grouping_sequence or [],
    )
    suppression_load_failed = _apply_suppressions(
        result,
        suppressions_path,
        load_default=fail_on is not None or fail_on_new is not None,
    )
    report = ReportData(results=[result])
    baseline_operation_failed = _apply_baseline(report, result, baseline_path, fail_on_new)
    if write_baseline_path is not None:
        issue = write_baseline_file(report, write_baseline_path)
        if issue is not None:
            result.issues.append(issue)
            baseline_operation_failed = True
    formatter = (
        TextFormatter(
            group_by=group_by.value,
            group_repeated=group_repeated,
            group_by_cause=group_by_cause,
        )
        if fmt == OutputFormat.text
        else JsonFormatter(group_by_cause=group_by_cause)
    )
    typer.echo(formatter.format(report))
    exit_code = _ci_exit_code(
        result,
        fail_on,
        fail_on_new,
        report,
        explicit_suppression_error=suppressions_path is not None and suppression_load_failed,
        explicit_baseline_error=baseline_operation_failed,
    )
    if exit_code:
        raise typer.Exit(exit_code)


def _output_fatal_result(
    result: AnalysisResult,
    *,
    fmt: OutputFormat,
    group_by: GroupBy,
    group_repeated: bool,
    group_by_cause: bool,
    grouping_sequence: list[str] | None = None,
) -> None:
    if group_by is None:
        group_by = GroupBy.severity
    if grouping_sequence is None:
        ctx = click.get_current_context(silent=True)
        grouping_sequence = list(_grouping_sequence(ctx)) if ctx is not None else []
    group_by, group_repeated, group_by_cause = _resolve_grouping_options(
        group_by=group_by,
        group_repeated=group_repeated,
        group_by_cause=group_by_cause,
        grouping_sequence=grouping_sequence or [],
    )
    formatter = (
        TextFormatter(
            group_by=group_by.value,
            group_repeated=group_repeated,
            group_by_cause=group_by_cause,
        )
        if fmt == OutputFormat.text
        else JsonFormatter(group_by_cause=group_by_cause)
    )
    typer.echo(formatter.format(ReportData(results=[result])))
    raise typer.Exit(1)


def _apply_suppressions(
    result: AnalysisResult,
    suppressions_path: str | None,
    *,
    load_default: bool,
) -> bool:
    suppression_set = load_suppression_file(suppressions_path, load_default=load_default)
    result.issues.extend(suppression_set.issues)
    apply_suppressions(result, suppression_set)
    return any(
        issue.level == "error" and issue.code.startswith("suppression_")
        for issue in suppression_set.issues
    )


def _record_group_by_option(
    ctx: click.Context,
    _param: click.Parameter,
    value: GroupBy,
) -> GroupBy:
    if value == GroupBy.standard:
        _grouping_sequence(ctx).append("standard")
    return value


def _record_group_repeated_option(
    ctx: click.Context,
    _param: click.Parameter,
    value: bool,
) -> bool:
    if value:
        _grouping_sequence(ctx).append("repeated")
    return value


def _record_group_by_cause_option(
    ctx: click.Context,
    _param: click.Parameter,
    value: bool,
) -> bool:
    if value:
        _grouping_sequence(ctx).append("cause")
    return value


def _grouping_sequence(ctx: click.Context) -> list[str]:
    sequence = ctx.meta.get(_GROUPING_SEQUENCE_META_KEY)
    if not isinstance(sequence, list):
        sequence = []
        ctx.meta[_GROUPING_SEQUENCE_META_KEY] = sequence
    return sequence


def _resolve_grouping_options(
    *,
    group_by: GroupBy,
    group_repeated: bool,
    group_by_cause: bool,
    grouping_sequence: list[str],
) -> tuple[GroupBy, bool, bool]:
    if len(grouping_sequence) > 1:
        typer.echo(
            (
                "Warning: --group-by standard, --group-repeated, and "
                "--group-by-cause are mutually exclusive; using the last one "
                "provided."
            ),
            err=True,
        )

    if not grouping_sequence:
        return group_by, group_repeated, group_by_cause

    winner = grouping_sequence[-1]
    if winner == "standard":
        return GroupBy.standard, False, False
    if winner == "repeated":
        return GroupBy.severity, True, False
    if winner == "cause":
        return GroupBy.severity, False, True
    return group_by, group_repeated, group_by_cause


def _ci_exit_code(
    result: AnalysisResult,
    fail_on: FailOnSeverity | None,
    fail_on_new: FailOnSeverity | None,
    report: ReportData,
    *,
    explicit_suppression_error: bool = False,
    explicit_baseline_error: bool = False,
) -> int:
    if explicit_suppression_error or explicit_baseline_error:
        return 1
    if fail_on is None and fail_on_new is None:
        return 0
    if any(issue.level == "error" for issue in result.issues):
        return 1
    if _has_blocking_current_findings(result, fail_on):
        return 2
    if _has_blocking_new_findings(report, fail_on_new):
        return 2
    return 0


def _apply_baseline(
    report: ReportData,
    result: AnalysisResult,
    baseline_path: str | None,
    fail_on_new: FailOnSeverity | None,
) -> bool:
    if baseline_path is None:
        if fail_on_new is None:
            return False
        result.issues.append(
            AnalysisIssue(
                code="baseline_required",
                level="error",
                message="--fail-on-new requires --baseline.",
                location=SourceLocation(mode="local", kind="check", details="baseline"),
            )
        )
        return True

    load_result = load_baseline_file(baseline_path)
    result.issues.extend(load_result.issues)
    if load_result.baseline is not None:
        apply_baseline_diff(report, load_result.baseline)
    return load_result.failed


def _has_blocking_current_findings(
    result: AnalysisResult,
    fail_on: FailOnSeverity | None,
) -> bool:
    if fail_on is None:
        return False
    threshold = _SEVERITY_RANK[fail_on.value]
    deduplicated, _ = deduplicate_findings(result.findings)
    return any(_SEVERITY_RANK[finding.severity] >= threshold for finding in deduplicated)


def _has_blocking_new_findings(
    report: ReportData,
    fail_on_new: FailOnSeverity | None,
) -> bool:
    if fail_on_new is None:
        return False
    baseline_diff = report.baseline_diff
    if baseline_diff is None:
        return False
    threshold = _SEVERITY_RANK[fail_on_new.value]
    new_findings = baseline_diff.get("new_findings")
    if not isinstance(new_findings, list):
        return False
    return any(
        isinstance(entry, dict)
        and isinstance(entry.get("severity"), str)
        and _SEVERITY_RANK.get(entry["severity"], -1) >= threshold
        for entry in new_findings
    )


def _parse_assessment_fail_on(raw: str | None) -> frozenset[str]:
    if raw is None:
        return frozenset()
    statuses = {
        token.strip()
        for token in raw.split(",")
        if token.strip()
    }
    valid = {
        "pass",
        "fail",
        "partial",
        "review",
        "indeterminate",
        "not-assessed",
        "not-applicable",
    }
    invalid = sorted(statuses - valid)
    if invalid:
        raise typer.BadParameter(
            "invalid_fail_on_status: "
            + ", ".join(invalid)
            + f"; expected one of: {', '.join(sorted(valid))}"
        )
    return frozenset(statuses)


def _assessment_gate_triggered(
    assessment: ControlAssessmentReport,
    gate_statuses: frozenset[str],
) -> bool:
    return any(
        control.status in gate_statuses
        for source in assessment.sources
        for control in source.controls
    )


def _filter_assessment_sources(
    assessment: ControlAssessmentReport,
    source_ids: tuple[str, ...],
) -> tuple[ControlAssessmentReport, AssessmentIssue | None]:
    filtered_sources = tuple(
        source
        for source in assessment.sources
        if source.source_id in set(source_ids)
    )
    missing = sorted(set(source_ids) - {source.source_id for source in assessment.sources})
    if missing:
        return assessment, AssessmentIssue(
            code="unknown_source_filter",
            severity="error",
            message=f"Unknown assessment source filter(s): {', '.join(missing)}",
        )
    return assessment.model_copy(update={"sources": filtered_sources}), None


def _emit_assessment_failure(
    output_format: OutputFormat,
    issues: tuple[AssessmentIssue, ...],
) -> None:
    if output_format == OutputFormat.json:
        typer.echo(_assessment_error_envelope(issues), nl=False)
        return
    for issue in issues:
        typer.echo(f"{issue.code}: {issue.message}", err=True)


def _assessment_error_envelope(issues: tuple[AssessmentIssue, ...]) -> str:
    payload = {
        "schema_version": 1,
        "assessment": None,
        "issues": [_assessment_issue_payload(issue) for issue in issues],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n"


def _assessment_issue_payload(issue: AssessmentIssue) -> dict[str, object]:
    return {
        "code": issue.code,
        "severity": issue.severity,
        "message": issue.message,
        "source_id": issue.source_id,
        "item_id": issue.item_id,
        "rule_id": issue.rule_id,
        "target_id": issue.target_id,
    }


def _policy_issue_payload(issue: AuditPolicyIssue) -> dict[str, object]:
    return {
        "code": issue.code,
        "message": issue.message,
        "profile_id": issue.profile_id,
        "source_id": issue.source_id,
        "item_id": issue.item_id,
        "rule_id": issue.rule_id,
        "path": issue.path,
    }


def _policy_issue_to_analysis_issue(
    issue: AuditPolicyIssue,
    *,
    mode: str,
) -> AnalysisIssue:
    location = SourceLocation(mode=mode, kind="check", details="audit_policy")
    if issue.path is not None:
        location.file_path = issue.path
    details_parts = [
        f"profile_id={issue.profile_id}" if issue.profile_id is not None else None,
        f"source_id={issue.source_id}" if issue.source_id is not None else None,
        f"item_id={issue.item_id}" if issue.item_id is not None else None,
        f"rule_id={issue.rule_id}" if issue.rule_id is not None else None,
    ]
    details = ", ".join(part for part in details_parts if part is not None) or None
    return AnalysisIssue(
        code=issue.code,
        level="error",
        message=issue.message,
        details=details,
        location=location,
    )


def _fatal_policy_result(
    *,
    mode: str,
    target: str,
    server_type: str | None,
    issues: list[AuditPolicyIssue],
) -> AnalysisResult:
    return AnalysisResult(
        mode=mode,
        target=target,
        server_type=server_type,
        issues=[
            _policy_issue_to_analysis_issue(issue, mode=mode)
            for issue in issues
        ],
    )


def _load_validated_policy_or_exit(
    *,
    policy_path: str,
    mode: str,
    target: str,
    server_type: str | None,
    output_format: OutputFormat,
    group_by: GroupBy,
    group_repeated: bool,
    group_by_cause: bool,
) -> ResolvedAuditPolicy:
    try:
        policy = load_audit_policy(Path(policy_path))
    except AuditPolicyLoadError as exc:
        _output_fatal_result(
            _fatal_policy_result(
                mode=mode,
                target=target,
                server_type=server_type,
                issues=[exc.issue],
            ),
            fmt=output_format,
            group_by=group_by,
            group_repeated=group_repeated,
            group_by_cause=group_by_cause,
        )
        raise AssertionError("unreachable")

    ledger = load_coverage_ledger()
    _ensure_all_rules_loaded()
    validation_issues = list(validate_audit_policy(policy, ledger, registry))
    if validation_issues:
        _output_fatal_result(
            _fatal_policy_result(
                mode=mode,
                target=target,
                server_type=server_type,
                issues=validation_issues,
            ),
            fmt=output_format,
            group_by=group_by,
            group_repeated=group_repeated,
            group_by_cause=group_by_cause,
        )
        raise AssertionError("unreachable")

    try:
        return resolve_audit_policy(
            policy,
            AuditTarget(mode=mode, server_type=server_type, target=target),
            ledger,
        )
    except AuditPolicyResolveError as exc:
        _output_fatal_result(
            _fatal_policy_result(
                mode=mode,
                target=target,
                server_type=server_type,
                issues=[exc.issue],
            ),
            fmt=output_format,
            group_by=group_by,
            group_repeated=group_repeated,
            group_by_cause=group_by_cause,
        )
        raise AssertionError("unreachable")


@app.command("analyze-nginx")
def analyze_nginx(
    config_path: str = typer.Argument(..., help="Path to nginx config file"),
    policy: str | None = _policy_option(),
    output_format: OutputFormat = typer.Option(
        OutputFormat.text, "--format", "-f", help="Output format: text, json.",
    ),
    fail_on: FailOnSeverity | None = typer.Option(
        None,
        "--fail-on",
        help="Exit 2 when unsuppressed findings at or above this severity exist.",
    ),
    suppressions: str | None = _suppressions_option(),
    baseline: str | None = _baseline_option(),
    write_baseline: str | None = _write_baseline_option(),
    fail_on_new: FailOnSeverity | None = _fail_on_new_option(),
    group_by: GroupBy = _group_by_option(),
    group_repeated: bool = _group_repeated_option(),
    group_by_cause: bool = _group_by_cause_option(),
    enable_policy_review: bool = _enable_policy_review_option(),
) -> None:
    kwargs: dict[str, object] = {}
    if policy is not None:
        kwargs["policy"] = _load_validated_policy_or_exit(
            policy_path=policy,
            mode="local",
            target=config_path,
            server_type="nginx",
            output_format=output_format,
            group_by=group_by,
            group_repeated=group_repeated,
            group_by_cause=group_by_cause,
        )
    if enable_policy_review:
        kwargs["enable_policy_review"] = True
    result = analyze_nginx_config(config_path, **kwargs)
    _output_result(
        result,
        output_format,
        fail_on,
        suppressions,
        baseline,
        write_baseline,
        fail_on_new,
        group_by,
        group_repeated,
        group_by_cause,
    )


@app.command("analyze-apache")
def analyze_apache(
    config_path: str = typer.Argument(..., help="Path to Apache config file"),
    policy: str | None = _policy_option(),
    output_format: OutputFormat = typer.Option(
        OutputFormat.text, "--format", "-f", help="Output format: text, json.",
    ),
    fail_on: FailOnSeverity | None = typer.Option(
        None,
        "--fail-on",
        help="Exit 2 when unsuppressed findings at or above this severity exist.",
    ),
    suppressions: str | None = _suppressions_option(),
    baseline: str | None = _baseline_option(),
    write_baseline: str | None = _write_baseline_option(),
    fail_on_new: FailOnSeverity | None = _fail_on_new_option(),
    group_by: GroupBy = _group_by_option(),
    group_repeated: bool = _group_repeated_option(),
    group_by_cause: bool = _group_by_cause_option(),
    enable_policy_review: bool = _enable_policy_review_option(),
) -> None:
    kwargs: dict[str, object] = {}
    if policy is not None:
        kwargs["policy"] = _load_validated_policy_or_exit(
            policy_path=policy,
            mode="local",
            target=config_path,
            server_type="apache",
            output_format=output_format,
            group_by=group_by,
            group_repeated=group_repeated,
            group_by_cause=group_by_cause,
        )
    if enable_policy_review:
        kwargs["enable_policy_review"] = True
    result = analyze_apache_config(config_path, **kwargs)
    _output_result(
        result,
        output_format,
        fail_on,
        suppressions,
        baseline,
        write_baseline,
        fail_on_new,
        group_by,
        group_repeated,
        group_by_cause,
    )


@app.command("analyze-lighttpd")
def analyze_lighttpd(
    config_path: str = typer.Argument(..., help="Path to Lighttpd config file"),
    execute_shell: bool = typer.Option(
        False,
        "--execute-shell/--no-execute-shell",
        help="Execute include_shell directives during analysis.",
    ),
    host: str | None = typer.Option(
        None,
        "--host",
        help="Evaluate conditional blocks for a specific host (targeted analysis).",
    ),
    policy: str | None = _policy_option(),
    output_format: OutputFormat = typer.Option(
        OutputFormat.text, "--format", "-f", help="Output format: text, json.",
    ),
    fail_on: FailOnSeverity | None = typer.Option(
        None,
        "--fail-on",
        help="Exit 2 when unsuppressed findings at or above this severity exist.",
    ),
    suppressions: str | None = _suppressions_option(),
    baseline: str | None = _baseline_option(),
    write_baseline: str | None = _write_baseline_option(),
    fail_on_new: FailOnSeverity | None = _fail_on_new_option(),
    group_by: GroupBy = _group_by_option(),
    group_repeated: bool = _group_repeated_option(),
    group_by_cause: bool = _group_by_cause_option(),
    enable_policy_review: bool = _enable_policy_review_option(),
) -> None:
    extra_kwargs: dict[str, object] = {}
    if policy is not None:
        extra_kwargs["policy"] = _load_validated_policy_or_exit(
            policy_path=policy,
            mode="local",
            target=config_path,
            server_type="lighttpd",
            output_format=output_format,
            group_by=group_by,
            group_repeated=group_repeated,
            group_by_cause=group_by_cause,
        )
    if enable_policy_review:
        extra_kwargs["enable_policy_review"] = True
    result = analyze_lighttpd_config(
        config_path, execute_shell=execute_shell, host=host, **extra_kwargs,
    )
    _output_result(
        result,
        output_format,
        fail_on,
        suppressions,
        baseline,
        write_baseline,
        fail_on_new,
        group_by,
        group_repeated,
        group_by_cause,
    )


@app.command("analyze-iis")
def analyze_iis(
    config_path: str = typer.Argument(
        ...,
        help="Path to IIS config file (web.config or applicationHost.config)",
    ),
    machine_config: str | None = typer.Option(
        None,
        "--machine-config",
        help="Optional path to machine.config for IIS inheritance analysis.",
    ),
    tls_registry: str | None = typer.Option(
        None,
        "--tls-registry",
        help="Optional JSON export of Windows SChannel TLS registry settings.",
    ),
    no_tls_registry: bool = typer.Option(
        False,
        "--no-tls-registry",
        help="Disable automatic local SChannel registry enrichment on Windows.",
    ),
    policy: str | None = _policy_option(),
    output_format: OutputFormat = typer.Option(
        OutputFormat.text, "--format", "-f", help="Output format: text, json.",
    ),
    fail_on: FailOnSeverity | None = typer.Option(
        None,
        "--fail-on",
        help="Exit 2 when unsuppressed findings at or above this severity exist.",
    ),
    suppressions: str | None = _suppressions_option(),
    baseline: str | None = _baseline_option(),
    write_baseline: str | None = _write_baseline_option(),
    fail_on_new: FailOnSeverity | None = _fail_on_new_option(),
    group_by: GroupBy = _group_by_option(),
    group_repeated: bool = _group_repeated_option(),
    group_by_cause: bool = _group_by_cause_option(),
    enable_policy_review: bool = _enable_policy_review_option(),
) -> None:
    kwargs: dict[str, object] = {}
    if policy is not None:
        kwargs["policy"] = _load_validated_policy_or_exit(
            policy_path=policy,
            mode="local",
            target=config_path,
            server_type="iis",
            output_format=output_format,
            group_by=group_by,
            group_repeated=group_repeated,
            group_by_cause=group_by_cause,
        )
    if machine_config is not None:
        kwargs["machine_config_path"] = machine_config
    if tls_registry is not None:
        kwargs["tls_registry_path"] = tls_registry
    if no_tls_registry:
        kwargs["use_tls_registry"] = False

    if enable_policy_review:
        kwargs["enable_policy_review"] = True
    result = analyze_iis_config(config_path, **kwargs)
    _output_result(
        result,
        output_format,
        fail_on,
        suppressions,
        baseline,
        write_baseline,
        fail_on_new,
        group_by,
        group_repeated,
        group_by_cause,
    )


def _parse_ports(raw: str) -> tuple[int, ...]:
    """Parse a comma-separated port string with validation.

    Raises :class:`typer.BadParameter` on invalid tokens, out-of-range
    values (must be 1-65535), or an empty result.
    """
    seen: set[int] = set()
    result: list[int] = []
    for idx, token in enumerate(raw.split(",")):
        token = token.strip()
        if not token:
            raise typer.BadParameter(
                f"empty port value at position {idx + 1} in: {raw!r}"
            )
        try:
            port = int(token)
        except ValueError:
            raise typer.BadParameter(f"invalid port value: {token!r}") from None
        if port < 1 or port > 65535:
            raise typer.BadParameter(
                f"port out of range (1-65535): {port}"
            )
        if port not in seen:
            seen.add(port)
            result.append(port)
    if not result:
        raise typer.BadParameter("--ports requires at least one valid port")
    return tuple(result)


@app.command("analyze-external")
def analyze_external(
    target: str = typer.Argument(..., help="URL, host, or host:port to probe"),
    scan_ports: bool = typer.Option(
        True,
        "--scan-ports/--no-scan-ports",
        help="Enable or disable port discovery for bare-host targets.",
    ),
    ports: str | None = typer.Option(
        None,
        "--ports",
        help="Comma-separated list of ports to scan (e.g. '80,443,8080').",
    ),
    policy: str | None = _policy_option(),
    output_format: OutputFormat = typer.Option(
        OutputFormat.text, "--format", "-f", help="Output format: text, json.",
    ),
    fail_on: FailOnSeverity | None = typer.Option(
        None,
        "--fail-on",
        help="Exit 2 when unsuppressed findings at or above this severity exist.",
    ),
    suppressions: str | None = _suppressions_option(),
    baseline: str | None = _baseline_option(),
    write_baseline: str | None = _write_baseline_option(),
    fail_on_new: FailOnSeverity | None = _fail_on_new_option(),
    group_by: GroupBy = _group_by_option(),
    group_repeated: bool = _group_repeated_option(),
    group_by_cause: bool = _group_by_cause_option(),
) -> None:
    parsed_ports: tuple[int, ...] | None = None
    if ports is not None:
        parsed_ports = _parse_ports(ports)
    kwargs: dict[str, object] = {}
    if policy is not None:
        kwargs["policy"] = _load_validated_policy_or_exit(
            policy_path=policy,
            mode="external",
            target=target,
            server_type=None,
            output_format=output_format,
            group_by=group_by,
            group_repeated=group_repeated,
            group_by_cause=group_by_cause,
        )
    result = analyze_external_target(
        target,
        scan_ports=scan_ports,
        ports=parsed_ports,
        **kwargs,
    )
    _output_result(
        result,
        output_format,
        fail_on,
        suppressions,
        baseline,
        write_baseline,
        fail_on_new,
        group_by,
        group_repeated,
        group_by_cause,
    )


@app.command("analyze-tls-inventory")
def analyze_tls_inventory(
    inventory_id: str = typer.Argument(
        ...,
        help="Declared TLS inventory id from the audit policy.",
    ),
    policy: str = typer.Option(
        ...,
        "--policy",
        help="Apply an explicit audit policy YAML file.",
    ),
    output_format: OutputFormat = typer.Option(
        OutputFormat.text, "--format", "-f", help="Output format: text, json.",
    ),
    fail_on: FailOnSeverity | None = typer.Option(
        None,
        "--fail-on",
        help="Exit 2 when unsuppressed findings at or above this severity exist.",
    ),
    suppressions: str | None = _suppressions_option(),
    baseline: str | None = _baseline_option(),
    write_baseline: str | None = _write_baseline_option(),
    fail_on_new: FailOnSeverity | None = _fail_on_new_option(),
    group_by: GroupBy = _group_by_option(),
    group_repeated: bool = _group_repeated_option(),
    group_by_cause: bool = _group_by_cause_option(),
) -> None:
    result = analyze_external_tls_inventory(policy, inventory_id)
    if any(issue.level == "error" for issue in result.issues):
        _output_fatal_result(
            result,
            fmt=output_format,
            group_by=group_by,
            group_repeated=group_repeated,
            group_by_cause=group_by_cause,
        )
    _output_result(
        result,
        output_format,
        fail_on,
        suppressions,
        baseline,
        write_baseline,
        fail_on_new,
        group_by,
        group_repeated,
        group_by_cause,
    )


@app.command("assess")
def assess_command(
    report: Path = typer.Option(
        ...,
        "--report",
        help="Path to the versioned analysis JSON report.",
    ),
    ledger: Path | None = typer.Option(
        None,
        "--ledger",
        help="Optional local coverage ledger path.",
    ),
    policy: Path | None = typer.Option(
        None,
        "--policy",
        help="Optional verification-only audit policy path.",
    ),
    source: list[str] | None = typer.Option(
        None,
        "--source",
        help="Repeatable source filter for rendered output only.",
    ),
    output_format: OutputFormat = typer.Option(
        OutputFormat.text,
        "--format",
        "-f",
        help="Output format: text, json.",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Write the assessment artifact to a file instead of stdout.",
    ),
    fail_on: str | None = typer.Option(
        None,
        "--fail-on",
        help="Comma-separated assessment statuses that trigger exit code 3.",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Atomically replace an existing regular output file.",
    ),
) -> None:
    gate_statuses = _parse_assessment_fail_on(fail_on)
    _ensure_all_rules_loaded()

    try:
        loaded_report = load_analysis_report(report)
    except AnalysisReportLoadError as exc:
        _emit_assessment_failure(output_format, (exc.issue,))
        raise typer.Exit(1)

    try:
        loaded_ledger = load_coverage_ledger(ledger)
    except CoverageLedgerLoadError as exc:
        issue = AssessmentIssue(
            code="ledger_validation_failed",
            severity="error",
            message=f"{exc.issue.code}: {exc.issue.message}",
        )
        _emit_assessment_failure(output_format, (issue,))
        raise typer.Exit(1)

    verification_policy = None
    if policy is not None:
        try:
            verification_policy = load_audit_policy(policy)
        except AuditPolicyLoadError as exc:
            _emit_assessment_failure(
                output_format,
                (
                    AssessmentIssue(
                        code="policy_verification_mismatch",
                        severity="error",
                        message=f"{exc.issue.code}: {exc.issue.message}",
                    ),
                ),
            )
            raise typer.Exit(1)
        validation_issues = validate_audit_policy(verification_policy, loaded_ledger, registry)
        if validation_issues:
            _emit_assessment_failure(
                output_format,
                tuple(
                    AssessmentIssue(
                        code="policy_verification_mismatch",
                        severity="error",
                        message=f"{issue.code}: {issue.message}",
                        source_id=issue.source_id,
                        item_id=issue.item_id,
                        rule_id=issue.rule_id,
                    )
                    for issue in validation_issues
                ),
            )
            raise typer.Exit(1)

    verification_issues = verify_assessment_inputs(
        loaded_report,
        loaded_ledger,
        registry,
        verification_policy=verification_policy,
    )
    fatal_issues = tuple(issue for issue in verification_issues if issue.severity == "error")
    if fatal_issues:
        _emit_assessment_failure(output_format, fatal_issues)
        raise typer.Exit(1)

    try:
        assessment = build_control_assessment(loaded_report, loaded_ledger, registry)
    except AssessmentBuildError as exc:
        _emit_assessment_failure(output_format, exc.issues)
        raise typer.Exit(1)

    filtered = assessment
    if source:
        filtered, source_issue = _filter_assessment_sources(assessment, tuple(source))
        if source_issue is not None:
            _emit_assessment_failure(output_format, (source_issue,))
            raise typer.Exit(1)

    content = (
        render_assessment_json(filtered)
        if output_format == OutputFormat.json
        else render_assessment_text(filtered)
    )
    if output is None:
        typer.echo(content, nl=False)
    else:
        write_issue = write_coverage_output(output, content, force=force)
        if write_issue is not None:
            _emit_assessment_failure(
                output_format,
                (
                    AssessmentIssue(
                        code=write_issue.code,
                        severity="error",
                        message=write_issue.message,
                    ),
                ),
            )
            raise typer.Exit(1)
        typer.echo(f"Wrote assessment artifact to {output}.")

    if gate_statuses and _assessment_gate_triggered(assessment, gate_statuses):
        raise typer.Exit(3)


@policy_app.command("validate")
def validate_policy_command(
    policy: str = typer.Option(..., "--policy", help="Path to the audit policy YAML file."),
    output_format: OutputFormat = typer.Option(
        OutputFormat.text,
        "--format",
        "-f",
        help="Output format: text, json.",
    ),
) -> None:
    issues: list[AuditPolicyIssue] = []
    try:
        loaded_policy = load_audit_policy(Path(policy))
    except AuditPolicyLoadError as exc:
        issues.append(exc.issue)
        loaded_policy = None

    if loaded_policy is not None:
        ledger = load_coverage_ledger()
        _ensure_all_rules_loaded()
        issues.extend(validate_audit_policy(loaded_policy, ledger, registry))

    payload = {
        "schema_version": 1,
        "policy": policy,
        "valid": not issues,
        "issues": [_policy_issue_payload(issue) for issue in issues],
    }
    if output_format == OutputFormat.json:
        typer.echo(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        typer.echo(f"Policy: {policy}")
        typer.echo("Valid: yes" if not issues else "Valid: no")
        for issue in issues:
            typer.echo(f"- {issue.code}: {issue.message}")
    raise typer.Exit(0 if not issues else 1)


@policy_app.command("show")
def show_policy_command(
    policy: str = typer.Option(..., "--policy", help="Path to the audit policy YAML file."),
    mode: str | None = typer.Option(
        None,
        "--mode",
        help="Optional analysis mode for resolution: local or external.",
    ),
    server_type: str | None = typer.Option(
        None,
        "--server-type",
        help="Server type for local target resolution.",
    ),
    target: str | None = typer.Option(
        None,
        "--target",
        help="Target path or URL used for profile resolution.",
    ),
    output_format: OutputFormat = typer.Option(
        OutputFormat.text,
        "--format",
        "-f",
        help="Output format: text, json.",
    ),
) -> None:
    try:
        loaded_policy = load_audit_policy(Path(policy))
    except AuditPolicyLoadError as exc:
        payload = {
            "schema_version": 1,
            "policy": {"path": policy},
            "resolved": None,
            "issues": [_policy_issue_payload(exc.issue)],
        }
        if output_format == OutputFormat.json:
            typer.echo(json.dumps(payload, indent=2, ensure_ascii=False))
        else:
            typer.echo(f"{exc.issue.code}: {exc.issue.message}")
        raise typer.Exit(1)

    ledger = load_coverage_ledger()
    _ensure_all_rules_loaded()
    validation_issues = list(validate_audit_policy(loaded_policy, ledger, registry))
    if validation_issues:
        payload = {
            "schema_version": 1,
            "policy": loaded_policy.model_dump(
                mode="json",
                exclude={"loaded_provenance"},
            ),
            "resolved": None,
            "issues": [_policy_issue_payload(issue) for issue in validation_issues],
        }
        if output_format == OutputFormat.json:
            typer.echo(json.dumps(payload, indent=2, ensure_ascii=False))
        else:
            for issue in validation_issues:
                typer.echo(f"{issue.code}: {issue.message}")
        raise typer.Exit(1)

    resolved = None
    if any(value is not None for value in (mode, server_type, target)):
        if mode is None or target is None:
            raise typer.BadParameter(
                "--mode and --target must be supplied together for policy resolution."
            )
        if mode not in {"local", "external"}:
            raise typer.BadParameter("--mode must be 'local' or 'external'.")
        if mode == "local" and server_type is None:
            raise typer.BadParameter("--server-type is required when --mode local is used.")
        if mode == "external" and server_type not in {None, "generic"}:
            raise typer.BadParameter(
                "--server-type may be omitted or set to 'generic' for --mode external."
            )
        normalized_server_type = (
            None if mode == "external" and server_type == "generic" else server_type
        )
        try:
            resolved = resolve_audit_policy(
                loaded_policy,
                AuditTarget(
                    mode=mode,
                    server_type=normalized_server_type,
                    target=target,
                ),
                ledger,
            )
        except AuditPolicyResolveError as exc:
            payload = {
                "schema_version": 1,
                "policy": loaded_policy.model_dump(
                    mode="json",
                    exclude={"loaded_provenance"},
                ),
                "resolved": None,
                "issues": [_policy_issue_payload(exc.issue)],
            }
            if output_format == OutputFormat.json:
                typer.echo(json.dumps(payload, indent=2, ensure_ascii=False))
            else:
                typer.echo(f"{exc.issue.code}: {exc.issue.message}")
            raise typer.Exit(1)

    payload = {
        "schema_version": 1,
        "policy": loaded_policy.model_dump(mode="json", exclude={"loaded_provenance"}),
        "resolved": (
            resolved.model_dump(mode="json")
            if resolved is not None
            else None
        ),
        "issues": [],
    }
    if output_format == OutputFormat.json:
        typer.echo(json.dumps(payload, indent=2, ensure_ascii=False))
        return

    typer.echo(f"Policy ID: {loaded_policy.policy_id}")
    typer.echo(f"Policy Version: {loaded_policy.policy_version}")
    typer.echo(f"Profiles: {len(loaded_policy.profiles)}")
    for profile in loaded_policy.profiles:
        typer.echo(f"- {profile.profile_id}: {profile.title}")
    if resolved is not None:
        typer.echo(f"Resolved Profile: {resolved.profile_id}")
        typer.echo(f"Raw SHA256: {resolved.raw_sha256}")
        typer.echo(f"Resolved SHA256: {resolved.resolved_sha256}")


@app.command("list-rules")
def list_rules(
    category: str | None = typer.Option(
        None,
        "--category",
        "-c",
        help="Filter by category (local, external, universal).",
    ),
    server_type: str | None = typer.Option(
        None,
        "--server-type",
        "-s",
        help="Filter by server type (nginx, apache, lighttpd, iis).",
    ),
    severity: str | None = typer.Option(
        None,
        "--severity",
        help="Filter by severity (critical, high, medium, low, info).",
    ),
    tag: str | None = typer.Option(None, "--tag", "-t", help="Filter by tag (e.g. tls, headers)."),
    fmt: OutputFormat = typer.Option(
        OutputFormat.text,
        "--format",
        "-f",
        help="Output format: text, json.",
    ),
) -> None:
    """List all registered audit rules with optional filtering."""
    from webconf_audit.rule_registry import registry

    _ensure_all_rules_loaded()
    parsed_category = _parse_rule_category(category)
    parsed_server_type = _parse_rule_server_type(server_type)
    parsed_severity = _parse_rule_severity(severity)
    parsed_tag = _parse_rule_tag(tag)

    rules = registry.list_rules(
        category=parsed_category,
        server_type=parsed_server_type,
        severity=parsed_severity,
        tag=parsed_tag,
    )

    if fmt == OutputFormat.json:
        typer.echo(json.dumps([_rule_meta_payload(m) for m in rules], indent=2, ensure_ascii=False))
        return

    if not rules:
        typer.echo("No rules match the given filters.")
        raise typer.Exit()

    typer.echo(f"{'RULE ID':<55} {'SEV':<7} {'CAT':<10} {'SERVER':<10} ORDER")
    typer.echo("-" * 90)
    for m in rules:
        server = m.server_type or ""
        typer.echo(f"{m.rule_id:<55} {m.severity:<7} {m.category:<10} {server:<10} {m.order}")
    typer.echo(f"\nTotal: {len(rules)} rules")


def _rule_meta_payload(meta: RuleMeta) -> dict[str, object]:
    return {
        "rule_id": meta.rule_id,
        "title": meta.title,
        "severity": meta.severity,
        "description": meta.description,
        "recommendation": meta.recommendation,
        "category": meta.category,
        "server_type": meta.server_type,
        "input_kind": meta.input_kind,
        "tags": list(meta.tags),
        "severity_profile": (
            meta.severity_profile.as_payload()
            if meta.severity_profile is not None
            else None
        ),
        "standards": [_standard_reference_payload(ref) for ref in meta.standards],
        "standards_secondary": [
            _standard_reference_payload(ref)
            for ref in meta.standards_secondary
        ],
        "condition": meta.condition,
        "order": meta.order,
    }


def _standard_reference_payload(ref: StandardReference) -> dict[str, object]:
    payload: dict[str, object] = {
        "standard": ref.standard,
        "reference": ref.reference,
        "coverage": ref.coverage,
        "origin": ref.origin,
        "derived_from": (
            {
                "standard": ref.derived_from_standard,
                "reference": ref.derived_from_reference,
            }
            if ref.origin == "derived"
            else None
        ),
    }
    if ref.url is not None:
        payload["url"] = ref.url
    if ref.note is not None:
        payload["note"] = ref.note
    return payload


def _parse_rule_category(value: str | None) -> RuleCategory | None:
    if value is None:
        return None
    normalized = value.strip().lower()
    valid = {"local", "external", "universal"}
    if normalized not in valid:
        raise typer.BadParameter(
            f"invalid category {value!r}; expected one of: {', '.join(sorted(valid))}"
        )
    return cast(RuleCategory, normalized)


def _parse_rule_severity(value: str | None) -> Severity | None:
    if value is None:
        return None
    normalized = value.strip().lower()
    valid = {"critical", "high", "medium", "low", "info"}
    if normalized not in valid:
        raise typer.BadParameter(
            f"invalid severity {value!r}; expected one of: {', '.join(sorted(valid))}"
        )
    return cast(Severity, normalized)


def _parse_rule_server_type(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip().lower()
    valid = _available_rule_server_types()
    if normalized not in valid:
        raise typer.BadParameter(
            f"invalid server type {value!r}; expected one of: {', '.join(sorted(valid))}"
        )
    return normalized


def _parse_rule_tag(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip().lower()
    valid = _available_rule_tags()
    if normalized not in valid:
        raise typer.BadParameter(
            f"invalid tag {value!r}; expected one of: {', '.join(sorted(valid))}"
        )
    return normalized


def _available_rule_server_types() -> set[str]:
    from webconf_audit.rule_registry import registry

    return {
        meta.server_type
        for meta in registry.list_rules()
        if meta.server_type is not None
    }


def _available_rule_tags() -> set[str]:
    from webconf_audit.rule_registry import registry

    return {
        tag
        for meta in registry.list_rules()
        for tag in meta.tags
    }


def _ensure_all_rules_loaded() -> None:
    """Load all rule packages + meta-only registrations into the registry."""
    from webconf_audit.rule_registry import registry
    from webconf_audit.external.rules._runner import register_external_rule_metas

    registry.ensure_loaded("webconf_audit.local.rules.universal")
    registry.ensure_loaded("webconf_audit.local.nginx.rules")
    registry.ensure_loaded("webconf_audit.local.apache.rules")
    registry.ensure_loaded("webconf_audit.local.lighttpd.rules")
    registry.ensure_loaded("webconf_audit.local.iis.rules")
    registry.ensure_loaded("webconf_audit.external.rules")
    register_external_rule_metas()


def _register_coverage_commands() -> None:
    from webconf_audit.cli.coverage import coverage_app

    app.add_typer(coverage_app, name="coverage")


def _register_policy_commands() -> None:
    app.add_typer(policy_app, name="policy")


_register_coverage_commands()
_register_policy_commands()


if __name__ == "__main__":
    app()
