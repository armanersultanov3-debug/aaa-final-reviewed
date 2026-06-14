import os
from pathlib import Path

from webconf_audit.audit_policy import (
    attach_audit_context,
    build_analysis_manifest,
    requested_opt_in_tags,
)
from webconf_audit.execution_manifest import RuleExecutionRecorder
from webconf_audit.local.load_context import LoadContext
from webconf_audit.local.nginx.assessments.logging import evaluate_logging_policy
from webconf_audit.local.nginx.assessments.rate_limits import evaluate_rate_limit_policy
from webconf_audit.local.nginx.assessments.reverse_proxy_headers import (
    evaluate_reverse_proxy_header_policy,
)
from webconf_audit.local.nginx.assessments.sensitive_locations import (
    evaluate_sensitive_location_policy,
)
from webconf_audit.local.nginx.effective_scope import build_scope_graph
from webconf_audit.local.nginx.include import resolve_includes
from webconf_audit.local.nginx.parser.parser import NginxParseError, NginxParser, NginxTokenizer
from webconf_audit.local.normalized import NormalizedConfig
from webconf_audit.local.nginx.rules_runner import run_nginx_rules
from webconf_audit.local.normalizers import normalize_config
from webconf_audit.local.universal_rules import run_universal_rules
from webconf_audit.models import (
    AnalysisIssue,
    AnalysisResult,
    Finding,
    PolicyControlAssessment,
    SourceLocation,
)
from webconf_audit.policy_models import ResolvedAuditPolicy
from webconf_audit.rule_registry import registry as rule_registry

_NGINX_SPECIFIC_UNIVERSAL_REPLACEMENTS = frozenset(
    {
        "universal.missing_x_frame_options",
        "universal.permissions_policy_unsafe",
        "universal.referrer_policy_unsafe",
        "universal.weak_tls_ciphers",
    }
)


def analyze_nginx_config(
    config_path: str | os.PathLike[str],
    *,
    enable_policy_review: bool = False,
    policy: ResolvedAuditPolicy | None = None,
) -> AnalysisResult:
    """Run the full Nginx local-analysis pipeline against ``config_path``.

    Resolves ``include`` directives, builds the effective AST, runs the
    Nginx-specific rule pack, then runs universal rules over the
    normalized view (filtered to drop Nginx-superseded universal
    duplicates). Read errors and parse errors are returned as
    :class:`AnalysisIssue` entries on the result instead of being
    raised.

    Set ``enable_policy_review=True`` to additionally include rules
    tagged ``policy-review`` (operator-judgment items surfaced via the
    ``--enable-policy-review`` CLI flag).
    """
    config_path_str = os.fspath(config_path)
    path = Path(config_path_str)
    effective_policy_review = (
        enable_policy_review
        or "policy-review" in requested_opt_in_tags(policy)
    )

    if not path.is_file():
        return _attach_context(
            AnalysisResult(
                mode="local",
                target=config_path_str,
                server_type="nginx",
                issues=[
                    AnalysisIssue(
                        code="config_not_found",
                        level="error",
                        message=f"Config file not found: {config_path_str}",
                        location=SourceLocation(
                            mode="local",
                            kind="file",
                            file_path=config_path_str,
                        ),
                    )
                ],
            ),
            policy=policy,
        )

    try:
        text = read_text_file(config_path_str)
    except (OSError, UnicodeDecodeError) as exc:
        return _attach_context(
            AnalysisResult(
                mode="local",
                target=config_path_str,
                server_type="nginx",
                issues=[
                    AnalysisIssue(
                        code="nginx_config_read_error",
                        level="error",
                        message=f"Cannot read config file: {exc}",
                        location=SourceLocation(
                            mode="local",
                            kind="file",
                            file_path=str(path),
                        ),
                    )
                ],
            ),
            policy=policy,
        )

    try:
        tokens = NginxTokenizer(text, file_path=str(path)).tokenize()
        ast = NginxParser(tokens).parse()
    except NginxParseError as exc:
        error_path = getattr(exc, "file_path", str(path))
        return _attach_context(
            AnalysisResult(
                mode="local",
                target=config_path_str,
                server_type="nginx",
                issues=[
                    AnalysisIssue(
                        code="nginx_parse_error",
                        level="error",
                        message=str(exc),
                        location=SourceLocation(
                            mode="local",
                            kind="file",
                            file_path=error_path,
                            line=getattr(exc, "line", None),
                        ),
                    )
                ],
            ),
            policy=policy,
        )

    load_ctx = LoadContext(root_file=str(path))
    issues = resolve_includes(ast, path, load_context=load_ctx)
    scope_graph = build_scope_graph(ast, issues=issues, root_file=str(path))
    recorder = RuleExecutionRecorder()
    findings = run_nginx_rules(
        ast,
        issues=issues,
        enable_policy_review=effective_policy_review,
        execution_recorder=recorder,
    )
    normalized = normalize_config("nginx", ast=ast)
    findings.extend(
        _universal_nginx_findings(
            normalized,
            issues,
            enable_policy_review=effective_policy_review,
            execution_recorder=recorder,
        )
    )
    logging_assessments = evaluate_logging_policy(
        ast,
        scope_graph=scope_graph,
        policy=policy.nginx.logging
        if policy is not None and policy.nginx is not None
        else None,
        findings=findings,
    )
    findings = _suppress_logging_policy_review_findings(findings, logging_assessments)
    sensitive_location_assessments = evaluate_sensitive_location_policy(
        ast,
        scope_graph=scope_graph,
        policy=policy.nginx.sensitive_locations
        if policy is not None and policy.nginx is not None
        else None,
        findings=findings,
    )
    rate_limit_assessments = evaluate_rate_limit_policy(
        ast,
        scope_graph=scope_graph,
        policy=policy.nginx.rate_limits
        if policy is not None and policy.nginx is not None
        else None,
        findings=findings,
    )
    findings = _suppress_rate_limit_policy_review_findings(findings, rate_limit_assessments)
    control_assessments = (
        logging_assessments
        + sensitive_location_assessments
        + rate_limit_assessments
        + evaluate_reverse_proxy_header_policy(
            ast,
            scope_graph=scope_graph,
            policy=policy.nginx.reverse_proxy_headers
            if policy is not None and policy.nginx is not None
            else None,
            findings=findings,
        )
    )

    return _attach_context(
        AnalysisResult(
            mode="local",
            target=config_path_str,
            server_type="nginx",
            findings=findings,
            issues=issues,
            metadata={"load_context": load_ctx.to_dict()},
            control_assessments=control_assessments,
        ),
        policy=policy,
        recorder=recorder,
    )


def read_text_file(path: str) -> str:
    file_path = Path(path)
    return file_path.read_text(encoding="utf-8")


def _universal_nginx_findings(
    normalized: NormalizedConfig,
    issues: list[AnalysisIssue],
    *,
    enable_policy_review: bool = False,
    execution_recorder: RuleExecutionRecorder | None = None,
) -> list[Finding]:
    return [
        finding
        for finding in run_universal_rules(
            normalized,
            issues=issues,
            enable_policy_review=enable_policy_review,
            execution_recorder=execution_recorder,
        )
        if finding.rule_id not in _NGINX_SPECIFIC_UNIVERSAL_REPLACEMENTS
    ]


def _attach_context(
    result: AnalysisResult,
    *,
    policy: ResolvedAuditPolicy | None,
    recorder: RuleExecutionRecorder | None = None,
) -> AnalysisResult:
    rule_registry.ensure_loaded("webconf_audit.local.nginx.rules")
    rule_registry.ensure_loaded("webconf_audit.local.rules.universal")
    manifest = build_analysis_manifest(
        recorder=recorder or RuleExecutionRecorder(),
        policy=policy,
        mode="local",
        server_type="nginx",
        registry=rule_registry,
    )
    return attach_audit_context(result, policy, manifest)


def _suppress_logging_policy_review_findings(
    findings: list[Finding],
    assessments: list[PolicyControlAssessment],
) -> list[Finding]:
    explicit_combined_sources = {
        (
            source.get("file_path"),
            source.get("line"),
        )
        for assessment in assessments
        if assessment.metadata.get("logging_kind") == "access"
        and assessment.metadata.get("profile_id") is not None
        for decision in assessment.metadata.get("evaluated_format_decisions", [])
        if decision.get("format_name") == "combined"
        and isinstance(decision.get("source"), dict)
        and (source := decision.get("source")) is not None
    }
    if not explicit_combined_sources:
        return findings
    return [
        finding
        for finding in findings
        if finding.rule_id != "nginx.access_log_uses_default_format"
        or finding.location is None
        or (finding.location.file_path, finding.location.line) not in explicit_combined_sources
    ]


def _suppress_rate_limit_policy_review_findings(
    findings: list[Finding],
    assessments: list[PolicyControlAssessment],
) -> list[Finding]:
    request_sources = {
        (
            source.get("file_path"),
            source.get("line"),
        )
        for assessment in assessments
        if assessment.control_id == "cis-nginx-5.2.5.requests-per-ip"
        for definition in assessment.metadata.get("request_zone_definitions", [])
        if isinstance(definition, dict)
        and isinstance(definition.get("source"), dict)
        and (source := definition.get("source")) is not None
    }
    connection_sources = {
        (
            source.get("file_path"),
            source.get("line"),
        )
        for assessment in assessments
        if assessment.control_id == "cis-nginx-5.2.4.connections-per-ip"
        for definition in assessment.metadata.get("connection_zone_definitions", [])
        if isinstance(definition, dict)
        and isinstance(definition.get("source"), dict)
        and (source := definition.get("source")) is not None
    }
    if not request_sources and not connection_sources:
        return findings
    return [
        finding
        for finding in findings
        if not (
            finding.location is not None
            and (
                (
                    finding.rule_id == "nginx.limit_req_zone_rate_review"
                    and (finding.location.file_path, finding.location.line) in request_sources
                )
                or (
                    finding.rule_id == "nginx.limit_conn_zone_review"
                    and (finding.location.file_path, finding.location.line) in connection_sources
                )
            )
        )
    ]
