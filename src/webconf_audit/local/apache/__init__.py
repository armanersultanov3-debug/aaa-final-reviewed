from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from webconf_audit.audit_policy import (
    AuditPolicyLoadError,
    AuditPolicyResolveError,
    attach_audit_context,
    build_analysis_manifest,
    load_audit_policy,
    requested_opt_in_tags,
    resolve_audit_policy,
    validate_audit_policy,
)
from webconf_audit.coverage_ledger import load_coverage_ledger
from webconf_audit.execution_manifest import RuleExecutionRecorder
from webconf_audit.local.apache.authorization import evaluate_root_authorization
from webconf_audit.local.apache.effective import (
    ApacheVirtualHostContext,
    EffectiveConfig,
    build_server_effective_config,
    extract_document_root,
    extract_virtualhost_contexts,
)
from webconf_audit.local.apache.htaccess import (
    HtaccessDiscoveryResult,
    HtaccessFile,
    discover_htaccess_files,
)
from webconf_audit.local.apache.include import resolve_includes
from webconf_audit.local.apache.parser import (
    ApacheConfigAst,
    ApacheParseError,
    ApacheParser,
    ApacheTokenizer,
)
from webconf_audit.local.apache.module_inventory import (
    ApacheModuleEvaluation,
    ApacheModuleSnapshot,
    ApacheModuleSnapshotLoadError,
    evaluate_apache_modules,
    load_apache_module_snapshot,
)
from webconf_audit.local.apache.rules_runner import (
    run_apache_ast_rules,
    run_apache_htaccess_rules,
    run_apache_rules,
)
from webconf_audit.local.load_context import LoadContext
from webconf_audit.local.normalizers import normalize_config
from webconf_audit.local.universal_rules import run_universal_rules
from webconf_audit.models import (
    AnalysisIssue,
    AnalysisResult,
    ControlAssessmentEvidence,
    ControlAssessmentScope,
    Finding,
    PolicyControlAssessment,
    SourceLocation,
)
from webconf_audit.policy_models import (
    ApacheModulePolicy,
    AuditPolicy,
    AuditTarget,
    ResolvedAuditPolicy,
)
from webconf_audit.rule_registry import registry as rule_registry

_APACHE_SPECIFIC_UNIVERSAL_REPLACEMENTS = frozenset(
    {
        "universal.missing_hsts",
        "universal.missing_x_frame_options",
        "universal.permissions_policy_unsafe",
        "universal.referrer_policy_unsafe",
        "universal.weak_tls_ciphers",
    }
)


@dataclass
class ApacheAnalysisContext:
    """One analyzable slice of an Apache configuration.

    For configs without VirtualHosts, there is a single global context.
    For configs with VirtualHosts, there is one context per VirtualHost.
    """

    label: str
    virtualhost: ApacheVirtualHostContext | None
    document_root: Path | None
    htaccess_files: list[HtaccessFile]
    effective_server_config: EffectiveConfig


def analyze_apache_config(
    config_path: str | os.PathLike[str],
    *,
    enable_policy_review: bool = False,
    policy: AuditPolicy | ResolvedAuditPolicy | str | os.PathLike[str] | None = None,
    module_inventory_path: str | os.PathLike[str] | None = None,
) -> AnalysisResult:
    """Run the full Apache local-analysis pipeline against ``config_path``.

    Resolves ``Include`` / ``IncludeOptional``, discovers ``.htaccess``
    files filtered by effective ``AllowOverride``, builds per-VirtualHost
    analysis contexts, then runs Apache AST rules, htaccess-aware rules,
    and universal rules over the normalized view.

    Set ``enable_policy_review=True`` to additionally include rules
    tagged ``policy-review`` (operator-judgment items surfaced via the
    ``--enable-policy-review`` CLI flag).
    """
    config_path_str = os.fspath(config_path)
    path = Path(config_path_str)
    resolved_policy, policy_error = _resolve_apache_policy(policy, target=config_path_str)
    if policy_error is not None:
        return _attach_context(policy_error, policy=resolved_policy)
    effective_policy_review = (
        enable_policy_review
        or "policy-review" in requested_opt_in_tags(resolved_policy)
    )

    if not path.is_file():
        return _attach_context(
            _config_not_found_result(config_path_str),
            policy=resolved_policy,
        )

    try:
        text = path.read_text(encoding="utf-8")
        ast, load_ctx, issues = _parse_apache_source(text, path)
        htaccess_result = discover_htaccess_files(ast, path)
        issues.extend(htaccess_result.issues)
        contexts = _build_analysis_contexts(ast, path.parent, htaccess_result.found)
        recorder = RuleExecutionRecorder()
        findings = _collect_apache_findings(
            ast,
            path.parent,
            contexts,
            issues,
            enable_policy_review=effective_policy_review,
            execution_recorder=recorder,
        )
        snapshot = (
            load_apache_module_snapshot(module_inventory_path)
            if module_inventory_path is not None
            else None
        )
    except UnicodeDecodeError as exc:
        return _attach_context(
            _apache_config_read_error_result(
                config_path_str,
                path,
                f"Cannot decode config file {config_path_str}: {exc}",
            ),
            policy=resolved_policy,
        )
    except OSError as exc:
        return _attach_context(
            _apache_config_read_error_result(
                config_path_str,
                path,
                f"Cannot read config file {config_path_str}: {exc}",
            ),
            policy=resolved_policy,
        )
    except ApacheParseError as exc:
        return _attach_context(
            _apache_parse_error_result(config_path_str, path, exc),
            policy=resolved_policy,
        )
    except ApacheModuleSnapshotLoadError as exc:
        return _attach_context(
            _apache_module_snapshot_error_result(
                config_path_str,
                path,
                code=exc.code,
                message=str(exc),
                snapshot_path=exc.path,
            ),
            policy=resolved_policy,
        )

    result = AnalysisResult(
        mode="local",
        target=config_path_str,
        server_type="apache",
        findings=findings,
        issues=issues,
        metadata=_analysis_metadata(load_ctx, htaccess_result, contexts),
    )
    _attach_apache_module_inventory(
        result,
        ast=ast,
        snapshot=snapshot,
        policy=resolved_policy,
        config_path=config_path_str,
    )
    return _attach_context(
        result,
        policy=resolved_policy,
        recorder=recorder,
    )


def _config_not_found_result(config_path: str) -> AnalysisResult:
    return AnalysisResult(
        mode="local",
        target=config_path,
        server_type="apache",
        issues=[
            AnalysisIssue(
                code="config_not_found",
                level="error",
                message=f"Config file not found: {config_path}",
                location=SourceLocation(
                    mode="local",
                    kind="file",
                    file_path=config_path,
                ),
            )
        ],
    )


def _parse_apache_source(
    text: str,
    path: Path,
) -> tuple[ApacheConfigAst, LoadContext, list[AnalysisIssue]]:
    tokens = ApacheTokenizer(text, file_path=str(path)).tokenize()
    ast = ApacheParser(tokens).parse()
    load_ctx = LoadContext(root_file=str(path))
    issues = resolve_includes(ast, path, load_context=load_ctx)
    return ast, load_ctx, issues


def _collect_apache_findings(
    ast: ApacheConfigAst,
    config_dir: Path,
    contexts: list[ApacheAnalysisContext],
    issues: list[AnalysisIssue],
    *,
    enable_policy_review: bool = False,
    execution_recorder: RuleExecutionRecorder | None = None,
) -> list[Finding]:
    findings = run_apache_ast_rules(
        ast,
        issues=issues,
        enable_policy_review=enable_policy_review,
        execution_recorder=execution_recorder,
    )
    findings.extend(
        _context_htaccess_findings(
            ast,
            contexts,
            config_dir,
            issues,
            enable_policy_review=enable_policy_review,
            execution_recorder=execution_recorder,
        )
    )
    findings.extend(
        _universal_apache_findings(
            ast,
            config_dir,
            issues,
            enable_policy_review=enable_policy_review,
            execution_recorder=execution_recorder,
        )
    )
    return findings


def _context_htaccess_findings(
    ast: ApacheConfigAst,
    contexts: list[ApacheAnalysisContext],
    config_dir: Path,
    issues: list[AnalysisIssue],
    *,
    enable_policy_review: bool = False,
    execution_recorder: RuleExecutionRecorder | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    seen_findings: set[tuple[str, str | None, int | None]] = set()

    for context in contexts:
        context_findings = run_apache_htaccess_rules(
            ast,
            htaccess_files=context.htaccess_files,
            config_dir=config_dir,
            issues=issues,
            enable_policy_review=enable_policy_review,
            execution_recorder=execution_recorder,
        )
        for finding in context_findings:
            key = _finding_key(finding)
            if key in seen_findings:
                continue
            seen_findings.add(key)
            findings.append(finding)

    return findings


def _finding_key(finding: Finding) -> tuple[str, str | None, int | None]:
    return (
        finding.rule_id,
        finding.location.file_path if finding.location else None,
        finding.location.line if finding.location else None,
    )


def _universal_apache_findings(
    ast: ApacheConfigAst,
    config_dir: Path,
    issues: list[AnalysisIssue],
    *,
    enable_policy_review: bool = False,
    execution_recorder: RuleExecutionRecorder | None = None,
) -> list[Finding]:
    normalized = normalize_config(
        "apache",
        ast=ast,
        effective_config={"config_dir": config_dir},
    )
    return [
        finding
        for finding in run_universal_rules(
            normalized,
            issues=issues,
            enable_policy_review=enable_policy_review,
            execution_recorder=execution_recorder,
        )
        if finding.rule_id not in _APACHE_SPECIFIC_UNIVERSAL_REPLACEMENTS
    ]


def _analysis_metadata(
    load_ctx: LoadContext,
    htaccess_result: HtaccessDiscoveryResult,
    contexts: list[ApacheAnalysisContext],
) -> dict[str, object]:
    metadata: dict[str, object] = {"load_context": load_ctx.to_dict()}
    if htaccess_result.found:
        metadata["htaccess_files"] = htaccess_result.found
    metadata["analysis_contexts"] = [_context_metadata(ctx) for ctx in contexts]
    return metadata


def _apache_config_read_error_result(
    config_path: str,
    path: Path,
    message: str,
) -> AnalysisResult:
    return AnalysisResult(
        mode="local",
        target=config_path,
        server_type="apache",
        issues=[
            AnalysisIssue(
                code="apache_config_read_error",
                level="error",
                message=message,
                location=SourceLocation(
                    mode="local",
                    kind="file",
                    file_path=str(path),
                ),
            )
        ],
    )


def _apache_parse_error_result(
    config_path: str,
    path: Path,
    exc: ApacheParseError,
) -> AnalysisResult:
    return AnalysisResult(
        mode="local",
        target=config_path,
        server_type="apache",
        issues=[
            AnalysisIssue(
                code="apache_parse_error",
                level="error",
                message=str(exc),
                location=SourceLocation(
                    mode="local",
                    kind="file",
                    file_path=exc.file_path or str(path),
                    line=exc.line,
                ),
            )
        ],
    )


def _apache_module_snapshot_error_result(
    config_path: str,
    path: Path,
    *,
    code: str,
    message: str,
    snapshot_path: str | None,
) -> AnalysisResult:
    location = SourceLocation(
        mode="local",
        kind="check",
        file_path=snapshot_path or str(path),
        details="apache_module_inventory",
    )
    return AnalysisResult(
        mode="local",
        target=config_path,
        server_type="apache",
        issues=[
            AnalysisIssue(
                code=code,
                level="error",
                message=message,
                location=location,
            )
        ],
    )


def _build_analysis_contexts(
    config_ast: ApacheConfigAst,
    config_dir: Path,
    all_htaccess: list[HtaccessFile],
) -> list[ApacheAnalysisContext]:
    """Build per-VirtualHost (or global) analysis contexts."""
    vhosts = extract_virtualhost_contexts(config_ast)

    if not vhosts:
        doc_root = extract_document_root(config_ast, config_dir=config_dir)
        effective = build_server_effective_config(config_ast)
        return [
            ApacheAnalysisContext(
                label="global",
                virtualhost=None,
                document_root=doc_root,
                htaccess_files=all_htaccess,
                effective_server_config=effective,
            )
        ]

    contexts: list[ApacheAnalysisContext] = []
    for vhost in vhosts:
        doc_root = extract_document_root(
            config_ast, virtualhost_context=vhost, config_dir=config_dir,
        )
        effective = build_server_effective_config(
            config_ast, virtualhost_context=vhost,
        )
        ctx_htaccess = _filter_htaccess_for_context(all_htaccess, vhost, doc_root)
        label = vhost.server_name or vhost.listen_address or "<default>"
        contexts.append(
            ApacheAnalysisContext(
                label=label,
                virtualhost=vhost,
                document_root=doc_root,
                htaccess_files=ctx_htaccess,
                effective_server_config=effective,
            )
        )
    return contexts


def _filter_htaccess_for_context(
    all_htaccess: list[HtaccessFile],
    vhost: ApacheVirtualHostContext,
    document_root: Path | None,
) -> list[HtaccessFile]:
    """Filter htaccess files to those belonging to a VirtualHost context.

    Includes htaccess files that were discovered inside the VirtualHost block,
    plus global htaccess files whose directory falls under the VirtualHost's
    effective DocumentRoot.
    """
    result: list[HtaccessFile] = []
    for h in all_htaccess:
        if h.source_virtualhost_block is vhost.node:
            result.append(h)
            continue
        if h.source_virtualhost_block is None and document_root is not None:
            if _path_is_under(h.directory_path, document_root):
                result.append(h)
    return result


def _path_is_under(child_path_str: str, parent: Path) -> bool:
    """Check if a path is under a parent directory."""
    try:
        child_resolved = str(Path(child_path_str).resolve()).replace("\\", "/").rstrip("/").lower()
        parent_resolved = str(parent.resolve()).replace("\\", "/").rstrip("/").lower()
        return child_resolved == parent_resolved or child_resolved.startswith(parent_resolved + "/")
    except (OSError, ValueError):
        return False


def _context_metadata(ctx: ApacheAnalysisContext) -> dict[str, object]:
    """Serialize an analysis context for result metadata."""
    return {
        "label": ctx.label,
        "virtualhost": ctx.virtualhost is not None,
        "document_root": str(ctx.document_root) if ctx.document_root else None,
        "htaccess_count": len(ctx.htaccess_files),
        "effective_directive_count": len(ctx.effective_server_config.directives),
    }


def _attach_context(
    result: AnalysisResult,
    *,
    policy: ResolvedAuditPolicy | None,
    recorder: RuleExecutionRecorder | None = None,
) -> AnalysisResult:
    rule_registry.ensure_loaded("webconf_audit.local.apache.rules")
    rule_registry.ensure_loaded("webconf_audit.local.rules.universal")
    manifest = build_analysis_manifest(
        recorder=recorder or RuleExecutionRecorder(),
        policy=policy,
        mode="local",
        server_type="apache",
        registry=rule_registry,
    )
    return attach_audit_context(result, policy, manifest)


def _resolve_apache_policy(
    policy: AuditPolicy | ResolvedAuditPolicy | str | os.PathLike[str] | None,
    *,
    target: str,
) -> tuple[ResolvedAuditPolicy | None, AnalysisResult | None]:
    if policy is None:
        return None, None
    if isinstance(policy, ResolvedAuditPolicy):
        return policy, None
    try:
        loaded_policy = (
            load_audit_policy(Path(policy))
            if isinstance(policy, (str, os.PathLike))
            else policy
        )
    except AuditPolicyLoadError as exc:
        return None, _policy_error_result(target=target, issue=exc.issue)
    ledger = load_coverage_ledger()
    _ensure_policy_rules_loaded()
    validation_issues = validate_audit_policy(loaded_policy, ledger, rule_registry)
    if validation_issues:
        return None, _policy_error_result(
            target=target,
            issue=validation_issues[0],
        )
    try:
        return (
            resolve_audit_policy(
                loaded_policy,
                AuditTarget(mode="local", server_type="apache", target=target),
                ledger,
            ),
            None,
        )
    except AuditPolicyResolveError as exc:
        return None, _policy_error_result(target=target, issue=exc.issue)


def _policy_error_result(*, target: str, issue) -> AnalysisResult:
    location = SourceLocation(mode="local", kind="check", details="audit_policy")
    if issue.path is not None:
        location.file_path = issue.path
    return AnalysisResult(
        mode="local",
        target=target,
        server_type="apache",
        issues=[
            AnalysisIssue(
                code=issue.code,
                level="error",
                message=issue.message,
                location=location,
            )
        ],
    )


def _ensure_policy_rules_loaded() -> None:
    rule_registry.ensure_loaded("webconf_audit.local.apache.rules")
    rule_registry.ensure_loaded("webconf_audit.local.rules.universal")
    rule_registry.ensure_loaded("webconf_audit.local.nginx.rules")
    rule_registry.ensure_loaded("webconf_audit.local.lighttpd.rules")
    rule_registry.ensure_loaded("webconf_audit.local.iis.rules")
    rule_registry.ensure_loaded("webconf_audit.external.rules")


def _attach_apache_module_inventory(
    result: AnalysisResult,
    *,
    ast: ApacheConfigAst,
    snapshot: ApacheModuleSnapshot | None,
    policy: ResolvedAuditPolicy | None,
    config_path: str,
) -> None:
    module_policies = (
        policy.apache.module_inventory.policies
        if policy is not None
        and policy.apache is not None
        and policy.apache.module_inventory is not None
        else ()
    )
    if snapshot is None and not module_policies:
        return

    metadata: dict[str, object] = {
        "snapshot": snapshot.model_dump(mode="json") if snapshot is not None else None,
        "policy_selected": None,
        "evaluation": None,
    }

    if snapshot is None and module_policies:
        result.metadata["apache_module_inventory"] = metadata
        result.control_assessments.append(
            _missing_snapshot_control_assessment(
                policy_id=module_policies[0].policy_id,
                config_path=config_path,
            )
        )
        return

    assert snapshot is not None
    selected_policy, selection_issue = _select_module_policy(module_policies, snapshot)
    if selected_policy is None:
        if selection_issue is not None:
            result.issues.append(selection_issue)
        result.metadata["apache_module_inventory"] = metadata
        if module_policies:
            result.control_assessments.append(
                _selection_failure_control_assessment(
                    config_path=config_path,
                    snapshot=snapshot,
                    summary=(
                        selection_issue.message
                        if selection_issue is not None
                        else "Apache module inventory policy did not match the explicit snapshot."
                    ),
                )
            )
        return

    evaluation = evaluate_apache_modules(snapshot, selected_policy, ast)
    metadata["policy_selected"] = selected_policy.policy_id
    metadata["evaluation"] = evaluation.model_dump(mode="json")
    result.metadata["apache_module_inventory"] = metadata
    if evaluation.conflicting_modules:
        result.issues.append(
            AnalysisIssue(
                code="apache_module_snapshot_conflict",
                level="warning",
                message=(
                    "Explicit Apache module snapshot conflicts with visible active LoadModule directives."
                ),
                details=", ".join(evaluation.conflicting_modules),
                location=SourceLocation(
                    mode="local",
                    kind="check",
                    file_path=config_path,
                    details="apache_module_inventory",
                ),
            )
        )
    result.control_assessments.append(
        _module_control_assessment(
            evaluation=evaluation,
            config_path=config_path,
            policy_source=policy.policy_id if policy is not None else "<resolved-policy>",
        )
    )


def _select_module_policy(
    policies: tuple[ApacheModulePolicy, ...],
    snapshot: ApacheModuleSnapshot,
) -> tuple[ApacheModulePolicy | None, AnalysisIssue | None]:
    if not policies:
        return None, None
    matches = [policy for policy in policies if _module_policy_matches(policy, snapshot)]
    if len(matches) == 1:
        return matches[0], None
    if not matches:
        return None, AnalysisIssue(
            code="apache_module_policy_no_match",
            level="warning",
            message=(
                "Apache module inventory policy did not match the explicit snapshot "
                f"{snapshot.snapshot_id!r} for host {snapshot.host!r}."
            ),
            location=SourceLocation(mode="local", kind="check", details="apache_module_inventory"),
        )
    return None, AnalysisIssue(
        code="apache_module_policy_multiple_matches",
        level="warning",
        message=(
            "Apache module inventory policy matched more than one policy entry for "
            f"snapshot {snapshot.snapshot_id!r}."
        ),
        location=SourceLocation(mode="local", kind="check", details="apache_module_inventory"),
    )


def _module_policy_matches(
    policy: ApacheModulePolicy,
    snapshot: ApacheModuleSnapshot,
) -> bool:
    if policy.inventory_snapshot_id != snapshot.snapshot_id:
        return False
    if policy.selectors is None:
        return True
    if policy.selectors.host is not None and policy.selectors.host != snapshot.host:
        return False
    if (
        policy.selectors.environment is not None
        and policy.selectors.environment != snapshot.environment
    ):
        return False
    if (
        policy.selectors.configuration_id is not None
        and policy.selectors.configuration_id != snapshot.apache.configuration_id
    ):
        return False
    return True


def _missing_snapshot_control_assessment(
    *,
    policy_id: str,
    config_path: str,
) -> PolicyControlAssessment:
    return PolicyControlAssessment(
        control_id="apache.module_inventory",
        title="Explicit Apache module inventory policy",
        status="indeterminate",
        scope=ControlAssessmentScope(
            server_scope_id=config_path,
            route_scope_id=config_path,
            route_selector=config_path,
        ),
        summary="Apache module snapshot was not supplied, so module inventory policy cannot be concluded safely.",
        evidence=(
            ControlAssessmentEvidence(
                kind="unsupported",
                status="missing",
                message="No explicit Apache module inventory snapshot was supplied.",
            ),
        ),
        policy_source=policy_id,
        metadata={
            "inventory_id": None,
            "inventory_complete": False,
            "observations_complete": False,
            "missing_evidence": ("module snapshot was not supplied",),
            "limitations": (
                "Config-visible LoadModule directives do not replace the explicit module snapshot.",
            ),
        },
    )


def _selection_failure_control_assessment(
    *,
    config_path: str,
    snapshot: ApacheModuleSnapshot,
    summary: str,
) -> PolicyControlAssessment:
    return PolicyControlAssessment(
        control_id="apache.module_inventory",
        title="Explicit Apache module inventory policy",
        status="indeterminate",
        scope=ControlAssessmentScope(
            server_scope_id=config_path,
            route_scope_id=config_path,
            route_selector=config_path,
        ),
        summary=summary,
        evidence=(
            ControlAssessmentEvidence(
                kind="unsupported",
                status="mismatch",
                message=summary,
                values=(snapshot.snapshot_id, snapshot.host),
            ),
        ),
        policy_source="<resolved-policy>",
        metadata={
            "inventory_id": snapshot.snapshot_id,
            "inventory_complete": snapshot.completeness.state == "complete",
            "observations_complete": False,
            "evidence_references": (
                f"apache-module-snapshot:{snapshot.snapshot_id}",
                f"host:{snapshot.host}",
            ),
            "missing_evidence": ("exactly one module inventory policy match is required",),
            "limitations": (
                "A mismatched or ambiguous module inventory policy prevents a safe benchmark conclusion.",
            ),
        },
    )


def _module_control_assessment(
    *,
    evaluation: ApacheModuleEvaluation,
    config_path: str,
    policy_source: str,
) -> PolicyControlAssessment:
    return PolicyControlAssessment(
        control_id=evaluation.control_id,
        title="Explicit Apache module inventory policy",
        status=evaluation.status,
        scope=ControlAssessmentScope(
            server_scope_id=config_path,
            route_scope_id=config_path,
            route_selector=config_path,
        ),
        summary=evaluation.summary,
        evidence=tuple(
            ControlAssessmentEvidence(
                kind="unsupported",
                status=comparison.predicate_result,
                message=comparison.reason,
                values=(
                    comparison.module_name,
                    comparison.snapshot_state,
                    comparison.policy_expectation or "unlisted",
                ),
            )
            for comparison in evaluation.comparisons
        ),
        policy_source=policy_source,
        metadata={
            "inventory_id": evaluation.snapshot_id,
            "inventory_complete": evaluation.inventory_complete,
            "observations_complete": evaluation.observations_complete,
            "evidence_references": evaluation.evidence_references,
            "missing_evidence": evaluation.missing_evidence,
            "limitations": evaluation.limitations,
            "apache_module_evaluation": evaluation.model_dump(mode="json"),
        },
    )


__all__ = [
    "ApacheAnalysisContext",
    "analyze_apache_config",
    "evaluate_root_authorization",
    "evaluate_apache_modules",
    "load_apache_module_snapshot",
    "run_apache_rules",
]
