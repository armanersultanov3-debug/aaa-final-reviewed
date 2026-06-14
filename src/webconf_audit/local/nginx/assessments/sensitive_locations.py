"""Policy-backed sensitive-location assessments for Nginx."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
from typing import Iterable

from webconf_audit.local.nginx.access_control_semantics import (
    AuthControlState,
    EffectiveAccessControl,
    resolve_effective_access_control,
)
from webconf_audit.local.nginx.effective_scope import NginxScope, NginxScopeGraph, NginxScopeKind
from webconf_audit.local.nginx.location_matcher import bind_declared_location, resolve_location_sample
from webconf_audit.local.nginx.parser.ast import ConfigAst, DirectiveNode, SourceSpan
from webconf_audit.models import (
    ControlAssessmentEvidence,
    ControlAssessmentScope,
    PolicyControlAssessment,
    SourceLocation,
)
from webconf_audit.policy_models import (
    NginxIpAllowlistRequirement,
    NginxSensitiveLocationEntry,
    NginxSensitiveLocationRequirement,
    NginxSensitiveLocationsPolicy,
)

_POLICY_SECTION = "nginx.sensitive_locations"
_ASVS_CONTROL_ID = "asvs-5.0.0-v13.4.5.sensitive-endpoint-exposure"
_CIS_CONTROL_ID = "cis-nginx-5.1.1.sensitive-ip-filters"

_GENERIC_RELATED_RULE_IDS = (
    "nginx.missing_access_restrictions_on_sensitive_locations",
    "nginx.sensitive_location_missing_ip_filter",
    "nginx.allow_all_with_deny_all",
    "nginx.missing_auth_basic_user_file",
)
_CIS_RELATED_RULE_IDS = (
    "nginx.sensitive_location_missing_ip_filter",
    "nginx.allow_all_with_deny_all",
)
_ASVS_RELATED_RULE_IDS = (
    "nginx.missing_access_restrictions_on_sensitive_locations",
)


@dataclass(frozen=True)
class _TargetEvaluation:
    label: str
    scope: NginxScope
    control: EffectiveAccessControl
    status: str
    summary: str
    evidence: tuple[ControlAssessmentEvidence, ...]
    ip_requirement_applies: bool = False
    ip_requirement_status: str | None = None
    ip_requirement_evidence: tuple[ControlAssessmentEvidence, ...] = ()
    shadowed: bool = False


def evaluate_sensitive_location_policy(
    config_ast: ConfigAst,
    *,
    scope_graph: NginxScopeGraph,
    policy: NginxSensitiveLocationsPolicy | None,
    findings: Iterable[object] = (),
) -> list[PolicyControlAssessment]:
    if policy is None:
        return []

    # Retain these parameters for analyzer-policy evaluator signature parity.
    del config_ast, findings
    assessments: list[PolicyControlAssessment] = []
    server_scopes = tuple(
        scope
        for scope in scope_graph.scopes
        if scope.kind == NginxScopeKind.SERVER
    )
    server_names_by_scope = {
        scope.scope_id: _scope_server_names(scope, scope_graph)
        for scope in server_scopes
    }

    for entry in policy.catalog:
        matched_servers = [
            scope
            for scope in server_scopes
            if {name.lower() for name in server_names_by_scope[scope.scope_id]}
            & {name.lower() for name in entry.server_names}
        ]
        if not matched_servers:
            assessments.extend(
                _unmatched_server_assessments(
                    entry,
                    status=policy.unmatched_entries,
                )
            )
            continue

        for server_scope in matched_servers:
            evaluations, reasons = _evaluate_entry_for_server(
                entry=entry,
                scope_graph=scope_graph,
                server_scope=server_scope,
                allow_unresolved_internal_redirects=policy.allow_unresolved_internal_redirects,
            )
            assessments.append(
                _policy_assessment(
                    entry=entry,
                    server_scope=server_scope,
                    scope_graph=scope_graph,
                    evaluations=evaluations,
                    reasons=reasons,
                )
            )
            if _requirement_requires_ip_allowlist(entry.required_controls):
                assessments.append(
                    _cis_assessment(
                        entry=entry,
                        server_scope=server_scope,
                        scope_graph=scope_graph,
                        evaluations=evaluations,
                        reasons=reasons,
                    )
                )
            if entry.kind in {"documentation", "monitoring"}:
                assessments.append(
                    _asvs_assessment(
                        entry=entry,
                        server_scope=server_scope,
                        scope_graph=scope_graph,
                        evaluations=evaluations,
                        reasons=reasons,
                    )
                )

    assessments.sort(key=_assessment_sort_key)
    return assessments


def _evaluate_entry_for_server(
    *,
    entry: NginxSensitiveLocationEntry,
    scope_graph: NginxScopeGraph,
    server_scope: NginxScope,
    allow_unresolved_internal_redirects: bool,
) -> tuple[tuple[_TargetEvaluation, ...], tuple[str, ...]]:
    evaluations: list[_TargetEvaluation] = []
    reasons: set[str] = set()
    declared_scope: NginxScope | None = None

    if entry.declared_location is not None:
        binding = bind_declared_location(
            scope_graph=scope_graph,
            server_scope_id=server_scope.scope_id,
            selector=entry.declared_location,
        )
        if binding.status == "selected" and binding.selected_scope is not None:
            declared_scope = binding.selected_scope
            evaluation, target_reasons = _evaluate_scope_target(
                label="declared_location",
                scope=declared_scope,
                entry=entry,
                scope_graph=scope_graph,
                allow_unresolved_internal_redirects=allow_unresolved_internal_redirects,
            )
            evaluations.append(evaluation)
            reasons.update(target_reasons)
        elif binding.status == "unmatched":
            reasons.add("declared-location-unmatched")
        else:
            reasons.update(binding.indeterminate_reasons)

    for sample_uri in entry.sample_uris:
        resolution = resolve_location_sample(
            scope_graph=scope_graph,
            server_scope_id=server_scope.scope_id,
            sample_uri=sample_uri,
        )
        if resolution.status != "selected" or resolution.selected_scope is None:
            reasons.update(resolution.indeterminate_reasons or ("sample-resolution-indeterminate",))
            continue
        shadowed = declared_scope is not None and resolution.selected_scope.scope_id != declared_scope.scope_id
        evaluation, target_reasons = _evaluate_scope_target(
            label=sample_uri,
            scope=resolution.selected_scope,
            entry=entry,
            scope_graph=scope_graph,
            allow_unresolved_internal_redirects=allow_unresolved_internal_redirects,
            shadowed=shadowed,
        )
        if shadowed:
            reasons.add("sample-shadowed-by-different-location")
        evaluations.append(evaluation)
        reasons.update(target_reasons)

    if not evaluations:
        reasons.add("no-resolved-sensitive-location-targets")
    return tuple(evaluations), tuple(sorted(reasons))


def _evaluate_scope_target(
    *,
    label: str,
    scope: NginxScope,
    entry: NginxSensitiveLocationEntry,
    scope_graph: NginxScopeGraph,
    allow_unresolved_internal_redirects: bool,
    shadowed: bool = False,
) -> tuple[_TargetEvaluation, tuple[str, ...]]:
    control = resolve_effective_access_control(
        scope_graph=scope_graph,
        route_scope_id=scope.scope_id,
    )
    reasons = set(control.indeterminate_reasons)
    if _has_unresolved_internal_redirect(scope_graph, scope.scope_id):
        if allow_unresolved_internal_redirects:
            reasons.add("unresolved-internal-redirect-allowed")
        else:
            reasons.add("unresolved-internal-redirect")
    if shadowed:
        reasons.add("sample-shadowed-by-different-location")

    status, evidence = _evaluate_requirement(
        requirement=entry.required_controls,
        control=control,
    )
    ip_requirement_applies, ip_status, ip_evidence = _evaluate_ip_requirement(
        requirement=entry.required_controls,
        control=control,
    )
    if shadowed:
        status = "indeterminate"
        if ip_requirement_applies:
            ip_status = "indeterminate"
    if reasons and status == "pass":
        status = "indeterminate"
    if reasons and ip_status == "pass":
        ip_status = "indeterminate"
    summary = (
        "Sensitive location target satisfies the declared access-control contract."
        if status == "pass"
        else "Sensitive location target does not satisfy the declared access-control contract."
        if status == "fail"
        else "Sensitive location target could not be resolved conclusively."
    )
    return (
        _TargetEvaluation(
            label=label,
            scope=scope,
            control=control,
            status=status,
            summary=summary,
            evidence=evidence,
            ip_requirement_applies=ip_requirement_applies,
            ip_requirement_status=ip_status,
            ip_requirement_evidence=ip_evidence,
            shadowed=shadowed,
        ),
        tuple(sorted(reasons)),
    )


def _evaluate_requirement(
    *,
    requirement: NginxSensitiveLocationRequirement,
    control: EffectiveAccessControl,
) -> tuple[str, tuple[ControlAssessmentEvidence, ...]]:
    evidence: list[ControlAssessmentEvidence] = []
    if requirement.satisfy is not None and control.satisfy != requirement.satisfy:
        evidence.append(
            _route_evidence(
                status="fail",
                message=(
                    f"Effective satisfy mode is {control.satisfy!r}, "
                    f"but the declared contract requires {requirement.satisfy!r}."
                ),
                scope=control.scope_id,
            )
        )
        return "fail", tuple(evidence)

    if requirement.all_of:
        child_statuses = []
        for child in requirement.all_of:
            child_status, child_evidence = _evaluate_requirement(
                requirement=child,
                control=control,
            )
            child_statuses.append(child_status)
            evidence.extend(child_evidence)
        if any(status == "fail" for status in child_statuses):
            return "fail", tuple(evidence)
        if any(status == "indeterminate" for status in child_statuses):
            return "indeterminate", tuple(evidence)
        return "pass", tuple(evidence)

    if requirement.one_of:
        child_statuses = []
        for child in requirement.one_of:
            child_status, child_evidence = _evaluate_requirement(
                requirement=child,
                control=control,
            )
            child_statuses.append(child_status)
            evidence.extend(child_evidence)
        if any(status == "pass" for status in child_statuses):
            return "pass", tuple(evidence)
        if any(status == "indeterminate" for status in child_statuses):
            return "indeterminate", tuple(evidence)
        return "fail", tuple(evidence)

    if requirement.internal is not None:
        if control.classification == "internal_only":
            return "pass", (_route_evidence(status="pass", message="The route is internal-only.", scope=control.scope_id),)
        return "fail", (
            _route_evidence(status="fail", message="The route is not marked internal-only.", scope=control.scope_id),
        )

    if requirement.deny_all is not None:
        if control.classification == "unconditionally_denied":
            return "pass", (
                _route_evidence(
                    status="pass",
                    message="The route is unconditionally denied for external requests.",
                    scope=control.scope_id,
                ),
            )
        return "fail", (
            _route_evidence(
                status="fail",
                message="The route is not unconditionally denied for external requests.",
                scope=control.scope_id,
            ),
        )

    if requirement.auth_basic is not None:
        return _evaluate_auth_leaf(
            control=control,
            state=control.auth_basic,
            control_name="auth_basic",
        )
    if requirement.auth_request is not None:
        return _evaluate_auth_leaf(
            control=control,
            state=control.auth_request,
            control_name="auth_request",
        )
    if requirement.auth_jwt is not None:
        return _evaluate_optional_auth_leaf(
            control=control,
            state=control.auth_jwt,
            control_name="auth_jwt",
        )
    if requirement.auth_oidc is not None:
        return _evaluate_optional_auth_leaf(
            control=control,
            state=control.auth_oidc,
            control_name="auth_oidc",
        )
    if requirement.ip_allowlist is not None:
        return _evaluate_ip_allowlist(
            control=control,
            requirement=requirement.ip_allowlist,
        )
    return "indeterminate", (
        _route_evidence(status="indeterminate", message="Unsupported requirement leaf.", scope=control.scope_id),
    )


def _evaluate_auth_leaf(
    *,
    control: EffectiveAccessControl,
    state: AuthControlState,
    control_name: str,
) -> tuple[str, tuple[ControlAssessmentEvidence, ...]]:
    if state.state == "enabled" and state.companion_present is not False:
        return "pass", (
            _route_evidence(
                status="pass",
                message=f"The route enables {control_name}.",
                scope=control.scope_id,
                location=state.source,
            ),
        )
    if state.state == "enabled" and state.companion_present is False:
        return "indeterminate", (
            _route_evidence(
                status="indeterminate",
                message=f"The route enables {control_name}, but required companion configuration is incomplete.",
                scope=control.scope_id,
                location=state.source,
            ),
        )
    if state.state == "unknown":
        return "indeterminate", (
            _route_evidence(
                status="indeterminate",
                message=f"The route contains an unresolved {control_name} directive.",
                scope=control.scope_id,
                location=state.source,
            ),
        )
    return "fail", (
        _route_evidence(
            status="fail",
            message=f"The route does not enable {control_name}.",
            scope=control.scope_id,
            location=state.source,
        ),
    )


def _evaluate_optional_auth_leaf(
    *,
    control: EffectiveAccessControl,
    state: AuthControlState,
    control_name: str,
) -> tuple[str, tuple[ControlAssessmentEvidence, ...]]:
    if state.state == "enabled":
        return "indeterminate", (
            _route_evidence(
                status="indeterminate",
                message=(
                    f"The route enables {control_name}, but static analysis cannot prove "
                    "module availability or successful runtime verification."
                ),
                scope=control.scope_id,
                location=state.source,
            ),
        )
    if state.state == "unknown":
        return "indeterminate", (
            _route_evidence(
                status="indeterminate",
                message=f"The route contains an unresolved {control_name} directive.",
                scope=control.scope_id,
                location=state.source,
            ),
        )
    return "fail", (
        _route_evidence(
            status="fail",
            message=f"The route does not enable {control_name}.",
            scope=control.scope_id,
            location=state.source,
        ),
    )


def _evaluate_ip_allowlist(
    *,
    control: EffectiveAccessControl,
    requirement: NginxIpAllowlistRequirement,
) -> tuple[str, tuple[ControlAssessmentEvidence, ...]]:
    normalized_policy = {
        _normalize_ip_or_cidr(value)
        for value in requirement.allowed_cidrs
    }
    derived = _derived_ip_allowlist(control)
    if derived["status"] == "indeterminate":
        return "indeterminate", (
            _route_evidence(
                status="indeterminate",
                message="Static analysis cannot prove the route's ordered IP allowlist exactly.",
                scope=control.scope_id,
            ),
        )
    if derived["status"] == "fail":
        return "fail", (
            _route_evidence(
                status="fail",
                message="The route does not enforce the declared ordered IP allowlist.",
                scope=control.scope_id,
            ),
        )
    effective_cidrs = derived["allowed_cidrs"]
    if requirement.require_deny_all_fallback and not derived["has_deny_all_fallback"]:
        return "fail", (
            _route_evidence(
                status="fail",
                message="The route is missing a deny all fallback after allowed CIDRs.",
                scope=control.scope_id,
            ),
        )
    if effective_cidrs != normalized_policy:
        return "fail", (
            _route_evidence(
                status="fail",
                message="The route's effective allowlist does not match the declared CIDR inventory.",
                scope=control.scope_id,
            ),
        )
    return "pass", (
        _route_evidence(
            status="pass",
            message="The route enforces the declared ordered IP allowlist.",
            scope=control.scope_id,
        ),
    )


def _evaluate_ip_requirement(
    *,
    requirement: NginxSensitiveLocationRequirement,
    control: EffectiveAccessControl,
) -> tuple[bool, str | None, tuple[ControlAssessmentEvidence, ...]]:
    if requirement.ip_allowlist is not None:
        status, evidence = _evaluate_ip_allowlist(
            control=control,
            requirement=requirement.ip_allowlist,
        )
        return True, status, evidence

    if requirement.all_of:
        evidence: list[ControlAssessmentEvidence] = []
        statuses: list[str] = []
        applicable = False
        for child in requirement.all_of:
            child_applicable, child_status, child_evidence = _evaluate_ip_requirement(
                requirement=child,
                control=control,
            )
            if not child_applicable or child_status is None:
                continue
            applicable = True
            statuses.append(child_status)
            evidence.extend(child_evidence)
        if not applicable:
            return False, None, ()
        if any(status == "fail" for status in statuses):
            return True, "fail", tuple(evidence)
        if any(status == "indeterminate" for status in statuses):
            return True, "indeterminate", tuple(evidence)
        return True, "pass", tuple(evidence)

    if requirement.one_of:
        results = [
            _evaluate_ip_requirement(
                requirement=child,
                control=control,
            )
            for child in requirement.one_of
        ]
        if not results or not all(applicable for applicable, _, _ in results):
            return False, None, ()
        evidence = tuple(
            item
            for _, _, child_evidence in results
            for item in child_evidence
        )
        statuses = [status for _, status, _ in results if status is not None]
        if any(status == "pass" for status in statuses):
            return True, "pass", evidence
        if any(status == "indeterminate" for status in statuses):
            return True, "indeterminate", evidence
        return True, "fail", evidence

    return False, None, ()


def _derived_ip_allowlist(control: EffectiveAccessControl) -> dict[str, object]:
    if control.satisfy == "any" and _authentication_can_bypass(control):
        return {"status": "fail"}
    allowed: list[str] = []
    seen_allow = False
    for rule in control.address_rules:
        if rule.subject_kind in {"dynamic", "hostname"}:
            return {"status": "indeterminate"}
        if rule.action == "allow" and rule.subject_kind == "all":
            return {"status": "fail"}
        if rule.action == "deny" and rule.subject_kind == "all":
            return {
                "status": "pass" if seen_allow else "fail",
                "allowed_cidrs": set(allowed),
                "has_deny_all_fallback": True,
            }
        if rule.action == "allow" and rule.subject_kind in {"ip", "cidr"}:
            allowed.append(_normalize_ip_or_cidr(rule.subject))
            seen_allow = True
            continue
        if rule.action == "allow" and rule.subject_kind == "unix":
            return {"status": "fail"}
        if rule.action == "deny":
            return {"status": "fail"}
    return {
        "status": "fail",
        "allowed_cidrs": set(allowed),
        "has_deny_all_fallback": False,
    }


def _authentication_can_bypass(control: EffectiveAccessControl) -> bool:
    return (
        (control.auth_basic.state == "enabled" and control.auth_basic.companion_present is not False)
        or control.auth_request.state == "enabled"
        or control.auth_jwt.state == "enabled"
        or control.auth_oidc.state == "enabled"
    )


def _policy_assessment(
    *,
    entry: NginxSensitiveLocationEntry,
    server_scope: NginxScope,
    scope_graph: NginxScopeGraph,
    evaluations: tuple[_TargetEvaluation, ...],
    reasons: tuple[str, ...],
) -> PolicyControlAssessment:
    status = _combined_status(evaluations, reasons)
    route_scope = evaluations[0].scope if evaluations else server_scope
    evidence = _combined_evidence(evaluations, reasons=reasons)
    return PolicyControlAssessment(
        control_id=f"policy.nginx.sensitive-location.{entry.entry_id}",
        title=f"Nginx sensitive location policy: {entry.entry_id}",
        status=status,  # type: ignore[arg-type]
        scope=ControlAssessmentScope(
            server_scope_id=server_scope.scope_id,
            route_scope_id=route_scope.scope_id,
            route_selector=route_scope.selector,
            server_name=_scope_server_names(server_scope, scope_graph)[0]
            if _scope_server_names(server_scope, scope_graph)
            else None,
        ),
        summary=_combined_summary(
            status=status,
            entry=entry,
            server_scope=server_scope,
            scope_graph=scope_graph,
        ),
        evidence=evidence,
        related_rule_ids=_GENERIC_RELATED_RULE_IDS,
        policy_source=f"{_POLICY_SECTION}.{entry.entry_id}",
        metadata=_assessment_metadata(
            entry=entry,
            server_scope=server_scope,
            evaluations=evaluations,
            reasons=reasons,
        ),
    )


def _cis_assessment(
    *,
    entry: NginxSensitiveLocationEntry,
    server_scope: NginxScope,
    scope_graph: NginxScopeGraph,
    evaluations: tuple[_TargetEvaluation, ...],
    reasons: tuple[str, ...],
) -> PolicyControlAssessment:
    status = _combined_status(evaluations, reasons, ip_only=True)
    route_scope = evaluations[0].scope if evaluations else server_scope
    return PolicyControlAssessment(
        control_id=_CIS_CONTROL_ID,
        title="Ensure allow and deny filters limit access to specific IP addresses",
        status=status,  # type: ignore[arg-type]
        scope=ControlAssessmentScope(
            server_scope_id=server_scope.scope_id,
            route_scope_id=route_scope.scope_id,
            route_selector=route_scope.selector,
            server_name=_scope_server_names(server_scope, scope_graph)[0]
            if _scope_server_names(server_scope, scope_graph)
            else None,
        ),
        summary=(
            "Effective ordered IP filters satisfy the declared sensitive-route contract."
            if status == "pass"
            else "Effective ordered IP filters do not satisfy the declared sensitive-route contract."
            if status == "fail"
            else "Effective ordered IP filters could not be resolved conclusively."
        ),
        evidence=_combined_evidence(evaluations, reasons=reasons, ip_only=True),
        related_rule_ids=_CIS_RELATED_RULE_IDS,
        policy_source=f"{_POLICY_SECTION}.{entry.entry_id}",
        metadata={
            **_assessment_metadata(
                entry=entry,
                server_scope=server_scope,
                evaluations=evaluations,
                reasons=reasons,
            ),
            "coverage_note": "CIS NGINX v3.0.0 §5.1.1 remains partial because the sensitive-route catalog is operator-supplied.",
        },
    )


def _asvs_assessment(
    *,
    entry: NginxSensitiveLocationEntry,
    server_scope: NginxScope,
    scope_graph: NginxScopeGraph,
    evaluations: tuple[_TargetEvaluation, ...],
    reasons: tuple[str, ...],
) -> PolicyControlAssessment:
    status = _combined_status(evaluations, reasons)
    route_scope = evaluations[0].scope if evaluations else server_scope
    return PolicyControlAssessment(
        control_id=_ASVS_CONTROL_ID,
        title="Verify that documentation and monitoring endpoints are not exposed unless explicitly intended",
        status=status,  # type: ignore[arg-type]
        scope=ControlAssessmentScope(
            server_scope_id=server_scope.scope_id,
            route_scope_id=route_scope.scope_id,
            route_selector=route_scope.selector,
            server_name=_scope_server_names(server_scope, scope_graph)[0]
            if _scope_server_names(server_scope, scope_graph)
            else None,
        ),
        summary=(
            "The declared documentation or monitoring endpoint exposure contract is satisfied."
            if status == "pass"
            else "The declared documentation or monitoring endpoint exposure contract is not satisfied."
            if status == "fail"
            else "The declared documentation or monitoring endpoint exposure contract could not be resolved conclusively."
        ),
        evidence=_combined_evidence(evaluations, reasons=reasons),
        related_rule_ids=_ASVS_RELATED_RULE_IDS,
        policy_source=f"{_POLICY_SECTION}.{entry.entry_id}",
        metadata={
            **_assessment_metadata(
                entry=entry,
                server_scope=server_scope,
                evaluations=evaluations,
                reasons=reasons,
            ),
            "coverage_note": "This is static route exposure evidence only; application authorization and runtime exposure remain separate corroboration layers.",
        },
    )


def _unmatched_server_assessments(
    entry: NginxSensitiveLocationEntry,
    *,
    status: str,
) -> list[PolicyControlAssessment]:
    synthetic_scope_id = f"policy-entry:{entry.entry_id}"
    metadata = {
        "policy_section": _POLICY_SECTION,
        "catalog_entry_id": entry.entry_id,
        "server_scope_id": synthetic_scope_id,
        "declared_location": (
            {
                "modifier": entry.declared_location.modifier,
                "pattern": entry.declared_location.pattern,
                "source_path": entry.declared_location.source_path,
            }
            if entry.declared_location is not None
            else None
        ),
        "sample_uris": list(entry.sample_uris),
        "server_names": list(entry.server_names),
        "effective_satisfy": None,
        "protection_classification": None,
        "ordered_access_rules": [],
        "indeterminate_reasons": [] if status != "indeterminate" else ["no-matching-server-scope"],
        "shadowed_samples": [],
    }
    base = PolicyControlAssessment(
        control_id=f"policy.nginx.sensitive-location.{entry.entry_id}",
        title=f"Nginx sensitive location policy: {entry.entry_id}",
        status=status,  # type: ignore[arg-type]
        scope=ControlAssessmentScope(
            server_scope_id=synthetic_scope_id,
            route_scope_id=synthetic_scope_id,
            route_selector=entry.declared_location.pattern if entry.declared_location is not None else None,
            server_name=entry.server_names[0] if entry.server_names else None,
        ),
        summary="The policy entry did not match any nginx server block.",
        evidence=(),
        related_rule_ids=(),
        policy_source=f"{_POLICY_SECTION}.{entry.entry_id}",
        metadata=metadata,
    )
    assessments = [base]
    if _requirement_requires_ip_allowlist(entry.required_controls):
        assessments.append(
            base.model_copy(
                update={
                    "control_id": _CIS_CONTROL_ID,
                    "title": "Ensure allow and deny filters limit access to specific IP addresses",
                    "related_rule_ids": _CIS_RELATED_RULE_IDS,
                }
            )
        )
    if entry.kind in {"documentation", "monitoring"}:
        assessments.append(
            base.model_copy(
                update={
                    "control_id": _ASVS_CONTROL_ID,
                    "title": "Verify that documentation and monitoring endpoints are not exposed unless explicitly intended",
                    "related_rule_ids": _ASVS_RELATED_RULE_IDS,
                }
            )
        )
    return assessments


def _combined_status(
    evaluations: tuple[_TargetEvaluation, ...],
    reasons: tuple[str, ...],
    *,
    ip_only: bool = False,
) -> str:
    if not evaluations:
        return "indeterminate" if reasons else "fail"
    statuses = [
        (
            evaluation.ip_requirement_status
            if ip_only
            else evaluation.status
        )
        for evaluation in evaluations
        if not ip_only or evaluation.ip_requirement_applies
    ]
    statuses = [status for status in statuses if status is not None]
    if not statuses:
        return "not-applicable"
    if any(status == "fail" for status in statuses):
        return "fail"
    if reasons or any(status == "indeterminate" for status in statuses):
        return "indeterminate"
    return "pass"


def _combined_summary(
    *,
    status: str,
    entry: NginxSensitiveLocationEntry,
    server_scope: NginxScope,
    scope_graph: NginxScopeGraph,
) -> str:
    server_names = _scope_server_names(server_scope, scope_graph)
    target_server = server_names[0] if server_names else server_scope.scope_id
    return (
        f"Sensitive location entry {entry.entry_id!r} satisfies the declared contract for {target_server!r}."
        if status == "pass"
        else f"Sensitive location entry {entry.entry_id!r} does not satisfy the declared contract for {target_server!r}."
        if status == "fail"
        else f"Sensitive location entry {entry.entry_id!r} could not be resolved conclusively for {target_server!r}."
    )


def _combined_evidence(
    evaluations: tuple[_TargetEvaluation, ...],
    *,
    reasons: tuple[str, ...],
    ip_only: bool = False,
) -> tuple[ControlAssessmentEvidence, ...]:
    evidence: list[ControlAssessmentEvidence] = []
    for evaluation in evaluations:
        if ip_only and not evaluation.ip_requirement_applies:
            continue
        evidence.extend(
            evaluation.ip_requirement_evidence if ip_only else evaluation.evidence
        )
    for reason in reasons:
        evidence.append(
            ControlAssessmentEvidence(
                kind="unsupported",
                status="indeterminate",
                message=f"Sensitive location evidence boundary: {reason}.",
            )
        )
    return tuple(evidence)


def _assessment_metadata(
    *,
    entry: NginxSensitiveLocationEntry,
    server_scope: NginxScope,
    evaluations: tuple[_TargetEvaluation, ...],
    reasons: tuple[str, ...],
) -> dict[str, object]:
    first_evaluation = evaluations[0] if evaluations else None
    ordered_access_rules = [
        {
            "action": rule.action,
            "subject_kind": rule.subject_kind,
            "subject": rule.subject,
            "source": _source_payload(rule.source),
        }
        for evaluation in evaluations
        for rule in evaluation.control.address_rules
    ]
    return {
        "policy_section": _POLICY_SECTION,
        "catalog_entry_id": entry.entry_id,
        "server_scope_id": server_scope.scope_id,
        "declared_location": (
            {
                "modifier": entry.declared_location.modifier,
                "pattern": entry.declared_location.pattern,
                "source_path": entry.declared_location.source_path,
            }
            if entry.declared_location is not None
            else None
        ),
        "sample_uris": list(entry.sample_uris),
        "server_names": list(entry.server_names),
        "effective_satisfy": first_evaluation.control.satisfy if first_evaluation is not None else None,
        "protection_classification": (
            first_evaluation.control.classification
            if first_evaluation is not None
            else None
        ),
        "ordered_access_rules": ordered_access_rules,
        "indeterminate_reasons": list(reasons),
        "shadowed_samples": [
            evaluation.label
            for evaluation in evaluations
            if evaluation.shadowed and evaluation.label != "declared_location"
        ],
    }


def _route_evidence(
    *,
    status: str,
    message: str,
    scope: str,
    location: SourceSpan | None = None,
) -> ControlAssessmentEvidence:
    return ControlAssessmentEvidence(
        kind="route",
        status=status,
        message=message,
        locations=(_source_location(location),) if location is not None else (),
        effective_scope_id=scope,
    )


def _source_location(source: SourceSpan) -> SourceLocation:
    return SourceLocation(
        mode="local",
        kind="file",
        file_path=source.file_path,
        line=source.line,
    )


def _source_payload(source: SourceSpan | None) -> dict[str, object] | None:
    if source is None:
        return None
    return {
        "file_path": source.file_path,
        "line": source.line,
        "column": source.column,
    }


def _scope_server_names(server_scope: NginxScope, scope_graph: NginxScopeGraph) -> tuple[str, ...]:
    server_names: list[str] = []
    for node in scope_graph.scope_nodes.get(server_scope.scope_id, ()):
        if not isinstance(node, DirectiveNode) or node.name != "server_name":
            continue
        server_names.extend(node.args)
    return tuple(server_names)


def _requirement_requires_ip_allowlist(
    requirement: NginxSensitiveLocationRequirement,
) -> bool:
    if requirement.ip_allowlist is not None:
        return True
    if requirement.all_of:
        return any(
            _requirement_requires_ip_allowlist(child)
            for child in requirement.all_of
        )
    if requirement.one_of:
        return all(
            _requirement_requires_ip_allowlist(child)
            for child in requirement.one_of
        )
    return False


def _normalize_ip_or_cidr(value: str) -> str:
    if "/" in value:
        return str(ipaddress.ip_network(value, strict=True))
    ip_addr = ipaddress.ip_address(value)
    suffix = "/32" if ip_addr.version == 4 else "/128"
    return f"{ip_addr.compressed}{suffix}"


def _has_unresolved_internal_redirect(
    scope_graph: NginxScopeGraph,
    scope_id: str,
) -> bool:
    return any(
        isinstance(node, DirectiveNode)
        and node.name in {"rewrite", "try_files", "error_page"}
        for node in scope_graph.scope_nodes.get(scope_id, ())
    )


def _assessment_sort_key(assessment: PolicyControlAssessment) -> tuple[str, str, str]:
    return (
        str(assessment.scope.server_scope_id),
        str(assessment.scope.route_scope_id),
        assessment.control_id,
    )


__all__ = ["evaluate_sensitive_location_policy"]
