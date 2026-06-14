"""Policy-backed response-header and CSP assessments for Nginx."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable
from urllib.parse import urlsplit

from webconf_audit.csp_ast import CspDirective, CspDisposition, CspParsedHeaderValue, CspPolicy, parse_csp_header_value
from webconf_audit.header_policy import referrer_policy_is_safe
from webconf_audit.hsts_policy import hsts_policy_reason
from webconf_audit.local.nginx.effective_scope import NginxScope, NginxScopeGraph, NginxScopeKind
from webconf_audit.local.nginx.location_matcher import bind_declared_location, resolve_location_sample
from webconf_audit.local.nginx.parser.ast import ConfigAst, DirectiveNode, SourceSpan
from webconf_audit.local.nginx.response_header_semantics import (
    EffectiveResponseBranch,
    EffectiveResponseHeader,
    EffectiveResponseScope,
    NginxResponseHeaderSemantics,
    resolve_response_header_semantics,
)
from webconf_audit.models import (
    ControlAssessmentEvidence,
    ControlAssessmentScope,
    PolicyControlAssessment,
    SourceLocation,
)
from webconf_audit.policy_models import (
    NginxCspProfile,
    NginxHeaderValuePolicy,
    NginxHstsHeaderPolicy,
    NginxResponseHeaderProfile,
    NginxResponseHeaderRoute,
    NginxResponseHeadersPolicy,
)

_POLICY_SECTION = "nginx.response_headers"

_CONTROL_CSP = "cis-nginx-5.3.2.csp"
_CONTROL_REFERRER = "cis-nginx-5.3.3.referrer-policy"
_CONTROL_ASVS_CSP = "asvs-5.0.0-v3.4.3.csp-quality"
_CONTROL_ASVS_HSTS = "asvs-5.0.0-v3.4.1.hsts"
_CONTROL_ASVS_XCTO = "asvs-5.0.0-v3.4.4.x-content-type-options"
_CONTROL_ASVS_REFERRER = "asvs-5.0.0-v3.4.5.referrer-policy"
_CONTROL_ASVS_FRAME_ANCESTORS = "asvs-5.0.0-v3.4.6.frame-ancestors"
_CONTROL_ASVS_CSP_REPORTING = "asvs-5.0.0-v3.4.7.csp-reporting"
_CONTROL_ASVS_COOP = "asvs-5.0.0-v3.4.8.coop"


@dataclass(frozen=True)
class _SelectedRoute:
    route: NginxResponseHeaderRoute
    profile_id: str
    profile: NginxResponseHeaderProfile
    server_scope: NginxScope
    response_scope: NginxScope
    server_names: tuple[str, ...]
    selection_reasons: tuple[str, ...]


@dataclass(frozen=True)
class _HeaderEvaluationTarget:
    response_scope_id: str
    route_selector: str | None
    headers: tuple[EffectiveResponseHeader, ...]
    completeness_issues: tuple[str, ...]
    branch_id: str | None = None


def evaluate_response_header_policy(
    config_ast: ConfigAst,
    *,
    scope_graph: NginxScopeGraph,
    policy: NginxResponseHeadersPolicy | None,
    findings: Iterable[object] = (),
) -> list[PolicyControlAssessment]:
    if policy is None:
        return []

    semantics = resolve_response_header_semantics(config_ast, scope_graph=scope_graph)
    server_scopes = tuple(
        scope for scope in scope_graph.scopes if scope.kind == NginxScopeKind.SERVER
    )
    server_names_by_scope = {
        scope.scope_id: _scope_server_names(scope, scope_graph)
        for scope in server_scopes
    }
    all_findings = tuple(findings)
    assessments: list[PolicyControlAssessment] = []

    for route in policy.route_manifest:
        profile = policy.profiles.get(route.profile)
        if profile is None:
            continue
        matched_servers = [
            scope
            for scope in server_scopes
            if _server_matches_route(
                server_names=server_names_by_scope[scope.scope_id],
                route=route,
            )
        ]
        if not matched_servers:
            if policy.unmatched_routes == "not-applicable":
                continue
            assessments.extend(
                _unmatched_route_assessments(
                    route=route,
                    profile=profile,
                    status=policy.unmatched_routes,
                )
            )
            continue

        for server_scope in matched_servers:
            selected = _select_route_scope(
                scope_graph=scope_graph,
                server_scope=server_scope,
                route=route,
                profile=profile,
                server_names=server_names_by_scope[server_scope.scope_id],
            )
            if selected is None:
                if policy.unmatched_routes == "not-applicable":
                    continue
                assessments.extend(
                    _unmatched_route_assessments(
                        route=route,
                        profile=profile,
                        status=policy.unmatched_routes,
                    )
                )
                continue
            assessments.extend(
                _evaluate_selected_route(
                    selected=selected,
                    semantics=semantics,
                    unresolved_internal_redirects=policy.unresolved_internal_redirects,
                    findings=all_findings,
                    policy=policy,
                )
            )

    assessments.sort(key=_assessment_sort_key)
    return assessments


def _evaluate_selected_route(
    *,
    selected: _SelectedRoute,
    semantics: NginxResponseHeaderSemantics,
    unresolved_internal_redirects: str,
    findings: tuple[object, ...],
    policy: NginxResponseHeadersPolicy,
) -> list[PolicyControlAssessment]:
    effective_scope = semantics.effective_scopes_by_id[selected.response_scope.scope_id]
    targets = _evaluation_targets(
        route=selected.route,
        profile=selected.profile,
        server_scope=selected.server_scope,
        response_scope=selected.response_scope,
        effective_scope=effective_scope,
    )
    shared_metadata = _shared_metadata(
        selected=selected,
        semantics=semantics,
        targets=targets,
    )
    shared_indeterminate = set(selected.selection_reasons)
    if _route_has_unresolved_internal_redirect(semantics.scope_graph, selected.response_scope.scope_id):
        if unresolved_internal_redirects == "indeterminate":
            shared_indeterminate.add("unresolved-internal-redirect")
        elif unresolved_internal_redirects == "fail":
            shared_indeterminate.add("unresolved-internal-redirect-fail")

    assessments: list[PolicyControlAssessment] = []
    component_statuses: list[str] = []
    component_related: set[str] = set()

    if selected.profile.csp is not None:
        csp_control = _csp_enforcement_assessment(
            selected=selected,
            targets=targets,
            csp_profile=selected.profile.csp,
            metadata=shared_metadata,
            shared_indeterminate=shared_indeterminate,
            findings=findings,
        )
        assessments.append(csp_control)
        component_statuses.append(csp_control.status)
        component_related.update(csp_control.related_rule_ids)

        csp_quality = _csp_quality_assessment(
            selected=selected,
            targets=targets,
            csp_profile=selected.profile.csp,
            metadata=shared_metadata,
            shared_indeterminate=shared_indeterminate,
            findings=findings,
        )
        assessments.append(csp_quality)
        component_statuses.append(csp_quality.status)
        component_related.update(csp_quality.related_rule_ids)

        if selected.profile.csp.frame_ancestors is not None:
            frame_assessment = _frame_ancestors_assessment(
                selected=selected,
                targets=targets,
                csp_profile=selected.profile.csp,
                metadata=shared_metadata,
                shared_indeterminate=shared_indeterminate,
                findings=findings,
            )
            assessments.append(frame_assessment)
            component_statuses.append(frame_assessment.status)
            component_related.update(frame_assessment.related_rule_ids)

        if selected.profile.csp.reporting is not None:
            reporting_assessment = _csp_reporting_assessment(
                selected=selected,
                targets=targets,
                csp_profile=selected.profile.csp,
                metadata=shared_metadata,
                shared_indeterminate=shared_indeterminate,
                findings=findings,
                policy=policy,
            )
            assessments.append(reporting_assessment)
            component_statuses.append(reporting_assessment.status)
            component_related.update(reporting_assessment.related_rule_ids)

    headers = selected.profile.headers
    if headers.referrer_policy is not None:
        referrer_assessment = _single_value_header_assessment(
            control_id=_CONTROL_REFERRER,
            title="Ensure the Referrer Policy is enabled and configured properly",
            selected=selected,
            targets=targets,
            header_name="Referrer-Policy",
            expectation=headers.referrer_policy,
            metadata=shared_metadata,
            shared_indeterminate=shared_indeterminate,
            findings=findings,
            related_rule_pool=("nginx.missing_referrer_policy", "nginx.referrer_policy_unsafe"),
            validator=_referrer_policy_validator,
        )
        assessments.append(referrer_assessment)
        component_statuses.append(referrer_assessment.status)
        component_related.update(referrer_assessment.related_rule_ids)

        asvs_referrer = _single_value_header_assessment(
            control_id=_CONTROL_ASVS_REFERRER,
            title="Verify effective Referrer-Policy values",
            selected=selected,
            targets=targets,
            header_name="Referrer-Policy",
            expectation=headers.referrer_policy,
            metadata=shared_metadata,
            shared_indeterminate=shared_indeterminate,
            findings=findings,
            related_rule_pool=("nginx.missing_referrer_policy", "nginx.referrer_policy_unsafe"),
            validator=_referrer_policy_validator,
        )
        assessments.append(asvs_referrer)
        component_statuses.append(asvs_referrer.status)
        component_related.update(asvs_referrer.related_rule_ids)

    if headers.x_content_type_options is not None:
        xcto = _single_value_header_assessment(
            control_id=_CONTROL_ASVS_XCTO,
            title="Verify X-Content-Type-Options on responses",
            selected=selected,
            targets=targets,
            header_name="X-Content-Type-Options",
            expectation=headers.x_content_type_options,
            metadata=shared_metadata,
            shared_indeterminate=shared_indeterminate,
            findings=findings,
            related_rule_pool=("nginx.missing_x_content_type_options",),
            validator=_exact_single_value_validator,
        )
        assessments.append(xcto)
        component_statuses.append(xcto.status)
        component_related.update(xcto.related_rule_ids)

    if headers.strict_transport_security is not None:
        hsts = _hsts_assessment(
            selected=selected,
            targets=targets,
            expectation=headers.strict_transport_security,
            metadata=shared_metadata,
            shared_indeterminate=shared_indeterminate,
            findings=findings,
        )
        assessments.append(hsts)
        component_statuses.append(hsts.status)
        component_related.update(hsts.related_rule_ids)

    if headers.cross_origin_opener_policy is not None:
        coop = _single_value_header_assessment(
            control_id=_CONTROL_ASVS_COOP,
            title="Verify COOP on document-rendering responses",
            selected=selected,
            targets=targets,
            header_name="Cross-Origin-Opener-Policy",
            expectation=headers.cross_origin_opener_policy,
            metadata=shared_metadata,
            shared_indeterminate=shared_indeterminate,
            findings=findings,
            related_rule_pool=(),
            validator=_exact_single_value_validator,
        )
        assessments.append(coop)
        component_statuses.append(coop.status)
        component_related.update(coop.related_rule_ids)

    aggregate_status = (
        "indeterminate"
        if any(status == "indeterminate" for status in component_statuses)
        else "fail"
        if any(status == "fail" for status in component_statuses)
        else "pass"
    )
    assessments.append(
        PolicyControlAssessment(
            control_id=f"policy.nginx.response-headers.{selected.profile_id}",
            title=f"Response-header policy profile {selected.profile_id}",
            status=aggregate_status,  # type: ignore[arg-type]
            scope=_assessment_scope(selected),
            summary=(
                "The selected route satisfies the declared nginx.response_headers profile."
                if aggregate_status == "pass"
                else "The selected route does not satisfy the declared nginx.response_headers profile."
                if aggregate_status == "fail"
                else "The selected route could not be fully assessed against the declared nginx.response_headers profile."
            ),
            evidence=(),
            related_rule_ids=tuple(sorted(component_related)),
            policy_source=f"{_POLICY_SECTION}.{selected.profile_id}",
            metadata={**shared_metadata, "component_statuses": component_statuses},
        )
    )
    return assessments


def _csp_enforcement_assessment(
    *,
    selected: _SelectedRoute,
    targets: tuple[_HeaderEvaluationTarget, ...],
    csp_profile: NginxCspProfile,
    metadata: dict[str, object],
    shared_indeterminate: set[str],
    findings: tuple[object, ...],
) -> PolicyControlAssessment:
    failures: list[str] = []
    indeterminate = set(shared_indeterminate)
    evidence: list[ControlAssessmentEvidence] = []

    for target in targets:
        scoped = _scoped_csp_evidence(target)
        evidence.extend(scoped["evidence"])
        indeterminate.update(target.completeness_issues)
        if csp_profile.enforcement.required:
            enforcing = [
                parsed
                for parsed in scoped["enforcing"]
                if _csp_header_satisfies_expected_statuses(
                    target=target,
                    parsed=parsed,
                    expected_statuses=selected.route.expected_statuses,
                )
            ]
            if not enforcing:
                failures.append(f"missing-enforcing-csp:{target.response_scope_id}")
                continue
            if csp_profile.enforcement.additional_policies == "forbid" and len(enforcing) > 1:
                failures.append(f"forbidden-additional-enforcing-policy:{target.response_scope_id}")
            if csp_profile.enforcement.additional_policies == "require_parseable" and any(
                any(issue.fatal_for_structure for issue in parsed.issues)
                for parsed in enforcing
            ):
                indeterminate.add("additional-enforcing-policy-not-parseable")

    status = "indeterminate" if indeterminate else "fail" if failures else "pass"
    return _assessment(
        control_id=_CONTROL_CSP,
        title="Ensure that Content Security Policy (CSP) is enabled and configured properly",
        status=status,
        summary=(
            "Effective enforcing Content-Security-Policy headers satisfy the declared route contract."
            if status == "pass"
            else "Effective enforcing Content-Security-Policy headers do not satisfy the declared route contract."
            if status == "fail"
            else "Effective Content-Security-Policy evidence is incomplete or dynamically ambiguous."
        ),
        selected=selected,
        evidence=tuple(evidence),
        related_rule_ids=_related_rule_ids(
            findings,
            "nginx.missing_content_security_policy",
        ),
        metadata={**metadata, "failures": sorted(set(failures)), "indeterminate_reasons": sorted(indeterminate)},
    )


def _csp_quality_assessment(
    *,
    selected: _SelectedRoute,
    targets: tuple[_HeaderEvaluationTarget, ...],
    csp_profile: NginxCspProfile,
    metadata: dict[str, object],
    shared_indeterminate: set[str],
    findings: tuple[object, ...],
) -> PolicyControlAssessment:
    failures: list[str] = []
    indeterminate = set(shared_indeterminate)
    evidence: list[ControlAssessmentEvidence] = []

    for target in targets:
        scoped = _scoped_csp_evidence(target)
        evidence.extend(scoped["evidence"])
        enforcing = [
            parsed
            for parsed in scoped["enforcing"]
            if _csp_header_satisfies_expected_statuses(
                target=target,
                parsed=parsed,
                expected_statuses=selected.route.expected_statuses,
            )
        ]
        if not enforcing:
            failures.append(f"no-enforcing-csp:{target.response_scope_id}")
            continue

        if csp_profile.enforcement.additional_policies == "require_parseable" and any(
            any(issue.fatal_for_structure for issue in parsed.issues)
            for parsed in enforcing
        ):
            indeterminate.add("enforcing-csp-parse-issues")

        if not _required_directives_satisfied(
            enforcing=enforcing,
            baseline_policy=csp_profile.enforcement.baseline_policy,
            required_directives=csp_profile.required_directives,
        ):
            failures.append(f"required-directives:{target.response_scope_id}")

        script_result = _script_authorization_satisfied(
            enforcing=enforcing,
            csp_profile=csp_profile,
        )
        if script_result == "fail":
            failures.append(f"script-authorization:{target.response_scope_id}")
        elif script_result == "indeterminate":
            indeterminate.add("script-authorization")

        for capability in csp_profile.forbidden_effective_capabilities:
            if _effective_csp_capability_allowed(enforcing, capability):
                failures.append(f"forbidden-capability:{capability}:{target.response_scope_id}")

    status = "indeterminate" if indeterminate else "fail" if failures else "pass"
    return _assessment(
        control_id=_CONTROL_ASVS_CSP,
        title="Verify effective CSP minimum directives and script authorization",
        status=status,
        summary=(
            "Effective enforcing CSP satisfies the configured minimum directives and script authorization strategy."
            if status == "pass"
            else "Effective enforcing CSP does not satisfy the configured minimum directives or script authorization strategy."
            if status == "fail"
            else "Effective CSP quality could not be fully determined from static configuration."
        ),
        selected=selected,
        evidence=tuple(evidence),
        related_rule_ids=_related_rule_ids(
            findings,
            "nginx.content_security_policy_unsafe",
            "nginx.missing_content_security_policy",
        ),
        metadata={**metadata, "failures": sorted(set(failures)), "indeterminate_reasons": sorted(indeterminate)},
    )


def _frame_ancestors_assessment(
    *,
    selected: _SelectedRoute,
    targets: tuple[_HeaderEvaluationTarget, ...],
    csp_profile: NginxCspProfile,
    metadata: dict[str, object],
    shared_indeterminate: set[str],
    findings: tuple[object, ...],
) -> PolicyControlAssessment:
    failures: list[str] = []
    indeterminate = set(shared_indeterminate)
    evidence: list[ControlAssessmentEvidence] = []

    for target in targets:
        scoped = _scoped_csp_evidence(target)
        evidence.extend(scoped["evidence"])
        enforcing = [
            parsed
            for parsed in scoped["enforcing"]
            if _csp_header_satisfies_expected_statuses(
                target=target,
                parsed=parsed,
                expected_statuses=selected.route.expected_statuses,
            )
        ]
        if not enforcing:
            failures.append(f"no-enforcing-csp:{target.response_scope_id}")
            continue
        if csp_profile.frame_ancestors is not None and csp_profile.frame_ancestors.mode == "deny":
            if not any(_policy_denies_frame_ancestors(policy) for parsed in enforcing for policy in parsed.policies):
                failures.append(f"frame-ancestors:{target.response_scope_id}")

    status = "indeterminate" if indeterminate else "fail" if failures else "pass"
    return _assessment(
        control_id=_CONTROL_ASVS_FRAME_ANCESTORS,
        title="Verify CSP frame-ancestors for the selected response route",
        status=status,
        summary=(
            "Effective enforcing CSP provides frame-ancestors protections for the selected route."
            if status == "pass"
            else "Effective enforcing CSP does not provide the required frame-ancestors protections."
            if status == "fail"
            else "Effective frame-ancestors evidence is incomplete or dynamically ambiguous."
        ),
        selected=selected,
        evidence=tuple(evidence),
        related_rule_ids=_related_rule_ids(
            findings,
            "nginx.content_security_policy_missing_frame_ancestors",
        ),
        metadata={**metadata, "failures": sorted(set(failures)), "indeterminate_reasons": sorted(indeterminate)},
    )


def _csp_reporting_assessment(
    *,
    selected: _SelectedRoute,
    targets: tuple[_HeaderEvaluationTarget, ...],
    csp_profile: NginxCspProfile,
    metadata: dict[str, object],
    shared_indeterminate: set[str],
    findings: tuple[object, ...],
    policy: NginxResponseHeadersPolicy,
) -> PolicyControlAssessment:
    failures: list[str] = []
    indeterminate = set(shared_indeterminate)
    evidence: list[ControlAssessmentEvidence] = []

    for target in targets:
        scoped = _scoped_csp_evidence(target)
        evidence.extend(scoped["evidence"])
        enforcing = [
            parsed
            for parsed in scoped["enforcing"]
            if _csp_header_satisfies_expected_statuses(
                target=target,
                parsed=parsed,
                expected_statuses=selected.route.expected_statuses,
            )
        ]
        if not enforcing:
            failures.append(f"no-enforcing-csp:{target.response_scope_id}")
            continue
        if not _csp_reporting_satisfied(
            enforcing=enforcing,
            target=target,
            csp_profile=csp_profile,
            policy=policy,
        ):
            failures.append(f"reporting:{target.response_scope_id}")

    status = "indeterminate" if indeterminate else "fail" if failures else "pass"
    return _assessment(
        control_id=_CONTROL_ASVS_CSP_REPORTING,
        title="Verify CSP violation reporting configuration for the selected route",
        status=status,
        summary=(
            "Effective enforcing CSP reporting directives are linked to allowed visible endpoint declarations."
            if status == "pass"
            else "Effective enforcing CSP reporting directives are missing or not linked to allowed visible endpoint declarations."
            if status == "fail"
            else "Effective CSP reporting evidence is incomplete or dynamically ambiguous."
        ),
        selected=selected,
        evidence=tuple(evidence),
        related_rule_ids=_related_rule_ids(
            findings,
            "nginx.content_security_policy_missing_reporting_endpoint",
        ),
        metadata={**metadata, "failures": sorted(set(failures)), "indeterminate_reasons": sorted(indeterminate)},
    )


def _single_value_header_assessment(
    *,
    control_id: str,
    title: str,
    selected: _SelectedRoute,
    targets: tuple[_HeaderEvaluationTarget, ...],
    header_name: str,
    expectation: NginxHeaderValuePolicy,
    metadata: dict[str, object],
    shared_indeterminate: set[str],
    findings: tuple[object, ...],
    related_rule_pool: tuple[str, ...],
    validator,
) -> PolicyControlAssessment:
    failures: list[str] = []
    indeterminate = set(shared_indeterminate)
    evidence: list[ControlAssessmentEvidence] = []
    wanted = header_name.lower()

    for target in targets:
        values = [header for header in target.headers if header.normalized_name == wanted]
        if not values:
            failures.append(f"missing:{wanted}:{target.response_scope_id}")
            evidence.append(
                _header_presence_evidence(
                    header_name=header_name,
                    status="missing",
                    message=f"{header_name} is absent from the effective response headers.",
                )
            )
            continue
        if expectation.require_all_expected_statuses and not any(
            _header_covers_statuses(header, selected.route.expected_statuses)
            for header in values
        ):
            failures.append(f"status-coverage:{wanted}:{target.response_scope_id}")

        rendered = {_normalized_header_value(header.rendered_static_value) for header in values}
        if len(rendered) > 1:
            failures.append(f"conflicting-values:{wanted}:{target.response_scope_id}")

        verdict = validator(values, expectation)
        if verdict == "fail":
            failures.append(f"value:{wanted}:{target.response_scope_id}")
        elif verdict == "indeterminate":
            indeterminate.add(f"value:{wanted}")

        for header in values:
            evidence.append(
                _header_evidence(
                    header=header,
                    status="observed",
                    message=f"Observed effective {header_name} value.",
                )
            )

    status = "indeterminate" if indeterminate else "fail" if failures else "pass"
    return _assessment(
        control_id=control_id,
        title=title,
        status=status,
        summary=(
            f"Effective {header_name} satisfies the declared route policy."
            if status == "pass"
            else f"Effective {header_name} does not satisfy the declared route policy."
            if status == "fail"
            else f"Effective {header_name} evidence is incomplete or dynamically ambiguous."
        ),
        selected=selected,
        evidence=tuple(evidence),
        related_rule_ids=_related_rule_ids(findings, *related_rule_pool),
        metadata={**metadata, "header_name": header_name, "failures": sorted(set(failures)), "indeterminate_reasons": sorted(indeterminate)},
    )


def _hsts_assessment(
    *,
    selected: _SelectedRoute,
    targets: tuple[_HeaderEvaluationTarget, ...],
    expectation: NginxHstsHeaderPolicy,
    metadata: dict[str, object],
    shared_indeterminate: set[str],
    findings: tuple[object, ...],
) -> PolicyControlAssessment:
    failures: list[str] = []
    indeterminate = set(shared_indeterminate)
    evidence: list[ControlAssessmentEvidence] = []
    wanted = "strict-transport-security"

    if not any(scheme in expectation.required_on_schemes for scheme in selected.route.schemes):
        return _assessment(
            control_id=_CONTROL_ASVS_HSTS,
            title="Verify HSTS on HTTPS response routes",
            status="not-applicable",
            summary="HSTS is not required for the declared route schemes.",
            selected=selected,
            evidence=(),
            related_rule_ids=(),
            metadata={**metadata, "header_name": "Strict-Transport-Security"},
        )

    for target in targets:
        values = [header for header in target.headers if header.normalized_name == wanted]
        if not values:
            failures.append(f"missing:{wanted}:{target.response_scope_id}")
            continue
        if expectation.require_all_expected_statuses and not any(
            _header_covers_statuses(header, selected.route.expected_statuses)
            for header in values
        ):
            failures.append(f"status-coverage:{wanted}:{target.response_scope_id}")

        if len({_normalized_header_value(header.rendered_static_value) for header in values}) > 1:
            failures.append(f"conflicting-values:{wanted}:{target.response_scope_id}")
        for header in values:
            if header.dynamic_variables:
                indeterminate.add("dynamic-hsts-value")
                continue
            reason = hsts_policy_reason(
                header.rendered_static_value,
                require_include_subdomains=expectation.include_subdomains,
            )
            if reason is not None:
                failures.append(f"hsts:{reason}:{target.response_scope_id}")
            evidence.append(
                _header_evidence(
                    header=header,
                    status="observed",
                    message="Observed effective Strict-Transport-Security value.",
                )
            )

    status = "indeterminate" if indeterminate else "fail" if failures else "pass"
    return _assessment(
        control_id=_CONTROL_ASVS_HSTS,
        title="Verify HSTS on HTTPS response routes",
        status=status,
        summary=(
            "Effective Strict-Transport-Security satisfies the declared HTTPS route policy."
            if status == "pass"
            else "Effective Strict-Transport-Security does not satisfy the declared HTTPS route policy."
            if status == "fail"
            else "Effective Strict-Transport-Security evidence is incomplete or dynamically ambiguous."
        ),
        selected=selected,
        evidence=tuple(evidence),
        related_rule_ids=_related_rule_ids(
            findings,
            "nginx.missing_hsts_header",
            "nginx.hsts_header_unsafe",
        ),
        metadata={**metadata, "header_name": "Strict-Transport-Security", "failures": sorted(set(failures)), "indeterminate_reasons": sorted(indeterminate)},
    )


def _scoped_csp_evidence(target: _HeaderEvaluationTarget) -> dict[str, object]:
    enforcing: list[CspParsedHeaderValue] = []
    report_only: list[CspParsedHeaderValue] = []
    evidence: list[ControlAssessmentEvidence] = []
    for header in target.headers:
        if header.normalized_name not in {
            "content-security-policy",
            "content-security-policy-report-only",
        }:
            continue
        disposition = (
            CspDisposition.ENFORCE
            if header.normalized_name == "content-security-policy"
            else CspDisposition.REPORT
        )
        parsed = parse_csp_header_value(
            header.rendered_static_value,
            disposition=disposition,
        )
        if disposition == CspDisposition.ENFORCE:
            enforcing.append(parsed)
        else:
            report_only.append(parsed)
        evidence.append(
            _header_evidence(
                header=header,
                status=disposition.value,
                message=f"Observed effective {header.configured_name} value.",
            )
        )
    return {
        "enforcing": tuple(enforcing),
        "report_only": tuple(report_only),
        "evidence": evidence,
    }


def _required_directives_satisfied(
    *,
    enforcing: list[CspParsedHeaderValue],
    baseline_policy: str,
    required_directives: dict[str, tuple[str, ...]],
) -> bool:
    if not required_directives:
        return True
    policy_checks = [
        _policy_satisfies_required_directives(policy, required_directives)
        for parsed in enforcing
        for policy in parsed.policies
    ]
    if not policy_checks:
        return False
    if baseline_policy == "each_enforcing":
        return all(policy_checks)
    return any(policy_checks)


def _policy_satisfies_required_directives(
    policy: CspPolicy,
    required_directives: dict[str, tuple[str, ...]],
) -> bool:
    for directive_name, required_tokens in required_directives.items():
        directive = policy.first_directive(directive_name)
        if directive is None:
            return False
        normalized_tokens = tuple(token.normalized for token in directive.tokens)
        if tuple(required_tokens) != normalized_tokens:
            return False
    return True


def _script_authorization_satisfied(
    *,
    enforcing: list[CspParsedHeaderValue],
    csp_profile: NginxCspProfile,
) -> str:
    expectation = csp_profile.script_authorization
    if expectation is None:
        return "pass"

    directives = [
        directive
        for parsed in enforcing
        for policy in parsed.policies
        if (directive := _script_directive(policy)) is not None
    ]
    if expectation.mode == "allowlist" and len(directives) > 1:
        return "indeterminate"

    satisfied = False
    for directive in directives:
        if _directive_satisfies_script_authorization(directive, expectation):
            satisfied = True
            break
    return "pass" if satisfied else "fail"


def _directive_satisfies_script_authorization(
    directive: CspDirective,
    expectation,
) -> bool:
    tokens = directive.tokens
    has_nonce = any(
        token.kind.name == "NONCE"
        and (
            token.details.get("nonce_kind") == "dynamic_template"
            and set(token.details.get("variables", ())).issubset(set(expectation.allowed_nonce_variables))
            or token.details.get("nonce_kind") == "static_literal"
            and expectation.allow_static_nonce
        )
        for token in tokens
    )
    has_hash = any(
        token.kind.name == "HASH"
        and (
            not expectation.allowed_hashes
            or token.raw in set(expectation.allowed_hashes)
            or token.normalized in {value.lower() for value in expectation.allowed_hashes}
        )
        for token in tokens
    )
    has_strict_dynamic = any(token.normalized == "'strict-dynamic'" for token in tokens)
    if expectation.mode == "nonce":
        return has_nonce
    if expectation.mode == "hash":
        return has_hash
    if expectation.mode == "nonce_or_hash":
        return has_nonce or has_hash
    if expectation.mode == "strict_nonce_or_hash":
        return (has_nonce or has_hash) and (not expectation.require_strict_dynamic or has_strict_dynamic)
    if expectation.mode == "allowlist":
        return expectation.allow_host_allowlist_fallback and any(
            token.kind.name in {"HOST", "SCHEME"} or token.normalized == "'self'"
            for token in tokens
        )
    return False


def _effective_csp_capability_allowed(
    enforcing: list[CspParsedHeaderValue],
    capability: str,
) -> bool:
    if capability == "generic-unsafe-inline":
        token_name = "'unsafe-inline'"
    elif capability == "unsafe-eval":
        token_name = "'unsafe-eval'"
    else:
        return False
    policy_directives: list[CspDirective | None] = []
    for parsed in enforcing:
        for policy in parsed.policies:
            policy_directives.append(_script_directive(policy))
    if not policy_directives:
        return False
    return all(
        directive is not None
        and any(token.normalized == token_name for token in directive.tokens)
        for directive in policy_directives
    )


def _script_directive(policy: CspPolicy) -> CspDirective | None:
    return policy.first_directive("script-src") or policy.first_directive("default-src")


def _policy_denies_frame_ancestors(policy: CspPolicy) -> bool:
    directive = policy.first_directive("frame-ancestors")
    if directive is None:
        return False
    return tuple(token.normalized for token in directive.tokens) == ("'none'",)


def _csp_reporting_satisfied(
    *,
    enforcing: list[CspParsedHeaderValue],
    target: _HeaderEvaluationTarget,
    csp_profile: NginxCspProfile,
    policy: NginxResponseHeadersPolicy,
) -> bool:
    reporting = csp_profile.reporting
    assert reporting is not None
    reporting_headers = _reporting_endpoint_headers(target.headers)

    for parsed in enforcing:
        for policy_node in parsed.policies:
            report_uri = policy_node.first_directive("report-uri")
            if report_uri is not None and "report-uri" in reporting.modes:
                if any(_endpoint_allowed(token.raw, reporting, policy) for token in report_uri.tokens):
                    return True
            report_to = policy_node.first_directive("report-to")
            if report_to is not None and "report-to" in reporting.modes:
                group_names = {token.raw for token in report_to.tokens}
                for group in group_names:
                    if group not in set(reporting.allowed_groups):
                        continue
                    for url in reporting_headers.get(group, ()):
                        if _endpoint_allowed(url, reporting, policy, group=group):
                            return True
    return False


def _endpoint_allowed(
    url: str,
    reporting,
    policy: NginxResponseHeadersPolicy,
    *,
    group: str | None = None,
) -> bool:
    parts = urlsplit(url.strip().strip("\"'"))
    origin = f"{parts.scheme}://{parts.netloc}" if parts.scheme and parts.netloc else None
    if origin is None or origin not in set(reporting.allowed_endpoint_origins):
        return False
    if group is None:
        return True
    expected = policy.reporting_endpoints.get(group)
    if expected is None:
        return False
    return url.strip().strip("\"'") in set(expected.allowed_urls)


def _reporting_endpoint_headers(
    headers: tuple[EffectiveResponseHeader, ...],
) -> dict[str, tuple[str, ...]]:
    entries: dict[str, list[str]] = {}
    for header in headers:
        if header.normalized_name != "reporting-endpoints":
            continue
        for part in header.rendered_static_value.split(","):
            item = part.strip()
            if "=" not in item:
                continue
            group, _, raw_url = item.partition("=")
            entries.setdefault(group.strip(), []).append(raw_url.strip().strip("\"'"))
    return {group: tuple(values) for group, values in entries.items()}


def _csp_header_satisfies_expected_statuses(
    *,
    target: _HeaderEvaluationTarget,
    parsed: CspParsedHeaderValue,
    expected_statuses: tuple[int, ...],
) -> bool:
    matching_headers = [
        header
        for header in target.headers
        if header.normalized_name
        == (
            "content-security-policy"
            if parsed.disposition == CspDisposition.ENFORCE
            else "content-security-policy-report-only"
        )
        and header.rendered_static_value == parsed.raw_value
    ]
    return any(_header_covers_statuses(header, expected_statuses) for header in matching_headers)


def _header_covers_statuses(
    header: EffectiveResponseHeader,
    expected_statuses: tuple[int, ...],
) -> bool:
    if header.applicability.all_statuses:
        return True
    return set(expected_statuses).issubset(set(header.applicability.known_statuses))


def _exact_single_value_validator(
    headers: list[EffectiveResponseHeader],
    expectation: NginxHeaderValuePolicy,
) -> str:
    allowed = {_normalize_text(value) for value in expectation.allowed_values}
    values = {_normalize_text(_normalized_header_value(header.rendered_static_value)) for header in headers}
    if any(header.dynamic_variables for header in headers):
        return "indeterminate"
    return "pass" if values and values.issubset(allowed) else "fail"


def _referrer_policy_validator(
    headers: list[EffectiveResponseHeader],
    expectation: NginxHeaderValuePolicy,
) -> str:
    if any(header.dynamic_variables for header in headers):
        return "indeterminate"
    allowed = {_normalize_text(value) for value in expectation.allowed_values}
    normalized_values = {_normalized_referrer_policy_value(header.rendered_static_value) for header in headers}
    if None in normalized_values:
        return "fail"
    if not normalized_values:
        return "fail"
    return "pass" if normalized_values.issubset(allowed) else "fail"


def _normalized_referrer_policy_value(value: str) -> str | None:
    cleaned = _normalized_header_value(value).lower()
    if not referrer_policy_is_safe(cleaned) and "," not in cleaned:
        return cleaned if cleaned else None
    tokens = [token.strip() for token in cleaned.split(",") if token.strip()]
    return tokens[-1] if tokens else None


def _evaluation_targets(
    *,
    route: NginxResponseHeaderRoute,
    profile: NginxResponseHeaderProfile,
    server_scope: NginxScope,
    response_scope: NginxScope,
    effective_scope: EffectiveResponseScope,
) -> tuple[_HeaderEvaluationTarget, ...]:
    targets = [
        _HeaderEvaluationTarget(
            response_scope_id=response_scope.scope_id,
            route_selector=response_scope.selector,
            headers=effective_scope.base_headers,
            completeness_issues=effective_scope.indeterminate_reasons,
        )
    ]
    if profile.conditional_branches == "require_all":
        for branch in effective_scope.conditional_branches:
            if branch.condition_kind == "constant_false":
                continue
            targets.append(_branch_target(branch))
    return tuple(targets)


def _branch_target(branch: EffectiveResponseBranch) -> _HeaderEvaluationTarget:
    return _HeaderEvaluationTarget(
        response_scope_id=branch.parent_scope_id,
        route_selector=None,
        headers=branch.headers,
        completeness_issues=branch.indeterminate_reasons,
        branch_id=branch.branch_scope_id,
    )


def _shared_metadata(
    *,
    selected: _SelectedRoute,
    semantics: NginxResponseHeaderSemantics,
    targets: tuple[_HeaderEvaluationTarget, ...],
) -> dict[str, object]:
    return {
        "policy_section": _POLICY_SECTION,
        "route_id": selected.route.route_id,
        "profile_id": selected.profile_id,
        "server_scope_id": selected.server_scope.scope_id,
        "response_scope_id": selected.response_scope.scope_id,
        "response_kind": selected.route.response_kind,
        "schemes": list(selected.route.schemes),
        "expected_statuses": list(selected.route.expected_statuses),
        "selection_reasons": list(selected.selection_reasons),
        "effective_headers": [
            _header_payload(header, branch_id=target.branch_id)
            for target in targets
            for header in target.headers
        ],
        "unsupported_evidence": [
            {
                "reason": entry.reason,
                "directive_name": entry.directive_name,
                "scope_id": entry.scope_id,
                "source": _source_payload(entry.source),
            }
            for entry in semantics.unsupported_evidence
            if entry.scope_id in _scope_lineage_ids(selected.response_scope, semantics.scope_graph)
        ],
    }


def _header_payload(
    header: EffectiveResponseHeader,
    *,
    branch_id: str | None,
) -> dict[str, object]:
    return {
        "name": header.configured_name,
        "normalized_name": header.normalized_name,
        "rendered_value": header.rendered_static_value,
        "declared_scope_id": header.declared_scope_id,
        "effective_scope_id": header.effective_scope_id,
        "origin": header.origin,
        "always": header.always,
        "dynamic_variables": list(header.dynamic_variables),
        "applicability": {
            "all_statuses": header.applicability.all_statuses,
            "known_statuses": sorted(header.applicability.known_statuses),
            "conditional_branch_id": header.applicability.conditional_branch_id,
        },
        "branch_scope_id": branch_id,
        "source": _source_payload(header.source),
    }


def _assessment(
    *,
    control_id: str,
    title: str,
    status: str,
    summary: str,
    selected: _SelectedRoute,
    evidence: tuple[ControlAssessmentEvidence, ...],
    related_rule_ids: tuple[str, ...],
    metadata: dict[str, object],
) -> PolicyControlAssessment:
    return PolicyControlAssessment(
        control_id=control_id,
        title=title,
        status=status,  # type: ignore[arg-type]
        scope=_assessment_scope(selected),
        summary=summary,
        evidence=evidence,
        related_rule_ids=related_rule_ids,
        policy_source=f"{_POLICY_SECTION}.{selected.profile_id}",
        metadata=metadata,
    )


def _assessment_scope(selected: _SelectedRoute) -> ControlAssessmentScope:
    return ControlAssessmentScope(
        server_scope_id=selected.server_scope.scope_id,
        route_scope_id=selected.response_scope.scope_id,
        route_selector=selected.response_scope.selector,
        server_name=selected.server_names[0] if selected.server_names else None,
    )


def _server_matches_route(
    *,
    server_names: tuple[str, ...],
    route: NginxResponseHeaderRoute,
) -> bool:
    wanted = {name.lower() for name in route.server_names}
    actual = {name.lower() for name in server_names}
    return bool(wanted & actual)


def _select_route_scope(
    *,
    scope_graph: NginxScopeGraph,
    server_scope: NginxScope,
    route: NginxResponseHeaderRoute,
    profile: NginxResponseHeaderProfile,
    server_names: tuple[str, ...],
) -> _SelectedRoute | None:
    selected_scope: NginxScope | None = None
    matched_any = False
    reasons: set[str] = set()
    if route.declared_location is not None:
        binding = bind_declared_location(
            scope_graph=scope_graph,
            server_scope_id=server_scope.scope_id,
            selector=route.declared_location,
        )
        if binding.status == "selected" and binding.selected_scope is not None:
            selected_scope = binding.selected_scope
            matched_any = True
        else:
            reasons.update(binding.indeterminate_reasons or (binding.status,))
    for sample_uri in route.sample_uris:
        resolution = resolve_location_sample(
            scope_graph=scope_graph,
            server_scope_id=server_scope.scope_id,
            sample_uri=sample_uri,
        )
        if resolution.status == "selected" and resolution.selected_scope is not None:
            if selected_scope is not None and selected_scope.scope_id != resolution.selected_scope.scope_id:
                reasons.add("route-manifest-scope-mismatch")
            selected_scope = selected_scope or resolution.selected_scope
            matched_any = True
        else:
            reasons.update(resolution.indeterminate_reasons or (resolution.status,))
    if route.declared_location is None and not route.sample_uris and selected_scope is None:
        selected_scope = server_scope
    if selected_scope is None and not matched_any:
        return None
    return _SelectedRoute(
        route=route,
        profile_id=route.profile,
        profile=profile,
        server_scope=server_scope,
        response_scope=selected_scope,
        server_names=server_names,
        selection_reasons=tuple(sorted(reasons)),
    )


def _unmatched_route_assessments(
    *,
    route: NginxResponseHeaderRoute,
    profile: NginxResponseHeaderProfile,
    status: str,
) -> list[PolicyControlAssessment]:
    pseudo_scope = ControlAssessmentScope(
        server_scope_id=f"policy-route:{route.route_id}",
        route_scope_id=f"policy-route:{route.route_id}",
        route_selector=route.declared_location.pattern if route.declared_location is not None else None,
        server_name=route.server_names[0] if route.server_names else None,
    )
    control_ids = [
        _CONTROL_CSP,
        _CONTROL_ASVS_CSP,
        _CONTROL_ASVS_FRAME_ANCESTORS,
        _CONTROL_ASVS_CSP_REPORTING,
        _CONTROL_REFERRER,
        _CONTROL_ASVS_REFERRER,
        _CONTROL_ASVS_HSTS,
        _CONTROL_ASVS_XCTO,
        _CONTROL_ASVS_COOP,
        f"policy.nginx.response-headers.{route.profile}",
    ]
    return [
        PolicyControlAssessment(
            control_id=control_id,
            title=control_id,
            status=status,  # type: ignore[arg-type]
            scope=pseudo_scope,
            summary="The route manifest entry did not match any reachable nginx response scope.",
            evidence=(),
            related_rule_ids=(),
            policy_source=f"{_POLICY_SECTION}.{route.profile}",
            metadata={
                "policy_section": _POLICY_SECTION,
                "route_id": route.route_id,
                "profile_id": route.profile,
                "server_scope_id": pseudo_scope.server_scope_id,
                "response_scope_id": pseudo_scope.route_scope_id,
                "response_kind": route.response_kind,
                "schemes": list(route.schemes),
                "expected_statuses": list(route.expected_statuses),
                "selection_reasons": ["unmatched-route"],
                "effective_headers": [],
                "unsupported_evidence": [],
            },
        )
        for control_id in control_ids
    ]


def _header_evidence(
    *,
    header: EffectiveResponseHeader,
    status: str,
    message: str,
) -> ControlAssessmentEvidence:
    return ControlAssessmentEvidence(
        kind="response-header",
        status=status,
        message=message,
        header_name=header.configured_name,
        locations=(_source_location(header.source),),
        declared_scope_id=header.declared_scope_id,
        effective_scope_id=header.effective_scope_id,
        values=(header.rendered_static_value,),
    )


def _header_presence_evidence(
    *,
    header_name: str,
    status: str,
    message: str,
) -> ControlAssessmentEvidence:
    return ControlAssessmentEvidence(
        kind="response-header",
        status=status,
        message=message,
        header_name=header_name,
    )


def _related_rule_ids(findings: tuple[object, ...], *rule_ids: str) -> tuple[str, ...]:
    present = set()
    for finding in findings:
        rule_id = getattr(finding, "rule_id", None)
        if rule_id in rule_ids:
            present.add(rule_id)
    return tuple(sorted(present))


def _scope_server_names(server_scope: NginxScope, scope_graph: NginxScopeGraph) -> tuple[str, ...]:
    server_names: list[str] = []
    for node in scope_graph.scope_nodes.get(server_scope.scope_id, ()):
        if not isinstance(node, DirectiveNode) or node.name != "server_name":
            continue
        server_names.extend(node.args)
    return tuple(server_names)


def _route_has_unresolved_internal_redirect(
    scope_graph: NginxScopeGraph,
    scope_id: str,
) -> bool:
    return any(
        isinstance(node, DirectiveNode)
        and node.name in {"rewrite", "try_files", "error_page"}
        for node in scope_graph.scope_nodes.get(scope_id, ())
    )


def _scope_lineage_ids(scope: NginxScope, scope_graph: NginxScopeGraph) -> set[str]:
    scope_ids: set[str] = set()
    current: NginxScope | None = scope
    while current is not None:
        scope_ids.add(current.scope_id)
        current = (
            scope_graph.scopes_by_id.get(current.parent_id)
            if current.parent_id is not None
            else None
        )
    return scope_ids


def _normalized_header_value(value: str) -> str:
    cleaned = value.strip()
    if len(cleaned) >= 2 and cleaned[0] == cleaned[-1] and cleaned[0] in {"'", '"'}:
        cleaned = cleaned[1:-1].strip()
    return cleaned


def _normalize_text(value: str) -> str:
    return " ".join(value.strip().split())


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


def _assessment_sort_key(entry: PolicyControlAssessment) -> tuple[str, str, str]:
    return (
        str(entry.scope.server_scope_id),
        str(entry.scope.route_scope_id),
        entry.control_id,
    )


__all__ = ["evaluate_response_header_policy"]
