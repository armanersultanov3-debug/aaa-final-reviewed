"""Policy-backed reverse-proxy header assessments for Nginx."""

from __future__ import annotations

from typing import Iterable

from webconf_audit.local.nginx.effective_scope import NginxScopeGraph
from webconf_audit.local.nginx.parser.ast import ConfigAst, SourceSpan
from webconf_audit.local.nginx.proxy_headers import (
    EffectiveHeaderValue,
    ProxyHeaderResolution,
    ProxyRoute,
    RouteContext,
    UnsupportedEvidence,
    UnsupportedProxyRoute,
    all_route_resolutions,
    expression_has_variables,
    header_values_by_name,
    response_filter_map,
    route_context,
)
from webconf_audit.local.nginx.rules._variable_taint_utils import TaintAnalyzer, extract_variables
from webconf_audit.models import (
    ControlAssessmentEvidence,
    ControlAssessmentScope,
    PolicyControlAssessment,
    SourceLocation,
)
from webconf_audit.policy_models import (
    NginxReverseProxyHeadersPolicy,
    ReverseProxyHeaderProfile,
)

_POLICY_SECTION = "nginx.reverse_proxy_headers"
_CONTROL_ID_SOURCE_IDENTITY = "cis-nginx-3.4.proxy-source-identity"
_CONTROL_ID_RESPONSE_DISCLOSURE = "cis-nginx-2.5.4.proxy-response-disclosure"
_CONTROL_ID_HOST_POLICY = "policy.nginx.reverse-proxy-host"

_TITLE_SOURCE_IDENTITY = "Ensure proxies pass source IP information"
_TITLE_RESPONSE_DISCLOSURE = (
    "Ensure the NGINX reverse proxy does not enable information disclosure"
)
_TITLE_HOST_POLICY = "Reverse-proxy Host trust contract"


def evaluate_reverse_proxy_header_policy(
    config_ast: ConfigAst,
    *,
    scope_graph: NginxScopeGraph,
    policy: NginxReverseProxyHeadersPolicy | None,
    findings: Iterable[object] = (),
) -> list[PolicyControlAssessment]:
    if policy is None:
        return []

    resolutions, unsupported_routes = all_route_resolutions(config_ast, scope_graph)
    analyzer = TaintAnalyzer(config_ast)
    all_findings = tuple(findings)
    assessments: list[PolicyControlAssessment] = []
    any_host_policy = any(
        profile.request_headers.host is not None
        for profile in policy.profiles
    )

    for resolution in resolutions:
        context = route_context(resolution.route, scope_graph)
        matched = _matched_profiles(policy, context)
        if not matched:
            if policy.unmatched_routes == "not-applicable":
                continue
            assessments.extend(
                _unmatched_route_assessments(
                    resolution.route,
                    context=context,
                    status=policy.unmatched_routes,
                    include_host=any_host_policy,
                )
            )
            continue

        profile = matched[0]
        assessments.append(
            _source_identity_assessment(
                resolution,
                context=context,
                profile=profile,
                findings=all_findings,
            )
        )
        assessments.append(
            _response_disclosure_assessment(
                resolution,
                context=context,
                profile=profile,
                findings=all_findings,
            )
        )
        if profile.request_headers.host is not None:
            assessments.append(
                _host_policy_assessment(
                    resolution,
                    context=context,
                    profile=profile,
                    findings=all_findings,
                    analyzer=analyzer,
                )
            )

    for unsupported_route in unsupported_routes:
        context = _unsupported_route_context(unsupported_route, scope_graph)
        matched = _matched_profiles_for_unsupported(policy, context)
        if not matched:
            continue
        profile = matched[0]
        assessments.extend(
            _unsupported_route_assessments(
                unsupported_route,
                context=context,
                profile=profile,
            )
        )

    return assessments


def _matched_profiles(
    policy: NginxReverseProxyHeadersPolicy,
    context: RouteContext,
) -> list[ReverseProxyHeaderProfile]:
    matches = [
        profile
        for profile in policy.profiles
        if _profile_matches(profile, context)
    ]
    matches.sort(key=lambda profile: profile.profile_id)
    return matches


def _matched_profiles_for_unsupported(
    policy: NginxReverseProxyHeadersPolicy,
    context: RouteContext,
) -> list[ReverseProxyHeaderProfile]:
    matches = []
    for profile in policy.profiles:
        if profile.applies_to.upstream_families:
            continue
        if _selector_server_mismatch(profile, context):
            continue
        if _selector_location_mismatch(profile, context):
            continue
        matches.append(profile)
    matches.sort(key=lambda profile: profile.profile_id)
    return matches


def _profile_matches(
    profile: ReverseProxyHeaderProfile,
    context: RouteContext,
) -> bool:
    if profile.applies_to.upstream_families and (
        context.route.upstream_family not in profile.applies_to.upstream_families
    ):
        return False
    if _selector_server_mismatch(profile, context):
        return False
    if _selector_location_mismatch(profile, context):
        return False
    return True


def _selector_server_mismatch(
    profile: ReverseProxyHeaderProfile,
    context: RouteContext,
) -> bool:
    if not profile.applies_to.server_names:
        return False
    profile_names = {name.lower() for name in profile.applies_to.server_names}
    route_names = {name.lower() for name in context.server_names}
    return not bool(profile_names & route_names)


def _selector_location_mismatch(
    profile: ReverseProxyHeaderProfile,
    context: RouteContext,
) -> bool:
    if not profile.applies_to.location_patterns:
        return False
    if context.location_scope is None or context.location_scope.selector is None:
        return True
    selector = _normalize_text(context.location_scope.selector)
    return selector not in {
        _normalize_text(pattern)
        for pattern in profile.applies_to.location_patterns
    }


def _source_identity_assessment(
    resolution: ProxyHeaderResolution,
    *,
    context: RouteContext,
    profile: ReverseProxyHeaderProfile,
    findings: tuple[object, ...],
) -> PolicyControlAssessment:
    header_map = header_values_by_name(resolution.request_headers)
    evidence: list[ControlAssessmentEvidence] = []
    failed = False
    indeterminate = bool(resolution.indeterminate_reasons)

    for header_name, requirement in profile.request_headers.required.items():
        normalized_name = _normalize_header_name(header_name)
        entries = header_map.get(normalized_name, ())
        allowed_values = {_normalize_text(value) for value in requirement.any_of}
        result = _evaluate_header_requirement(
            entries,
            required_name=header_name,
            allowed_values=allowed_values,
            forbidden_variables={
                variable.lower()
                for variable in profile.request_headers.forbidden_client_variables
            },
        )
        evidence.extend(result["evidence"])
        failed = failed or result["status"] == "fail"
        indeterminate = indeterminate or result["status"] == "indeterminate"

    evidence.extend(_unsupported_evidence_payloads(resolution.unsupported_evidence))
    status = "indeterminate" if indeterminate else "fail" if failed else "pass"
    summary = (
        "Effective request-header evidence is incomplete or dynamically ambiguous."
        if status == "indeterminate"
        else "One or more required trusted source headers are missing or unsafe."
        if status == "fail"
        else "Effective request headers satisfy the declared trusted source identity contract."
    )
    return _assessment(
        control_id=_CONTROL_ID_SOURCE_IDENTITY,
        title=_TITLE_SOURCE_IDENTITY,
        status=status,
        summary=summary,
        context=context,
        profile=profile,
        evidence=evidence,
        related_rule_ids=_related_rule_ids(findings, "nginx.proxy_missing_source_ip_headers"),
        resolution=resolution,
    )


def _response_disclosure_assessment(
    resolution: ProxyHeaderResolution,
    *,
    context: RouteContext,
    profile: ReverseProxyHeaderProfile,
    findings: tuple[object, ...],
) -> PolicyControlAssessment:
    filter_map = response_filter_map(resolution.response_header_filters)
    evidence: list[ControlAssessmentEvidence] = []
    failed = False
    indeterminate = bool(resolution.indeterminate_reasons)

    for header_name in profile.response_headers.must_hide:
        normalized_name = _normalize_header_name(header_name)
        disposition = filter_map.get(normalized_name, "not_filtered")
        evidence.append(
            ControlAssessmentEvidence(
                kind="response-header",
                status=disposition,
                message=f"{header_name} must be hidden.",
                header_name=header_name,
                values=(disposition,),
            )
        )
        if disposition != "hidden":
            failed = True

    allowed_pass = {
        _normalize_header_name(header)
        for header in profile.response_headers.allow_explicit_pass
    }
    for header_name in profile.response_headers.must_not_pass:
        normalized_name = _normalize_header_name(header_name)
        disposition = filter_map.get(normalized_name, "not_filtered")
        evidence.append(
            ControlAssessmentEvidence(
                kind="response-header",
                status=disposition,
                message=f"{header_name} must not be explicitly passed.",
                header_name=header_name,
                values=(disposition,),
            )
        )
        if disposition == "passed" and normalized_name not in allowed_pass:
            failed = True
        elif disposition == "not_filtered":
            failed = True

    evidence.extend(_unsupported_evidence_payloads(resolution.unsupported_evidence))
    status = "indeterminate" if indeterminate else "fail" if failed else "pass"
    summary = (
        "Effective response-header filtering evidence is incomplete or dynamically ambiguous."
        if status == "indeterminate"
        else "One or more backend disclosure headers are not statically hidden by configuration."
        if status == "fail"
        else "Effective response-header filtering satisfies the declared disclosure policy."
    )
    return _assessment(
        control_id=_CONTROL_ID_RESPONSE_DISCLOSURE,
        title=_TITLE_RESPONSE_DISCLOSURE,
        status=status,
        summary=summary,
        context=context,
        profile=profile,
        evidence=evidence,
        related_rule_ids=(),
        resolution=resolution,
    )


def _host_policy_assessment(
    resolution: ProxyHeaderResolution,
    *,
    context: RouteContext,
    profile: ReverseProxyHeaderProfile,
    findings: tuple[object, ...],
    analyzer: TaintAnalyzer,
) -> PolicyControlAssessment:
    host_policy = profile.request_headers.host
    assert host_policy is not None
    header_map = header_values_by_name(resolution.request_headers)
    host_entries = header_map.get("host", ())
    evidence: list[ControlAssessmentEvidence] = []
    failed = False
    indeterminate = bool(resolution.indeterminate_reasons)
    forbidden_variables = {
        variable.lower()
        for variable in profile.request_headers.forbidden_client_variables
    }
    allowed_values = {
        _normalize_text(value)
        for value in host_policy.allowed_values
    }

    set_entries = [entry for entry in host_entries if entry.disposition == "set"]
    if not set_entries:
        failed = True
        evidence.append(
            ControlAssessmentEvidence(
                kind="request-header",
                status="missing",
                message="No effective Host value is forwarded to the upstream.",
                header_name="Host",
            )
        )
    for entry in set_entries:
        normalized_value = _normalize_text(entry.rendered_value)
        variables = {variable.lower() for variable in extract_variables(entry.rendered_value)}
        if variables & forbidden_variables:
            failed = True
            evidence.append(
                _header_evidence(
                    entry,
                    status="forbidden-variable",
                    message="Host value contains a forbidden client-controlled variable.",
                )
            )
            continue
        if normalized_value in allowed_values:
            evidence.append(
                _header_evidence(
                    entry,
                    status="allowed",
                    message="Host value matches an allowlisted exact expression.",
                )
            )
            continue
        if not variables and host_policy.allow_fixed_literals:
            evidence.append(
                _header_evidence(
                    entry,
                    status="allowed-fixed-literal",
                    message="Fixed literal Host value is permitted by policy.",
                )
            )
            continue
        if analyzer.value_contains_user_controlled(entry.rendered_value, context.location_scope.block if context.location_scope else context.server_scope.block):
            failed = True
            evidence.append(
                _header_evidence(
                    entry,
                    status="untrusted",
                    message="Host value flows from request-controlled input.",
                )
            )
            continue
        if variables:
            indeterminate = True
            evidence.append(
                _header_evidence(
                    entry,
                    status="dynamic",
                    message="Host value is dynamic and not explicitly allowlisted.",
                )
            )
            continue
        failed = True
        evidence.append(
            _header_evidence(
                entry,
                status="disallowed",
                message="Host value is not permitted by the declared policy.",
            )
        )

    evidence.extend(_unsupported_evidence_payloads(resolution.unsupported_evidence))
    status = "indeterminate" if indeterminate else "fail" if failed else "pass"
    summary = (
        "Host forwarding evidence is incomplete or dynamically ambiguous."
        if status == "indeterminate"
        else "The effective Host value violates the declared reverse-proxy trust contract."
        if status == "fail"
        else "The effective Host value satisfies the declared reverse-proxy trust contract."
    )
    return _assessment(
        control_id=_CONTROL_ID_HOST_POLICY,
        title=_TITLE_HOST_POLICY,
        status=status,
        summary=summary,
        context=context,
        profile=profile,
        evidence=evidence,
        related_rule_ids=_related_rule_ids(findings, "nginx.proxy_set_header_host_spoofing"),
        resolution=resolution,
    )


def _evaluate_header_requirement(
    entries: tuple[EffectiveHeaderValue, ...],
    *,
    required_name: str,
    allowed_values: set[str],
    forbidden_variables: set[str],
) -> dict[str, object]:
    evidence: list[ControlAssessmentEvidence] = []
    if not entries:
        evidence.append(
            ControlAssessmentEvidence(
                kind="request-header",
                status="missing",
                message=f"{required_name} is not present in the effective header list.",
                header_name=required_name,
            )
        )
        return {"status": "fail", "evidence": evidence}

    set_entries = [entry for entry in entries if entry.disposition == "set"]
    if not set_entries:
        for entry in entries:
            evidence.append(
                _header_evidence(
                    entry,
                    status="removed",
                    message=f"{required_name} is explicitly removed.",
                )
            )
        return {"status": "fail", "evidence": evidence}

    for entry in set_entries:
        variables = {variable.lower() for variable in extract_variables(entry.rendered_value)}
        if variables & forbidden_variables:
            evidence.append(
                _header_evidence(
                    entry,
                    status="forbidden-variable",
                    message=f"{required_name} contains a forbidden client-controlled variable.",
                )
            )
            return {"status": "fail", "evidence": evidence}

    allowed_matches = [
        entry
        for entry in set_entries
        if _normalize_text(entry.rendered_value) in allowed_values
    ]
    if allowed_matches and len(allowed_matches) == len(set_entries):
        for entry in allowed_matches:
            evidence.append(
                _header_evidence(
                    entry,
                    status="allowed",
                    message=f"{required_name} matches an allowlisted exact expression.",
                )
            )
        return {"status": "pass", "evidence": evidence}

    for entry in set_entries:
        if expression_has_variables(entry.rendered_value):
            evidence.append(
                _header_evidence(
                    entry,
                    status="dynamic",
                    message=f"{required_name} is dynamic and not explicitly allowlisted.",
                )
            )
            return {"status": "indeterminate", "evidence": evidence}

    for entry in set_entries:
        evidence.append(
            _header_evidence(
                entry,
                status="disallowed",
                message=f"{required_name} does not match an allowlisted exact expression.",
            )
        )
    return {"status": "fail", "evidence": evidence}


def _unsupported_route_assessments(
    unsupported_route: UnsupportedProxyRoute,
    *,
    context: RouteContext,
    profile: ReverseProxyHeaderProfile,
) -> list[PolicyControlAssessment]:
    evidence = (
        ControlAssessmentEvidence(
            kind="unsupported",
            status=unsupported_route.reason,
            message="Unsupported upstream module cannot be evaluated safely.",
            locations=(_source_location(unsupported_route.directive.source),),
        ),
    )
    assessments = [
        _bare_assessment(
            control_id=_CONTROL_ID_SOURCE_IDENTITY,
            title=_TITLE_SOURCE_IDENTITY,
            status="indeterminate",
            summary="The route uses an unsupported upstream module and cannot be assessed safely.",
            context=context,
            profile=profile,
            evidence=evidence,
            upstream_family=unsupported_route.directive.name.removesuffix("_pass"),
            route_scope_id=unsupported_route.scope_id,
        ),
        _bare_assessment(
            control_id=_CONTROL_ID_RESPONSE_DISCLOSURE,
            title=_TITLE_RESPONSE_DISCLOSURE,
            status="indeterminate",
            summary="The route uses an unsupported upstream module and cannot be assessed safely.",
            context=context,
            profile=profile,
            evidence=evidence,
            upstream_family=unsupported_route.directive.name.removesuffix("_pass"),
            route_scope_id=unsupported_route.scope_id,
        ),
    ]
    if profile.request_headers.host is not None:
        assessments.append(
            _bare_assessment(
                control_id=_CONTROL_ID_HOST_POLICY,
                title=_TITLE_HOST_POLICY,
                status="indeterminate",
                summary="The route uses an unsupported upstream module and cannot be assessed safely.",
                context=context,
                profile=profile,
                evidence=evidence,
                upstream_family=unsupported_route.directive.name.removesuffix("_pass"),
                route_scope_id=unsupported_route.scope_id,
            )
        )
    return assessments


def _unmatched_route_assessments(
    route: ProxyRoute,
    *,
    context: RouteContext,
    status: str,
    include_host: bool,
) -> list[PolicyControlAssessment]:
    assessments = [
        _bare_assessment(
            control_id=_CONTROL_ID_SOURCE_IDENTITY,
            title=_TITLE_SOURCE_IDENTITY,
            status=status,
            summary="The route did not match any nginx.reverse_proxy_headers profile.",
            context=context,
            profile=None,
            evidence=(),
            upstream_family=route.upstream_family,
            route_scope_id=route.scope_id,
        ),
        _bare_assessment(
            control_id=_CONTROL_ID_RESPONSE_DISCLOSURE,
            title=_TITLE_RESPONSE_DISCLOSURE,
            status=status,
            summary="The route did not match any nginx.reverse_proxy_headers profile.",
            context=context,
            profile=None,
            evidence=(),
            upstream_family=route.upstream_family,
            route_scope_id=route.scope_id,
        ),
    ]
    if include_host:
        assessments.append(
            _bare_assessment(
                control_id=_CONTROL_ID_HOST_POLICY,
                title=_TITLE_HOST_POLICY,
                status=status,
                summary="The route did not match any nginx.reverse_proxy_headers profile.",
                context=context,
                profile=None,
                evidence=(),
                upstream_family=route.upstream_family,
                route_scope_id=route.scope_id,
            )
        )
    return assessments


def _assessment(
    *,
    control_id: str,
    title: str,
    status: str,
    summary: str,
    context: RouteContext,
    profile: ReverseProxyHeaderProfile,
    evidence: list[ControlAssessmentEvidence],
    related_rule_ids: tuple[str, ...],
    resolution: ProxyHeaderResolution,
) -> PolicyControlAssessment:
    return _bare_assessment(
        control_id=control_id,
        title=title,
        status=status,
        summary=summary,
        context=context,
        profile=profile,
        evidence=tuple(evidence),
        related_rule_ids=related_rule_ids,
        upstream_family=resolution.route.upstream_family,
        route_scope_id=resolution.route.scope_id,
        metadata={
            "policy_section": _POLICY_SECTION,
            "server_scope_id": context.server_scope.scope_id,
            "route_scope_id": resolution.route.scope_id,
            "upstream_family": resolution.route.upstream_family,
            "profile_id": profile.profile_id,
            "effective_request_headers": [
                {
                    "name": entry.configured_name,
                    "normalized_name": entry.normalized_name,
                    "rendered_value": entry.rendered_value,
                    "declared_scope_id": entry.declared_scope_id,
                    "effective_scope_id": entry.effective_scope_id,
                    "origin": entry.origin,
                    "disposition": entry.disposition,
                    "source": {
                        "file_path": entry.source.file_path,
                        "line": entry.source.line,
                        "column": entry.source.column,
                    },
                }
                for entry in resolution.request_headers
            ],
            "effective_response_header_filters": [
                {
                    "name": entry.normalized_name,
                    "disposition": entry.disposition,
                }
                for entry in resolution.response_header_filters
            ],
            "unsupported_or_dynamic_evidence": [
                {
                    "kind": entry.kind,
                    "reason": entry.reason,
                    "scope_id": entry.scope_id,
                    "header_name": entry.header_name,
                    "source": {
                        "file_path": entry.source.file_path,
                        "line": entry.source.line,
                        "column": entry.source.column,
                    },
                }
                for entry in resolution.unsupported_evidence
            ],
        },
    )


def _bare_assessment(
    *,
    control_id: str,
    title: str,
    status: str,
    summary: str,
    context: RouteContext,
    profile: ReverseProxyHeaderProfile | None,
    evidence: tuple[ControlAssessmentEvidence, ...],
    upstream_family: str,
    route_scope_id: str,
    related_rule_ids: tuple[str, ...] = (),
    metadata: dict[str, object] | None = None,
) -> PolicyControlAssessment:
    return PolicyControlAssessment(
        control_id=control_id,
        title=title,
        status=status,  # type: ignore[arg-type]
        scope=ControlAssessmentScope(
            server_scope_id=context.server_scope.scope_id,
            route_scope_id=route_scope_id,
            route_selector=context.location_scope.selector if context.location_scope else None,
            server_name=context.server_names[0] if context.server_names else None,
        ),
        summary=summary,
        evidence=evidence,
        related_rule_ids=related_rule_ids,
        policy_source=_POLICY_SECTION if profile is None else f"{_POLICY_SECTION}.{profile.profile_id}",
        metadata=metadata
        or {
            "policy_section": _POLICY_SECTION,
            "server_scope_id": context.server_scope.scope_id,
            "route_scope_id": route_scope_id,
            "upstream_family": upstream_family,
            "profile_id": profile.profile_id if profile is not None else None,
            "effective_request_headers": [],
            "effective_response_header_filters": [],
            "unsupported_or_dynamic_evidence": [],
        },
    )


def _unsupported_route_context(
    unsupported_route: UnsupportedProxyRoute,
    scope_graph: NginxScopeGraph,
) -> RouteContext:
    pseudo_route = ProxyRoute(
        route_id=f"{unsupported_route.scope_id}:{unsupported_route.directive.name}:{unsupported_route.directive.source.line}",
        scope_id=unsupported_route.scope_id,
        upstream_family="proxy",
        pass_directive=unsupported_route.directive,
        destination_tokens=tuple(unsupported_route.directive.args),
        destination_kind="literal",
    )
    return route_context(pseudo_route, scope_graph)


def _header_evidence(
    entry: EffectiveHeaderValue,
    *,
    status: str,
    message: str,
) -> ControlAssessmentEvidence:
    return ControlAssessmentEvidence(
        kind="request-header",
        status=status,
        message=message,
        header_name=entry.configured_name,
        locations=(_source_location(entry.source),),
        declared_scope_id=entry.declared_scope_id,
        effective_scope_id=entry.effective_scope_id,
        values=(entry.rendered_value,),
    )


def _unsupported_evidence_payloads(
    entries: tuple[UnsupportedEvidence, ...],
) -> list[ControlAssessmentEvidence]:
    return [
        ControlAssessmentEvidence(
            kind="unsupported",
            status=entry.reason,
            message="Directive was ignored for effective semantics because it is unsupported or illegal here.",
            header_name=entry.header_name,
            locations=(_source_location(entry.source),),
            declared_scope_id=entry.scope_id,
        )
        for entry in entries
    ]


def _related_rule_ids(findings: tuple[object, ...], *rule_ids: str) -> tuple[str, ...]:
    present = set()
    for finding in findings:
        rule_id = getattr(finding, "rule_id", None)
        if rule_id in rule_ids:
            present.add(rule_id)
    return tuple(sorted(present))


def _source_location(source: SourceSpan) -> SourceLocation:
    return SourceLocation(
        mode="local",
        kind="file",
        file_path=source.file_path,
        line=source.line,
    )


def _normalize_header_name(value: str) -> str:
    return value.lower()


def _normalize_text(value: str) -> str:
    return " ".join(value.strip().split())


__all__ = ["evaluate_reverse_proxy_header_policy"]
