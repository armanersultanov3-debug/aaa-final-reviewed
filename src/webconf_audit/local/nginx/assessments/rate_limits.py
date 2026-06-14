"""Policy-backed rate-limit assessments for Nginx."""

from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
from typing import Iterable

from webconf_audit.local.nginx.effective_scope import NginxScope, NginxScopeGraph, NginxScopeKind
from webconf_audit.local.nginx.location_matcher import bind_declared_location, resolve_location_sample
from webconf_audit.local.nginx.parser.ast import ConfigAst, DirectiveNode, SourceSpan
from webconf_audit.local.nginx.rate_limit_semantics import (
    EffectiveLimitConn,
    EffectiveLimitReq,
    LimitConnZoneDefinition,
    LimitReqZoneDefinition,
    NginxRateLimitSemantics,
    RequestRate,
    resolve_rate_limit_semantics,
)
from webconf_audit.models import (
    ControlAssessmentEvidence,
    ControlAssessmentScope,
    PolicyControlAssessment,
    SourceLocation,
)
from webconf_audit.policy_models import (
    NginxConnectionLimitRequirement,
    NginxRateLimitProfile,
    NginxRateLimitsPolicy,
    NginxRequestLimitRequirement,
)

_POLICY_SECTION = "nginx.rate_limits"
_REQUEST_CONTROL_ID = "cis-nginx-5.2.5.requests-per-ip"
_CONNECTION_CONTROL_ID = "cis-nginx-5.2.4.connections-per-ip"

_REQUEST_RELATED_RULE_IDS = (
    "nginx.missing_limit_req",
    "nginx.missing_limit_req_zone",
    "nginx.limit_req_unknown_zone",
    "nginx.limit_req_zone_invalid_rate",
    "nginx.limit_req_zone_not_per_ip",
    "nginx.limit_req_zone_rate_review",
)
_CONNECTION_RELATED_RULE_IDS = (
    "nginx.missing_limit_conn",
    "nginx.missing_limit_conn_zone",
    "nginx.limit_conn_invalid_limit",
    "nginx.limit_conn_zone_not_per_ip",
    "nginx.limit_conn_zone_review",
)


@dataclass(frozen=True)
class _SelectedRoute:
    server_scope: NginxScope
    route_scope: NginxScope
    server_names: tuple[str, ...]
    route_label: str | None
    selection_reasons: tuple[str, ...]


def evaluate_rate_limit_policy(
    config_ast: ConfigAst,
    *,
    scope_graph: NginxScopeGraph,
    policy: NginxRateLimitsPolicy | None,
    findings: Iterable[object] = (),
) -> list[PolicyControlAssessment]:
    if policy is None:
        return []

    semantics = resolve_rate_limit_semantics(config_ast, scope_graph=scope_graph)
    server_scopes = tuple(
        scope for scope in scope_graph.scopes if scope.kind == NginxScopeKind.SERVER
    )
    server_names_by_scope = {
        scope.scope_id: _scope_server_names(scope, scope_graph)
        for scope in server_scopes
    }
    all_findings = tuple(findings)
    assessments: list[PolicyControlAssessment] = []

    for profile in policy.profiles:
        matched_server_scopes = [
            scope
            for scope in server_scopes
            if _profile_matches_server(
                profile,
                server_names=server_names_by_scope[scope.scope_id],
            )
        ]
        if not matched_server_scopes:
            assessments.extend(
                _unmatched_profile_assessments(
                    profile=profile,
                    status=policy.unmatched_routes,
                )
            )
            continue

        for server_scope in matched_server_scopes:
            selected_routes = _select_routes_for_profile(
                scope_graph=scope_graph,
                server_scope=server_scope,
                profile=profile,
                unmatched_routes=policy.unmatched_routes,
            )
            for selected_route in selected_routes:
                effective = semantics.effective_scopes_by_id[selected_route.route_scope.scope_id]
                if profile.request is not None:
                    assessments.append(
                        _request_assessment(
                            profile=profile,
                            requirement=profile.request,
                            route=selected_route,
                            semantics=semantics,
                            effective=effective,
                            request_inventory=policy.zone_inventory.request,
                            unresolved_internal_redirects=policy.unresolved_internal_redirects,
                            findings=all_findings,
                        )
                    )
                if profile.connection is not None:
                    assessments.append(
                        _connection_assessment(
                            profile=profile,
                            requirement=profile.connection,
                            route=selected_route,
                            semantics=semantics,
                            effective=effective,
                            connection_inventory=policy.zone_inventory.connection,
                            unresolved_internal_redirects=policy.unresolved_internal_redirects,
                            findings=all_findings,
                        )
                    )

    assessments.sort(key=_assessment_sort_key)
    return assessments


def _profile_matches_server(
    profile: NginxRateLimitProfile,
    *,
    server_names: tuple[str, ...],
) -> bool:
    profile_names = {name.lower() for name in profile.applies_to.server_names}
    return bool(profile_names & {name.lower() for name in server_names})


def _select_routes_for_profile(
    *,
    scope_graph: NginxScopeGraph,
    server_scope: NginxScope,
    profile: NginxRateLimitProfile,
    unmatched_routes: str,
) -> list[_SelectedRoute]:
    selected_by_scope_id: dict[str, _SelectedRoute] = {}
    selector = profile.applies_to
    if not selector.declared_locations and not selector.sample_uris:
        return [
            _SelectedRoute(
                server_scope=server_scope,
                route_scope=server_scope,
                server_names=_scope_server_names(server_scope, scope_graph),
                route_label=None,
                selection_reasons=(),
            )
        ]

    for declared_location in selector.declared_locations:
        binding = bind_declared_location(
            scope_graph=scope_graph,
            server_scope_id=server_scope.scope_id,
            selector=declared_location,
        )
        if binding.status == "selected" and binding.selected_scope is not None:
            selected_by_scope_id.setdefault(
                binding.selected_scope.scope_id,
                _SelectedRoute(
                    server_scope=server_scope,
                    route_scope=binding.selected_scope,
                    server_names=_scope_server_names(server_scope, scope_graph),
                    route_label=declared_location.pattern,
                    selection_reasons=(),
                ),
            )
        elif unmatched_routes != "not-applicable":
            selected_by_scope_id.setdefault(
                f"{server_scope.scope_id}:unmatched:{declared_location.pattern}",
                _SelectedRoute(
                    server_scope=server_scope,
                    route_scope=server_scope,
                    server_names=_scope_server_names(server_scope, scope_graph),
                    route_label=declared_location.pattern,
                    selection_reasons=binding.indeterminate_reasons or ("declared-location-unmatched",),
                ),
            )

    for sample_uri in selector.sample_uris:
        resolution = resolve_location_sample(
            scope_graph=scope_graph,
            server_scope_id=server_scope.scope_id,
            sample_uri=sample_uri,
        )
        if resolution.status == "selected" and resolution.selected_scope is not None:
            existing = selected_by_scope_id.get(resolution.selected_scope.scope_id)
            if existing is None:
                selected_by_scope_id[resolution.selected_scope.scope_id] = _SelectedRoute(
                    server_scope=server_scope,
                    route_scope=resolution.selected_scope,
                    server_names=_scope_server_names(server_scope, scope_graph),
                    route_label=sample_uri,
                    selection_reasons=(),
                )
            continue
        if unmatched_routes != "not-applicable":
            selected_by_scope_id.setdefault(
                f"{server_scope.scope_id}:unmatched:{sample_uri}",
                _SelectedRoute(
                    server_scope=server_scope,
                    route_scope=server_scope,
                    server_names=_scope_server_names(server_scope, scope_graph),
                    route_label=sample_uri,
                    selection_reasons=resolution.indeterminate_reasons or ("sample-uri-unmatched",),
                ),
            )

    return list(selected_by_scope_id.values())


def _request_assessment(
    *,
    profile: NginxRateLimitProfile,
    requirement: NginxRequestLimitRequirement,
    route: _SelectedRoute,
    semantics: NginxRateLimitSemantics,
    effective,
    request_inventory: dict[str, object],
    unresolved_internal_redirects: str,
    findings: tuple[object, ...],
) -> PolicyControlAssessment:
    status, summary, evidence, metadata = _evaluate_request_requirement(
        profile=profile,
        requirement=requirement,
        route=route,
        semantics=semantics,
        effective=effective,
        request_inventory=request_inventory,
        unresolved_internal_redirects=unresolved_internal_redirects,
    )
    return _assessment(
        control_id=_REQUEST_CONTROL_ID,
        title="Ensure rate limits by IP address are set",
        status=status,
        summary=summary,
        route=route,
        profile=profile,
        evidence=evidence,
        related_rule_ids=_related_rule_ids(findings, *_REQUEST_RELATED_RULE_IDS),
        metadata=metadata,
    )


def _connection_assessment(
    *,
    profile: NginxRateLimitProfile,
    requirement: NginxConnectionLimitRequirement,
    route: _SelectedRoute,
    semantics: NginxRateLimitSemantics,
    effective,
    connection_inventory: dict[str, object],
    unresolved_internal_redirects: str,
    findings: tuple[object, ...],
) -> PolicyControlAssessment:
    status, summary, evidence, metadata = _evaluate_connection_requirement(
        profile=profile,
        requirement=requirement,
        route=route,
        semantics=semantics,
        effective=effective,
        connection_inventory=connection_inventory,
        unresolved_internal_redirects=unresolved_internal_redirects,
    )
    return _assessment(
        control_id=_CONNECTION_CONTROL_ID,
        title="Ensure the number of connections per IP address is limited",
        status=status,
        summary=summary,
        route=route,
        profile=profile,
        evidence=evidence,
        related_rule_ids=_related_rule_ids(findings, *_CONNECTION_RELATED_RULE_IDS),
        metadata=metadata,
    )


def _evaluate_request_requirement(
    *,
    profile: NginxRateLimitProfile,
    requirement: NginxRequestLimitRequirement,
    route: _SelectedRoute,
    semantics: NginxRateLimitSemantics,
    effective,
    request_inventory: dict[str, object],
    unresolved_internal_redirects: str,
) -> tuple[str, str, tuple[ControlAssessmentEvidence, ...], dict[str, object]]:
    evidence: list[ControlAssessmentEvidence] = []
    failures: list[str] = []
    indeterminate_reasons = set(route.selection_reasons) | set(effective.indeterminate_reasons)
    if _route_has_unresolved_internal_redirect(semantics.scope_graph, route.route_scope.scope_id):
        if unresolved_internal_redirects == "fail":
            failures.append("unresolved-internal-redirect")
        elif unresolved_internal_redirects == "indeterminate":
            indeterminate_reasons.add("unresolved-internal-redirect")

    active_limits = list(effective.request_limits)
    accepted_zone_names = set(requirement.accepted_zones)
    active_zone_names = {entry.zone_name for entry in active_limits}

    if not requirement.required and not active_limits:
        status = "not-applicable"
        summary = "Request-rate policy is explicitly exempt for this route."
        metadata = _base_metadata(
            semantics=semantics,
            profile=profile,
            route=route,
            request_limits=active_limits,
            connection_limits=(),
            effective=effective,
            extra={"request_zone_definitions": []},
        )
        return status, summary, (), metadata

    if requirement.required and not active_limits:
        failures.append("missing-request-limit")
        evidence.append(
            _route_evidence(
                status="missing",
                message="No effective limit_req directive applies to this route.",
            )
        )

    if accepted_zone_names:
        matched_limits = [entry for entry in active_limits if entry.zone_name in accepted_zone_names]
    else:
        matched_limits = active_limits

    if requirement.required and accepted_zone_names and not matched_limits:
        failures.append("required-request-zones-not-active")

    if requirement.require_all_zones and not accepted_zone_names.issubset(active_zone_names):
        failures.append("required-request-zone-missing")

    extra_zone_names = active_zone_names - accepted_zone_names if accepted_zone_names else set()
    if requirement.additional_zones == "forbid" and extra_zone_names:
        failures.append("forbidden-additional-request-zone")
    elif requirement.additional_zones == "require_in_inventory":
        inventory_names = set(request_inventory)
        if not extra_zone_names.issubset(inventory_names):
            failures.append("unapproved-additional-request-zone")

    for limit in matched_limits:
        zone_definition = semantics.request_zones_by_name.get(limit.zone_name)
        if zone_definition is None:
            indeterminate_reasons.add("request-zone-definition-unresolved")
            evidence.append(
                _route_evidence(
                    status="indeterminate",
                    message=f"Request zone {limit.zone_name!r} is not conclusively defined.",
                    location=_source_location(limit.source),
                    declared_scope_id=limit.declared_scope_id,
                    effective_scope_id=limit.effective_scope_id,
                    values=(limit.zone_name,),
                )
            )
            continue
        inventory_entry = request_inventory.get(limit.zone_name)
        if inventory_entry is not None:
            if zone_definition.normalized_key not in {
                _normalize_expression(value) for value in inventory_entry.allowed_keys
            }:
                failures.append("request-zone-key-mismatch")
            if inventory_entry.min_size is not None and zone_definition.size_bytes < inventory_entry.min_size.bytes:
                failures.append("request-zone-size-too-small")
            if inventory_entry.max_size is not None and zone_definition.size_bytes > inventory_entry.max_size.bytes:
                failures.append("request-zone-size-too-large")
            if inventory_entry.rate.min is not None and _rate_fraction(zone_definition.rate) < _rate_fraction(inventory_entry.rate.min):
                failures.append("request-rate-too-strict")
            if inventory_entry.rate.max is not None and _rate_fraction(zone_definition.rate) > _rate_fraction(inventory_entry.rate.max):
                failures.append("request-rate-too-weak")

        if requirement.burst is not None:
            if requirement.burst.min is not None and limit.burst < requirement.burst.min:
                failures.append("request-burst-too-small")
            if requirement.burst.max is not None and limit.burst > requirement.burst.max:
                failures.append("request-burst-too-large")

        effective_delay_mode = _effective_delay_mode(limit)
        if requirement.delay_mode is not None and effective_delay_mode != requirement.delay_mode:
            failures.append("request-delay-mode-mismatch")
        if requirement.delayed_requests is not None:
            effective_delayed_requests = 0 if limit.delay is None else limit.delay
            if (
                requirement.delayed_requests.min is not None
                and effective_delayed_requests < requirement.delayed_requests.min
            ):
                failures.append("request-delayed-requests-too-small")
            if (
                requirement.delayed_requests.max is not None
                and effective_delayed_requests > requirement.delayed_requests.max
            ):
                failures.append("request-delayed-requests-too-large")

        evidence.append(
            _route_evidence(
                status="observed",
                message=f"Observed effective request limit for zone {limit.zone_name!r}.",
                location=_source_location(limit.source),
                declared_scope_id=limit.declared_scope_id,
                effective_scope_id=limit.effective_scope_id,
                values=(
                    limit.zone_name,
                    str(limit.burst),
                    str(limit.delay) if limit.delay is not None else "<default>",
                    "nodelay" if limit.nodelay else "delayed",
                ),
            )
        )

    if requirement.dry_run is not None and effective.request_dry_run != requirement.dry_run:
        failures.append("request-dry-run-mismatch")
    if requirement.allowed_rejection_statuses and effective.request_status not in requirement.allowed_rejection_statuses:
        failures.append("request-status-mismatch")
    if requirement.allowed_log_levels and effective.request_log_level not in requirement.allowed_log_levels:
        failures.append("request-log-level-mismatch")

    status = "indeterminate" if indeterminate_reasons else "fail" if failures else "pass"
    summary = (
        "Effective request-rate evidence is incomplete or unsupported."
        if status == "indeterminate"
        else "Effective request-rate limits do not satisfy the declared route policy."
        if status == "fail"
        else "Effective request-rate limits satisfy the declared route policy."
    )
    metadata = _base_metadata(
        semantics=semantics,
        profile=profile,
        route=route,
        request_limits=active_limits,
        connection_limits=(),
        effective=effective,
        extra={
            "request_zone_definitions": [
                _request_zone_payload(semantics.request_zones_by_name[entry.zone_name])
                for entry in matched_limits
                if entry.zone_name in semantics.request_zones_by_name
            ],
            "indeterminate_reasons": sorted(indeterminate_reasons),
            "failures": sorted(set(failures)),
        },
    )
    return status, summary, tuple(evidence), metadata


def _evaluate_connection_requirement(
    *,
    profile: NginxRateLimitProfile,
    requirement: NginxConnectionLimitRequirement,
    route: _SelectedRoute,
    semantics: NginxRateLimitSemantics,
    effective,
    connection_inventory: dict[str, object],
    unresolved_internal_redirects: str,
) -> tuple[str, str, tuple[ControlAssessmentEvidence, ...], dict[str, object]]:
    evidence: list[ControlAssessmentEvidence] = []
    failures: list[str] = []
    indeterminate_reasons = set(route.selection_reasons) | set(effective.indeterminate_reasons)
    if _route_has_unresolved_internal_redirect(semantics.scope_graph, route.route_scope.scope_id):
        if unresolved_internal_redirects == "fail":
            failures.append("unresolved-internal-redirect")
        elif unresolved_internal_redirects == "indeterminate":
            indeterminate_reasons.add("unresolved-internal-redirect")

    active_limits = list(effective.connection_limits)
    accepted_zone_names = set(requirement.accepted_zones)
    active_zone_names = {entry.zone_name for entry in active_limits}

    if not requirement.required and not active_limits:
        status = "not-applicable"
        summary = "Connection-limit policy is explicitly exempt for this route."
        metadata = _base_metadata(
            semantics=semantics,
            profile=profile,
            route=route,
            request_limits=(),
            connection_limits=active_limits,
            effective=effective,
            extra={"connection_zone_definitions": []},
        )
        return status, summary, (), metadata

    if requirement.required and not active_limits:
        failures.append("missing-connection-limit")
        evidence.append(
            _route_evidence(
                status="missing",
                message="No effective limit_conn directive applies to this route.",
            )
        )

    if accepted_zone_names:
        matched_limits = [entry for entry in active_limits if entry.zone_name in accepted_zone_names]
    else:
        matched_limits = active_limits

    if requirement.required and accepted_zone_names and not matched_limits:
        failures.append("required-connection-zones-not-active")

    if requirement.require_all_zones and not accepted_zone_names.issubset(active_zone_names):
        failures.append("required-connection-zone-missing")

    extra_zone_names = active_zone_names - accepted_zone_names if accepted_zone_names else set()
    if requirement.additional_zones == "forbid" and extra_zone_names:
        failures.append("forbidden-additional-connection-zone")
    elif requirement.additional_zones == "require_in_inventory":
        inventory_names = set(connection_inventory)
        if not extra_zone_names.issubset(inventory_names):
            failures.append("unapproved-additional-connection-zone")

    for limit in matched_limits:
        zone_definition = semantics.connection_zones_by_name.get(limit.zone_name)
        if zone_definition is None:
            indeterminate_reasons.add("connection-zone-definition-unresolved")
            evidence.append(
                _route_evidence(
                    status="indeterminate",
                    message=f"Connection zone {limit.zone_name!r} is not conclusively defined.",
                    location=_source_location(limit.source),
                    declared_scope_id=limit.declared_scope_id,
                    effective_scope_id=limit.effective_scope_id,
                    values=(limit.zone_name,),
                )
            )
            continue
        inventory_entry = connection_inventory.get(limit.zone_name)
        if inventory_entry is not None:
            if zone_definition.normalized_key not in {
                _normalize_expression(value) for value in inventory_entry.allowed_keys
            }:
                failures.append("connection-zone-key-mismatch")
            if inventory_entry.min_size is not None and zone_definition.size_bytes < inventory_entry.min_size.bytes:
                failures.append("connection-zone-size-too-small")
            if inventory_entry.max_size is not None and zone_definition.size_bytes > inventory_entry.max_size.bytes:
                failures.append("connection-zone-size-too-large")
        if requirement.connections is not None:
            if requirement.connections.min is not None and limit.connections < requirement.connections.min:
                failures.append("connection-limit-too-small")
            if requirement.connections.max is not None and limit.connections > requirement.connections.max:
                failures.append("connection-limit-too-large")
        evidence.append(
            _route_evidence(
                status="observed",
                message=f"Observed effective connection limit for zone {limit.zone_name!r}.",
                location=_source_location(limit.source),
                declared_scope_id=limit.declared_scope_id,
                effective_scope_id=limit.effective_scope_id,
                values=(limit.zone_name, str(limit.connections)),
            )
        )

    if requirement.dry_run is not None and effective.connection_dry_run != requirement.dry_run:
        failures.append("connection-dry-run-mismatch")
    if requirement.allowed_rejection_statuses and effective.connection_status not in requirement.allowed_rejection_statuses:
        failures.append("connection-status-mismatch")
    if requirement.allowed_log_levels and effective.connection_log_level not in requirement.allowed_log_levels:
        failures.append("connection-log-level-mismatch")

    status = "indeterminate" if indeterminate_reasons else "fail" if failures else "pass"
    summary = (
        "Effective connection-limit evidence is incomplete or unsupported."
        if status == "indeterminate"
        else "Effective connection limits do not satisfy the declared route policy."
        if status == "fail"
        else "Effective connection limits satisfy the declared route policy."
    )
    metadata = _base_metadata(
        semantics=semantics,
        profile=profile,
        route=route,
        request_limits=(),
        connection_limits=active_limits,
        effective=effective,
        extra={
            "connection_zone_definitions": [
                _connection_zone_payload(semantics.connection_zones_by_name[entry.zone_name])
                for entry in matched_limits
                if entry.zone_name in semantics.connection_zones_by_name
            ],
            "indeterminate_reasons": sorted(indeterminate_reasons),
            "failures": sorted(set(failures)),
        },
    )
    return status, summary, tuple(evidence), metadata


def _assessment(
    *,
    control_id: str,
    title: str,
    status: str,
    summary: str,
    route: _SelectedRoute,
    profile: NginxRateLimitProfile,
    evidence: tuple[ControlAssessmentEvidence, ...],
    related_rule_ids: tuple[str, ...],
    metadata: dict[str, object],
) -> PolicyControlAssessment:
    return PolicyControlAssessment(
        control_id=control_id,
        title=title,
        status=status,  # type: ignore[arg-type]
        scope=ControlAssessmentScope(
            server_scope_id=route.server_scope.scope_id,
            route_scope_id=route.route_scope.scope_id,
            route_selector=route.route_scope.selector,
            server_name=route.server_names[0] if route.server_names else None,
        ),
        summary=summary,
        evidence=evidence,
        related_rule_ids=related_rule_ids,
        policy_source=f"{_POLICY_SECTION}.{profile.profile_id}",
        metadata=metadata,
    )


def _unmatched_profile_assessments(
    *,
    profile: NginxRateLimitProfile,
    status: str,
) -> list[PolicyControlAssessment]:
    scope = ControlAssessmentScope(
        server_scope_id=f"policy-profile:{profile.profile_id}",
        route_scope_id=f"policy-profile:{profile.profile_id}",
        route_selector=None,
        server_name=profile.applies_to.server_names[0] if profile.applies_to.server_names else None,
    )
    assessments: list[PolicyControlAssessment] = []
    if profile.request is not None:
        assessments.append(
            PolicyControlAssessment(
                control_id=_REQUEST_CONTROL_ID,
                title="Ensure rate limits by IP address are set",
                status=status,  # type: ignore[arg-type]
                scope=scope,
                summary="The rate-limit profile did not match any nginx route.",
                evidence=(),
                related_rule_ids=(),
                policy_source=f"{_POLICY_SECTION}.{profile.profile_id}",
                metadata={
                    "policy_section": _POLICY_SECTION,
                    "profile_id": profile.profile_id,
                    "server_scope_id": scope.server_scope_id,
                    "route_scope_id": scope.route_scope_id,
                    "route_label": None,
                    "server_names": list(profile.applies_to.server_names),
                    "complete": False,
                    "request_limits": [],
                    "connection_limits": [],
                    "request_dry_run": None,
                    "connection_dry_run": None,
                    "request_status": None,
                    "connection_status": None,
                    "request_log_level": None,
                    "connection_log_level": None,
                    "unsupported_evidence": [],
                    "indeterminate_reasons": []
                    if status != "indeterminate"
                    else ["no-matching-route"],
                    "failures": [],
                    "request_zone_definitions": [],
                    "connection_zone_definitions": [],
                },
            )
        )
    if profile.connection is not None:
        assessments.append(
            PolicyControlAssessment(
                control_id=_CONNECTION_CONTROL_ID,
                title="Ensure the number of connections per IP address is limited",
                status=status,  # type: ignore[arg-type]
                scope=scope,
                summary="The rate-limit profile did not match any nginx route.",
                evidence=(),
                related_rule_ids=(),
                policy_source=f"{_POLICY_SECTION}.{profile.profile_id}",
                metadata={
                    "policy_section": _POLICY_SECTION,
                    "profile_id": profile.profile_id,
                    "server_scope_id": scope.server_scope_id,
                    "route_scope_id": scope.route_scope_id,
                    "route_label": None,
                    "server_names": list(profile.applies_to.server_names),
                    "complete": False,
                    "request_limits": [],
                    "connection_limits": [],
                    "request_dry_run": None,
                    "connection_dry_run": None,
                    "request_status": None,
                    "connection_status": None,
                    "request_log_level": None,
                    "connection_log_level": None,
                    "unsupported_evidence": [],
                    "indeterminate_reasons": []
                    if status != "indeterminate"
                    else ["no-matching-route"],
                    "failures": [],
                    "request_zone_definitions": [],
                    "connection_zone_definitions": [],
                },
            )
        )
    return assessments


def _route_evidence(
    *,
    status: str,
    message: str,
    location: SourceLocation | None = None,
    declared_scope_id: str | None = None,
    effective_scope_id: str | None = None,
    values: tuple[str, ...] = (),
) -> ControlAssessmentEvidence:
    return ControlAssessmentEvidence(
        kind="route",
        status=status,
        message=message,
        locations=(location,) if location is not None else (),
        declared_scope_id=declared_scope_id,
        effective_scope_id=effective_scope_id,
        values=values,
    )


def _source_location(source: SourceSpan) -> SourceLocation:
    return SourceLocation(
        mode="local",
        kind="file",
        file_path=source.file_path,
        line=source.line,
    )


def _base_metadata(
    *,
    semantics: NginxRateLimitSemantics,
    profile: NginxRateLimitProfile,
    route: _SelectedRoute,
    request_limits: list[EffectiveLimitReq] | tuple[EffectiveLimitReq, ...],
    connection_limits: list[EffectiveLimitConn] | tuple[EffectiveLimitConn, ...],
    effective,
    extra: dict[str, object],
) -> dict[str, object]:
    unsupported_evidence = _relevant_unsupported_evidence(
        semantics=semantics,
        route=route,
        request_limits=request_limits,
        connection_limits=connection_limits,
    )
    return {
        "policy_section": _POLICY_SECTION,
        "profile_id": profile.profile_id,
        "server_scope_id": route.server_scope.scope_id,
        "route_scope_id": route.route_scope.scope_id,
        "route_label": route.route_label,
        "server_names": list(route.server_names),
        "complete": effective.complete,
        "request_limits": [_request_limit_payload(entry) for entry in request_limits],
        "connection_limits": [_connection_limit_payload(entry) for entry in connection_limits],
        "request_dry_run": effective.request_dry_run,
        "connection_dry_run": effective.connection_dry_run,
        "request_status": effective.request_status,
        "connection_status": effective.connection_status,
        "request_log_level": effective.request_log_level,
        "connection_log_level": effective.connection_log_level,
        "unsupported_evidence": unsupported_evidence,
        **extra,
    }


def _request_limit_payload(entry: EffectiveLimitReq) -> dict[str, object]:
    return {
        "zone_name": entry.zone_name,
        "burst": entry.burst,
        "delay": entry.delay,
        "nodelay": entry.nodelay,
        "declared_scope_id": entry.declared_scope_id,
        "effective_scope_id": entry.effective_scope_id,
        "origin": entry.origin,
        "source": _source_payload(entry.source),
    }


def _connection_limit_payload(entry: EffectiveLimitConn) -> dict[str, object]:
    return {
        "zone_name": entry.zone_name,
        "connections": entry.connections,
        "declared_scope_id": entry.declared_scope_id,
        "effective_scope_id": entry.effective_scope_id,
        "origin": entry.origin,
        "source": _source_payload(entry.source),
    }


def _request_zone_payload(entry: LimitReqZoneDefinition) -> dict[str, object]:
    return {
        "zone_name": entry.name,
        "normalized_key": entry.normalized_key,
        "size_bytes": entry.size_bytes,
        "rate_requests": entry.rate.requests,
        "rate_period_seconds": entry.rate.period_seconds,
        "source": _source_payload(entry.source),
    }


def _connection_zone_payload(entry: LimitConnZoneDefinition) -> dict[str, object]:
    return {
        "zone_name": entry.name,
        "normalized_key": entry.normalized_key,
        "size_bytes": entry.size_bytes,
        "source": _source_payload(entry.source),
    }


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


def _relevant_unsupported_evidence(
    *,
    semantics,
    route: _SelectedRoute,
    request_limits: list[EffectiveLimitReq] | tuple[EffectiveLimitReq, ...],
    connection_limits: list[EffectiveLimitConn] | tuple[EffectiveLimitConn, ...],
) -> list[dict[str, object]]:
    relevant_scope_ids = _scope_lineage_ids(route.route_scope, semantics.scope_graph)
    relevant_scope_ids.add(route.server_scope.scope_id)
    relevant_zone_names = {
        *(entry.zone_name for entry in request_limits),
        *(entry.zone_name for entry in connection_limits),
    }
    payloads: list[dict[str, object]] = []
    for entry in semantics.unsupported_evidence:
        if entry.scope_id not in relevant_scope_ids and (
            entry.zone_name is None or entry.zone_name not in relevant_zone_names
        ):
            continue
        payloads.append(
            {
                "reason": entry.reason,
                "directive_name": entry.directive_name,
                "scope_id": entry.scope_id,
                "zone_name": entry.zone_name,
                "details": list(entry.details),
                "source": _source_payload(entry.source),
            }
        )
    return payloads


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


def _rate_fraction(value: RequestRate) -> Fraction:
    return Fraction(value.requests, value.period_seconds)


def _effective_delay_mode(limit: EffectiveLimitReq) -> str:
    if limit.nodelay:
        return "nodelay"
    if limit.delay is None or limit.delay == 0:
        return "default"
    return "delayed"


def _normalize_expression(value: str) -> str:
    return " ".join(value.strip().split())


__all__ = ["evaluate_rate_limit_policy"]
