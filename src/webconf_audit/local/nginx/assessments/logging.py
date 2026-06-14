"""Policy-backed logging assessments for Nginx."""

from __future__ import annotations

from collections import defaultdict
from typing import Iterable

from webconf_audit.local.nginx.effective_scope import (
    NginxScope,
    NginxScopeGraph,
    NginxScopeKind,
)
from webconf_audit.local.nginx.logging_semantics import (
    AccessLogDestination,
    EffectiveLoggingScope,
    ErrorLogDestination,
    LogFormatDefinition,
    NginxLoggingSemantics,
    resolve_logging_semantics,
)
from webconf_audit.local.nginx.parser.ast import ConfigAst, DirectiveNode, SourceSpan
from webconf_audit.models import (
    ControlAssessmentEvidence,
    ControlAssessmentScope,
    PolicyControlAssessment,
    SourceLocation,
)
from webconf_audit.policy_models import (
    NginxAccessDestinationEntry,
    NginxAccessLoggingPolicy,
    NginxErrorLoggingPolicy,
    NginxLoggingPolicy,
    NginxLoggingProfile,
)

_POLICY_SECTION = "nginx.logging"
_ACCESS_CONTROL_ID = "cis-nginx-3.1.detailed-access-logging"
_ERROR_CONTROL_ID = "cis-nginx-3.3.error-log-info-level"
_GENERIC_CONTROL_ID = "policy.nginx.logging"

_ACCESS_TITLE = "Ensure detailed logging is enabled"
_ERROR_TITLE = "Ensure error logging is enabled and set to the info logging level"
_GENERIC_TITLE = "Nginx logging policy scope match"

_ACCESS_FINDING_IDS = (
    "nginx.access_log_uses_default_format",
    "nginx.log_format_missing_fields",
    "nginx.missing_access_log",
    "nginx.missing_log_format",
)
_ERROR_FINDING_IDS = (
    "nginx.error_log_too_restrictive",
    "nginx.missing_error_log",
)

_ERROR_LEVEL_INDEX = {
    level: index
    for index, level in enumerate(
        ("debug", "info", "notice", "warn", "error", "crit", "alert", "emerg")
    )
}


def evaluate_logging_policy(
    config_ast: ConfigAst,
    *,
    scope_graph: NginxScopeGraph,
    policy: NginxLoggingPolicy | None,
    findings: Iterable[object] = (),
) -> list[PolicyControlAssessment]:
    if policy is None:
        return []

    semantics = resolve_logging_semantics(config_ast, scope_graph=scope_graph)
    server_names_by_scope = _server_names_by_scope(scope_graph)
    matched_material_scope_ids = _material_scope_ids(
        semantics,
        policy=policy,
        server_names_by_scope=server_names_by_scope,
    )
    all_findings = tuple(findings)
    assessments: list[PolicyControlAssessment] = []

    any_access = any(profile.access is not None for profile in policy.profiles)
    any_error = any(profile.error is not None for profile in policy.profiles)

    for scope_id in matched_material_scope_ids:
        scope = scope_graph.scopes_by_id[scope_id]
        matched = [
            profile
            for profile in policy.profiles
            if _profile_matches_scope(
                profile,
                scope=scope,
                server_names=server_names_by_scope[scope_id],
            )
        ]
        matched.sort(key=lambda profile: profile.profile_id)
        effective = semantics.effective_scopes_by_id[scope_id]

        if not matched:
            if policy.unmatched_scopes == "not-applicable":
                continue
            if any_access:
                assessments.append(
                    _unmatched_assessment(
                        scope_graph=scope_graph,
                        scope=scope,
                        server_names=server_names_by_scope[scope_id],
                        logging_kind="access",
                        status=policy.unmatched_scopes,
                    )
                )
            if any_error:
                assessments.append(
                    _unmatched_assessment(
                        scope_graph=scope_graph,
                        scope=scope,
                        server_names=server_names_by_scope[scope_id],
                        logging_kind="error",
                        status=policy.unmatched_scopes,
                    )
                )
            continue

        profile = matched[0]
        if profile.access is not None:
            assessments.append(
                _access_assessment(
                    semantics,
                    effective=effective,
                    scope=scope,
                    server_names=server_names_by_scope[scope_id],
                    profile=profile,
                    policy=profile.access,
                    findings=all_findings,
                )
            )
        if profile.error is not None:
            assessments.append(
                _error_assessment(
                    effective=effective,
                    scope_graph=scope_graph,
                    scope=scope,
                    server_names=server_names_by_scope[scope_id],
                    profile=profile,
                    policy=profile.error,
                    findings=all_findings,
                )
            )

    assessments.sort(key=_assessment_sort_key)
    return assessments


def _material_scope_ids(
    semantics: NginxLoggingSemantics,
    *,
    policy: NginxLoggingPolicy,
    server_names_by_scope: dict[str, tuple[str, ...]],
) -> tuple[str, ...]:
    material: set[str] = {
        scope.scope_id
        for scope in semantics.scope_graph.scopes
        if scope.kind == NginxScopeKind.SERVER
    }
    material.update(
        scope_id
        for scope_id in semantics.declared_access_scope_ids
        if semantics.scope_graph.scopes_by_id[scope_id].kind
        in {
            NginxScopeKind.LOCATION,
            NginxScopeKind.IF_IN_LOCATION,
            NginxScopeKind.LIMIT_EXCEPT,
        }
    )
    material.update(
        scope_id
        for scope_id in semantics.declared_error_scope_ids
        if semantics.scope_graph.scopes_by_id[scope_id].kind == NginxScopeKind.LOCATION
    )

    for profile in policy.profiles:
        for scope in semantics.scope_graph.scopes:
            if _profile_matches_scope(
                profile,
                scope=scope,
                server_names=server_names_by_scope[scope.scope_id],
            ):
                material.add(scope.scope_id)

    return tuple(sorted(material))


def _profile_matches_scope(
    profile: NginxLoggingProfile,
    *,
    scope: NginxScope,
    server_names: tuple[str, ...],
) -> bool:
    if profile.applies_to.server_names:
        profile_names = {name.lower() for name in profile.applies_to.server_names}
        if not ({name.lower() for name in server_names} & profile_names):
            return False
    if profile.applies_to.location_patterns:
        if scope.kind != NginxScopeKind.LOCATION or scope.selector is None:
            return False
        selector = _normalize_text(scope.selector)
        return selector in {
            _normalize_text(pattern)
            for pattern in profile.applies_to.location_patterns
        }
    return scope.kind == NginxScopeKind.SERVER


def _access_assessment(
    semantics: NginxLoggingSemantics,
    *,
    effective: EffectiveLoggingScope,
    scope: NginxScope,
    server_names: tuple[str, ...],
    profile: NginxLoggingProfile,
    policy: NginxAccessLoggingPolicy,
    findings: tuple[object, ...],
) -> PolicyControlAssessment:
    evidence: list[ControlAssessmentEvidence] = []
    failed = False
    indeterminate = not effective.complete or bool(effective.indeterminate_reasons)
    runtime_dependent = False
    present_groups: dict[str, list[str]] = defaultdict(list)
    missing_groups: dict[str, list[str]] = defaultdict(list)
    resolved_formats: dict[str, object] = {}
    evaluated_format_decisions: list[dict[str, object]] = []
    effective_destinations = [
        _access_destination_payload(destination)
        for destination in effective.access_logs
    ]

    if effective.access_state == "unknown":
        indeterminate = True
        evidence.append(
            _route_evidence(
                status="indeterminate",
                message="Effective access_log state could not be resolved safely.",
            )
        )
    elif effective.access_state == "off":
        if policy.required and not policy.allow_off:
            failed = True
        evidence.append(
            _route_evidence(
                status="off",
                message="Effective access logging is disabled for this scope.",
            )
        )

    enabled_logs = [
        destination
        for destination in effective.access_logs
        if destination.condition_kind != "constant_false"
    ]
    if policy.required and effective.access_state != "off" and not enabled_logs:
        failed = True
        evidence.append(
            _route_evidence(
                status="missing",
                message="No enabled access_log destination remains effective for this scope.",
            )
        )

    remote_guaranteed = False
    remote_dynamic = False
    for destination in enabled_logs:
        allowed_result = _access_destination_allowed(destination, policy)
        evidence.append(
            _route_evidence(
                status=allowed_result["status"],
                message=allowed_result["message"],
                location=_source_location(destination.source),
                declared_scope_id=destination.declared_scope_id,
                effective_scope_id=destination.effective_scope_id,
                values=_destination_values(destination),
            )
        )
        failed = failed or allowed_result["failed"]
        indeterminate = indeterminate or allowed_result["indeterminate"]

        if destination.destination_kind == "syslog":
            if destination.condition_kind in {"unconditional", "constant_true"}:
                remote_guaranteed = True
            elif destination.condition_kind == "dynamic":
                remote_dynamic = True

        condition_result = _condition_result(destination, policy)
        if condition_result is not None:
            evidence.append(condition_result["evidence"])
            failed = failed or condition_result["failed"]
            indeterminate = indeterminate or condition_result["indeterminate"]
            runtime_dependent = runtime_dependent or condition_result["runtime_dependent"]

        format_definition = semantics.format_definitions.get(destination.format_name)
        if format_definition is None:
            indeterminate = True
            evidence.append(
                _route_evidence(
                    status="indeterminate",
                    message=(
                        f"Referenced log_format {destination.format_name!r} is not defined."
                    ),
                    location=_source_location(destination.source),
                    declared_scope_id=destination.declared_scope_id,
                    effective_scope_id=destination.effective_scope_id,
                    values=(destination.format_name,),
                )
            )
            continue

        resolved_formats[destination.format_name] = {
            "name": format_definition.name,
            "origin": format_definition.origin,
            "escape_mode": format_definition.escape_mode,
            "source": _source_payload(format_definition.source),
            "variables": sorted(format_definition.variables),
        }
        evaluated_format_decisions.append(
            {
                "format_name": format_definition.name,
                "source": _source_payload(destination.source),
                "declared_scope_id": destination.declared_scope_id,
                "effective_scope_id": destination.effective_scope_id,
            }
        )
        format_result = _evaluate_access_format(
            destination=destination,
            format_definition=format_definition,
            policy=policy,
        )
        evidence.extend(format_result["evidence"])
        failed = failed or format_result["failed"]
        indeterminate = indeterminate or format_result["indeterminate"]
        for group_name, values in format_result["present_groups"].items():
            present_groups[group_name].extend(values)
        for group_name, values in format_result["missing_groups"].items():
            missing_groups[group_name].extend(values)

    if policy.destinations.require_at_least_one_remote and not remote_guaranteed:
        if remote_dynamic:
            indeterminate = True
            evidence.append(
                _route_evidence(
                    status="runtime-dependent",
                    message="At least one remote syslog destination depends on runtime conditions.",
                )
            )
        else:
            failed = True
            evidence.append(
                _route_evidence(
                    status="missing",
                    message="The policy requires at least one remote syslog destination.",
                )
            )

    status = "indeterminate" if indeterminate else "fail" if failed else "pass"
    summary = (
        "Effective access-log evidence is incomplete, dynamic, or partially unresolved."
        if status == "indeterminate"
        else "Effective access logging does not satisfy the declared policy."
        if status == "fail"
        else "Effective access logging satisfies the declared detailed logging policy."
    )
    return _assessment(
        control_id=_ACCESS_CONTROL_ID,
        title=_ACCESS_TITLE,
        status=status,
        summary=summary,
        scope=scope,
        server_names=server_names,
        profile=profile,
        evidence=tuple(evidence),
        related_rule_ids=_related_rule_ids(findings, *_ACCESS_FINDING_IDS),
        metadata={
            "policy_section": _POLICY_SECTION,
            "profile_id": profile.profile_id,
            "server_scope_id": _server_scope_id(scope, semantics.scope_graph),
            "logging_scope_id": scope.scope_id,
            "logging_kind": "access",
            "server_names": list(server_names),
            "effective_destinations": effective_destinations,
            "resolved_formats": list(resolved_formats.values()),
            "evaluated_format_decisions": evaluated_format_decisions,
            "required_field_groups": {
                key: list(values)
                for key, values in policy.formats.required_field_groups.items()
            },
            "present_field_groups": {
                key: sorted(set(values))
                for key, values in present_groups.items()
            },
            "missing_field_groups": {
                key: sorted(set(values))
                for key, values in missing_groups.items()
            },
            "indeterminate_reasons": list(effective.indeterminate_reasons),
            "runtime_dependent": runtime_dependent,
        },
    )


def _error_assessment(
    *,
    effective: EffectiveLoggingScope,
    scope_graph: NginxScopeGraph,
    scope: NginxScope,
    server_names: tuple[str, ...],
    profile: NginxLoggingProfile,
    policy: NginxErrorLoggingPolicy,
    findings: tuple[object, ...],
) -> PolicyControlAssessment:
    evidence: list[ControlAssessmentEvidence] = []
    failed = False
    indeterminate = not effective.complete or bool(effective.indeterminate_reasons)
    effective_destinations = [
        _error_destination_payload(destination)
        for destination in effective.error_logs
    ]

    if policy.required and not effective.error_logs:
        failed = True
        evidence.append(
            _route_evidence(
                status="missing",
                message="No effective error_log destination remains for this scope.",
            )
        )

    for destination in effective.error_logs:
        status, message, destination_failed, destination_indeterminate = _error_destination_status(
            destination,
            policy,
        )
        evidence.append(
            _route_evidence(
                status=status,
                message=message,
                location=_source_location(destination.source) if destination.source else None,
                declared_scope_id=destination.declared_scope_id,
                effective_scope_id=destination.effective_scope_id,
                values=_error_destination_values(destination),
            )
        )
        failed = failed or destination_failed
        indeterminate = indeterminate or destination_indeterminate

    status = "indeterminate" if indeterminate else "fail" if failed else "pass"
    summary = (
        "Effective error-log evidence is incomplete or edition-dependent."
        if status == "indeterminate"
        else "Effective error logging does not satisfy the declared threshold or destination policy."
        if status == "fail"
        else "Effective error logging satisfies the declared threshold and destination policy."
    )
    return _assessment(
        control_id=_ERROR_CONTROL_ID,
        title=_ERROR_TITLE,
        status=status,
        summary=summary,
        scope=scope,
        server_names=server_names,
        profile=profile,
        evidence=tuple(evidence),
        related_rule_ids=_related_rule_ids(findings, *_ERROR_FINDING_IDS),
        metadata={
            "policy_section": _POLICY_SECTION,
            "profile_id": profile.profile_id,
            "server_scope_id": _server_scope_id(scope, scope_graph),
            "logging_scope_id": scope.scope_id,
            "logging_kind": "error",
            "server_names": list(server_names),
            "effective_destinations": effective_destinations,
            "indeterminate_reasons": list(effective.indeterminate_reasons),
        },
    )


def _error_destination_status(
    destination: ErrorLogDestination,
    policy: NginxErrorLoggingPolicy,
) -> tuple[str, str, bool, bool]:
    failed = False
    indeterminate = False
    if destination.origin == "nginx_default":
        if policy.require_explicit_destination:
            failed = True
            return (
                "forbidden",
                "The policy requires an explicit error_log destination instead of the compiled default.",
                failed,
                indeterminate,
            )
        indeterminate = True
    if destination.destination_kind == "unknown":
        indeterminate = True
    elif destination.destination_kind not in policy.destinations.allowed_kinds:
        failed = True
    if destination.raw_path in policy.destinations.forbidden_paths:
        failed = True
    if destination.json_mode:
        indeterminate = True
    most_restrictive = policy.threshold.most_restrictive_allowed
    if _ERROR_LEVEL_INDEX[destination.threshold] > _ERROR_LEVEL_INDEX[most_restrictive]:
        failed = True
    if destination.threshold == "debug" and not policy.threshold.allow_debug:
        failed = True

    status = "indeterminate" if indeterminate else "forbidden" if failed else "allowed"
    message = (
        "The error_log destination is edition-dependent or not fully identifiable."
        if indeterminate
        else "The error_log destination violates the declared kind, path, or threshold policy."
        if failed
        else "The error_log destination satisfies the declared kind, path, and threshold policy."
    )
    return status, message, failed, indeterminate


def _evaluate_access_format(
    *,
    destination: AccessLogDestination,
    format_definition: LogFormatDefinition,
    policy: NginxAccessLoggingPolicy,
) -> dict[str, object]:
    evidence: list[ControlAssessmentEvidence] = []
    failed = False
    indeterminate = False
    present_groups: dict[str, list[str]] = defaultdict(list)
    missing_groups: dict[str, list[str]] = defaultdict(list)

    if policy.formats.allowed_names and format_definition.name not in policy.formats.allowed_names:
        failed = True
        evidence.append(
            _route_evidence(
                status="forbidden",
                message=f"log_format {format_definition.name!r} is not in the approved set.",
                location=_source_location(destination.source),
                declared_scope_id=destination.declared_scope_id,
                effective_scope_id=destination.effective_scope_id,
                values=(format_definition.name,),
            )
        )
    else:
        evidence.append(
            _route_evidence(
                status="allowed",
                message=f"log_format {format_definition.name!r} is approved.",
                location=_source_location(destination.source),
                declared_scope_id=destination.declared_scope_id,
                effective_scope_id=destination.effective_scope_id,
                values=(format_definition.name,),
            )
        )

    if (
        policy.formats.require_escape is not None
        and format_definition.escape_mode != policy.formats.require_escape
    ):
        failed = True
        evidence.append(
            _route_evidence(
                status="forbidden",
                message=(
                    "log_format escape mode does not satisfy the declared policy."
                ),
                location=_source_location(destination.source),
                declared_scope_id=destination.declared_scope_id,
                effective_scope_id=destination.effective_scope_id,
                values=(format_definition.escape_mode,),
            )
        )

    normalized_variables = {_normalize_variable(variable) for variable in format_definition.variables}
    forbidden = {_normalize_variable(variable) for variable in policy.formats.forbidden_variables}
    overlap = sorted(normalized_variables & forbidden)
    if overlap:
        failed = True
        evidence.append(
            _route_evidence(
                status="forbidden",
                message="The format includes forbidden raw variables.",
                location=_source_location(destination.source),
                declared_scope_id=destination.declared_scope_id,
                effective_scope_id=destination.effective_scope_id,
                values=tuple(overlap),
            )
        )

    for group_name, variables in policy.formats.required_field_groups.items():
        alternatives = {_normalize_variable(variable) for variable in variables}
        present = sorted(normalized_variables & alternatives)
        if present:
            present_groups[group_name].extend(present)
            evidence.append(
                _route_evidence(
                    status="allowed",
                    message=f"Required field group {group_name!r} is present.",
                    location=_source_location(destination.source),
                    declared_scope_id=destination.declared_scope_id,
                    effective_scope_id=destination.effective_scope_id,
                    values=tuple(present),
                )
            )
            continue
        failed = True
        missing_groups[group_name].extend(sorted(alternatives))
        evidence.append(
            _route_evidence(
                status="missing",
                message=f"Required field group {group_name!r} is missing.",
                location=_source_location(destination.source),
                declared_scope_id=destination.declared_scope_id,
                effective_scope_id=destination.effective_scope_id,
                values=tuple(sorted(alternatives)),
            )
        )

    return {
        "evidence": evidence,
        "failed": failed,
        "indeterminate": indeterminate,
        "present_groups": present_groups,
        "missing_groups": missing_groups,
    }


def _condition_result(
    destination: AccessLogDestination,
    policy: NginxAccessLoggingPolicy,
) -> dict[str, object] | None:
    if destination.condition_kind == "unconditional":
        return None
    if destination.condition_kind == "constant_false":
        return {
            "evidence": _route_evidence(
                status="missing",
                message="The access_log destination is statically disabled by if=0 or an empty literal.",
                location=_source_location(destination.source),
                declared_scope_id=destination.declared_scope_id,
                effective_scope_id=destination.effective_scope_id,
            ),
            "failed": False,
            "indeterminate": False,
            "runtime_dependent": False,
        }
    if destination.condition_kind == "constant_true":
        return {
            "evidence": _route_evidence(
                status="allowed",
                message="The access_log destination is conditionally configured but statically true.",
                location=_source_location(destination.source),
                declared_scope_id=destination.declared_scope_id,
                effective_scope_id=destination.effective_scope_id,
            ),
            "failed": False,
            "indeterminate": False,
            "runtime_dependent": False,
        }

    failed = False
    indeterminate = False
    runtime_dependent = False
    if policy.conditional.mode == "forbid":
        failed = True
    elif policy.conditional.mode == "allow_listed":
        allowed_conditions = {
            _normalize_text(condition)
            for condition in policy.conditional.allowed_conditions
        }
        if _normalize_text(destination.condition or "") not in allowed_conditions:
            failed = True
        else:
            indeterminate = True
            runtime_dependent = True
    else:
        indeterminate = True
        runtime_dependent = True

    status = "forbidden" if failed else "runtime-dependent" if indeterminate else "allowed"
    message = (
        "Dynamic conditional logging is forbidden by policy."
        if failed
        else "Dynamic conditional logging depends on runtime values and cannot prove request-by-request coverage."
    )
    return {
        "evidence": _route_evidence(
            status=status,
            message=message,
            location=_source_location(destination.source),
            declared_scope_id=destination.declared_scope_id,
            effective_scope_id=destination.effective_scope_id,
            values=((destination.condition or ""),),
        ),
        "failed": failed,
        "indeterminate": indeterminate,
        "runtime_dependent": runtime_dependent,
    }


def _access_destination_allowed(
    destination: AccessLogDestination,
    policy: NginxAccessLoggingPolicy,
) -> dict[str, object]:
    failed = False
    indeterminate = False
    if destination.destination_kind == "variable_path":
        if not policy.destinations.allow_variable_paths:
            failed = True
        else:
            indeterminate = True
    elif destination.destination_kind == "unknown":
        indeterminate = True
    elif policy.destinations.allowed and not any(
        _matches_allowed_destination(destination, allowed)
        for allowed in policy.destinations.allowed
    ):
        failed = True

    status = "indeterminate" if indeterminate else "forbidden" if failed else "allowed"
    message = (
        "The access_log destination cannot be fully resolved or inventory-verified."
        if indeterminate
        else "The access_log destination is not approved by policy."
        if failed
        else "The access_log destination is approved by policy."
    )
    return {
        "status": status,
        "message": message,
        "failed": failed,
        "indeterminate": indeterminate,
    }


def _matches_allowed_destination(
    destination: AccessLogDestination,
    allowed: NginxAccessDestinationEntry,
) -> bool:
    if destination.destination_kind != allowed.kind:
        return False
    if allowed.kind == "file":
        return destination.raw_path == allowed.path
    if allowed.kind == "syslog":
        return destination.raw_path.startswith(allowed.prefix or "")
    return True


def _assessment(
    *,
    control_id: str,
    title: str,
    status: str,
    summary: str,
    scope: NginxScope,
    server_names: tuple[str, ...],
    profile: NginxLoggingProfile,
    evidence: tuple[ControlAssessmentEvidence, ...],
    related_rule_ids: tuple[str, ...],
    metadata: dict[str, object],
) -> PolicyControlAssessment:
    return PolicyControlAssessment(
        control_id=control_id,
        title=title,
        status=status,  # type: ignore[arg-type]
        scope=ControlAssessmentScope(
            server_scope_id=metadata["server_scope_id"],  # type: ignore[arg-type]
            route_scope_id=scope.scope_id,
            route_selector=scope.selector,
            server_name=server_names[0] if server_names else None,
        ),
        summary=summary,
        evidence=evidence,
        related_rule_ids=related_rule_ids,
        policy_source=f"{_POLICY_SECTION}.{profile.profile_id}",
        metadata=metadata,
    )


def _unmatched_assessment(
    *,
    scope_graph: NginxScopeGraph,
    scope: NginxScope,
    server_names: tuple[str, ...],
    logging_kind: str,
    status: str,
) -> PolicyControlAssessment:
    return PolicyControlAssessment(
        control_id=_GENERIC_CONTROL_ID,
        title=_GENERIC_TITLE,
        status=status,  # type: ignore[arg-type]
        scope=ControlAssessmentScope(
            server_scope_id=_server_scope_id(scope, scope_graph),
            route_scope_id=scope.scope_id,
            route_selector=scope.selector,
            server_name=server_names[0] if server_names else None,
        ),
        summary="The scope did not match any nginx.logging profile.",
        evidence=(),
        related_rule_ids=(),
        policy_source=_POLICY_SECTION,
        metadata={
            "policy_section": _POLICY_SECTION,
            "profile_id": None,
            "server_scope_id": _server_scope_id(scope, scope_graph),
            "logging_scope_id": scope.scope_id,
            "logging_kind": logging_kind,
            "server_names": list(server_names),
            "effective_destinations": [],
            "indeterminate_reasons": [],
        },
    )


def _server_scope_id(scope: NginxScope, scope_graph: NginxScopeGraph) -> str:
    if scope.kind == NginxScopeKind.SERVER:
        return scope.scope_id
    current = scope
    while current.kind != NginxScopeKind.SERVER and current.parent_id is not None:
        current = scope_graph.scopes_by_id[current.parent_id]
    return current.scope_id


def _server_names_by_scope(
    scope_graph: NginxScopeGraph,
) -> dict[str, tuple[str, ...]]:
    server_names_for_server_scope: dict[str, tuple[str, ...]] = {}
    for scope in scope_graph.scopes:
        if scope.kind != NginxScopeKind.SERVER:
            continue
        names: list[str] = []
        for node in scope_graph.scope_nodes.get(scope.scope_id, ()):
            if not isinstance(node, DirectiveNode) or node.name != "server_name":
                continue
            names.extend(node.args)
        server_names_for_server_scope[scope.scope_id] = tuple(names)

    names_by_scope: dict[str, tuple[str, ...]] = {}
    for scope in scope_graph.scopes:
        current = scope
        while current.kind != NginxScopeKind.SERVER and current.parent_id is not None:
            current = scope_graph.scopes_by_id[current.parent_id]
        names_by_scope[scope.scope_id] = server_names_for_server_scope.get(current.scope_id, ())
    return names_by_scope


def _assessment_sort_key(
    assessment: PolicyControlAssessment,
) -> tuple[str, str, str]:
    metadata = assessment.metadata
    return (
        str(metadata.get("server_scope_id", "")),
        str(metadata.get("logging_scope_id", "")),
        str(metadata.get("logging_kind", "")),
    )


def _related_rule_ids(findings: tuple[object, ...], *rule_ids: str) -> tuple[str, ...]:
    present = set()
    for finding in findings:
        rule_id = getattr(finding, "rule_id", None)
        if rule_id in rule_ids:
            present.add(rule_id)
    return tuple(sorted(present))


def _route_evidence(
    *,
    status: str,
    message: str,
    location: SourceLocation | None = None,
    declared_scope_id: str | None = None,
    effective_scope_id: str | None = None,
    values: tuple[str, ...] = (),
) -> ControlAssessmentEvidence:
    locations = (location,) if location is not None else ()
    return ControlAssessmentEvidence(
        kind="route",
        status=status,
        message=message,
        locations=locations,
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


def _access_destination_payload(destination: AccessLogDestination) -> dict[str, object]:
    return {
        "destination_kind": destination.destination_kind,
        "raw_path": destination.raw_path,
        "format_name": destination.format_name,
        "condition": destination.condition,
        "condition_kind": destination.condition_kind,
        "declared_scope_id": destination.declared_scope_id,
        "effective_scope_id": destination.effective_scope_id,
        "origin": destination.origin,
        "source": _source_payload(destination.source),
    }


def _error_destination_payload(destination: ErrorLogDestination) -> dict[str, object]:
    return {
        "destination_kind": destination.destination_kind,
        "raw_path": destination.raw_path,
        "threshold": destination.threshold,
        "json_mode": destination.json_mode,
        "declared_scope_id": destination.declared_scope_id,
        "effective_scope_id": destination.effective_scope_id,
        "origin": destination.origin,
        "source": _source_payload(destination.source),
    }


def _source_payload(source: SourceSpan | None) -> dict[str, object] | None:
    if source is None:
        return None
    return {
        "file_path": source.file_path,
        "line": source.line,
        "column": source.column,
    }


def _destination_values(destination: AccessLogDestination) -> tuple[str, ...]:
    values = [destination.raw_path, destination.format_name]
    if destination.condition is not None:
        values.append(destination.condition)
    return tuple(values)


def _error_destination_values(destination: ErrorLogDestination) -> tuple[str, ...]:
    values = [destination.raw_path, destination.threshold]
    if destination.json_mode:
        values.append("json")
    return tuple(values)


def _normalize_text(value: str) -> str:
    return " ".join(value.strip().split())


def _normalize_variable(value: str) -> str:
    stripped = value.strip()
    if stripped.startswith("${") and stripped.endswith("}"):
        return f"${stripped[2:-1]}"
    return stripped


__all__ = ["evaluate_logging_policy"]
