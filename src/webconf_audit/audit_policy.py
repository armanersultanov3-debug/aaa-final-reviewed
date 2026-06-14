"""Audit policy loading, validation, resolution, and result attachment."""

from __future__ import annotations

from datetime import datetime, timezone
from fnmatch import fnmatchcase
import hashlib
import ipaddress
import json
from pathlib import Path, PurePath
import re
from typing import Any

from pydantic import ValidationError
import yaml
from yaml.constructor import ConstructorError
from yaml.nodes import MappingNode
from yaml.resolver import BaseResolver
from yaml.tokens import AliasToken, AnchorToken, ScalarToken, TagToken

from webconf_audit.coverage_ledger import DEFAULT_LEDGER_MAX_BYTES
from webconf_audit.coverage_models import CoverageItem, CoverageLedger, CoverageSource
from webconf_audit.execution_manifest import (
    RuleExecutionManifest,
    RuleExecutionRecorder,
    RuleSelection,
    build_rule_execution_manifest,
    registry_revision as current_registry_revision,
)
from webconf_audit.models import AnalysisResult, rebuild_analysis_result_models
from webconf_audit.policy_models import (
    AuditPolicy,
    AuditPolicyIssue,
    AuditTarget,
    ControlPolicy,
    LoadedPolicyProvenance,
    NginxLocationSelector,
    NginxLoggingProfile,
    NginxLoggingSelector,
    NginxPolicy,
    NginxSensitiveLocationEntry,
    ResolvedAuditPolicy,
    ResolvedControlPolicy,
    ResolvedSourcePolicy,
    ResolvedTarget,
    ReverseProxyHeaderProfile,
    ReverseProxyRouteSelector,
    SourcePolicy,
    TargetSelector,
)
from webconf_audit.rule_registry import OPT_IN_TAGS, RuleRegistry

DEFAULT_POLICY_MAX_BYTES = DEFAULT_LEDGER_MAX_BYTES

rebuild_analysis_result_models()


class _UniqueKeySafeLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate mapping keys."""


def _construct_unique_mapping(
    loader: yaml.SafeLoader,
    node: MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as exc:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found an unhashable mapping key",
                key_node.start_mark,
            ) from exc
        if duplicate:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeySafeLoader.add_constructor(
    BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


class AuditPolicyLoadError(ValueError):
    """Raised when a policy file cannot be loaded into a trusted model."""

    def __init__(self, issue: AuditPolicyIssue) -> None:
        super().__init__(issue.message)
        self.issue = issue


class AuditPolicyResolveError(ValueError):
    """Raised when a validated policy cannot resolve a single target profile."""

    def __init__(self, issue: AuditPolicyIssue) -> None:
        super().__init__(issue.message)
        self.issue = issue


def load_audit_policy(
    path: Path,
    *,
    max_bytes: int = DEFAULT_POLICY_MAX_BYTES,
) -> AuditPolicy:
    """Load a local policy YAML file with safe bounded parsing."""
    display_path = str(path)
    try:
        size = path.stat().st_size
    except FileNotFoundError as exc:
        raise _load_error(
            "policy_file_not_found",
            f"Audit policy was not found: {path}",
            path=display_path,
        ) from exc
    except OSError as exc:
        raise _load_error(
            "policy_file_not_found",
            f"Audit policy could not be read: {path}",
            path=display_path,
        ) from exc
    if size > max_bytes:
        raise _load_error(
            "policy_file_too_large",
            f"Audit policy exceeds the {max_bytes}-byte limit: {path}",
            path=display_path,
        )
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise _load_error(
            "policy_file_not_found",
            f"Audit policy could not be read: {path}",
            path=display_path,
        ) from exc

    if len(payload) > max_bytes:
        raise _load_error(
            "policy_file_too_large",
            f"Audit policy exceeds the {max_bytes}-byte limit: {path}",
            path=display_path,
        )
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _load_error(
            "policy_yaml_invalid",
            "Audit policy must be UTF-8 encoded.",
            path=display_path,
        ) from exc

    _reject_unsafe_yaml(text, display_path)
    try:
        raw = yaml.load(text, Loader=_UniqueKeySafeLoader)
    except yaml.YAMLError as exc:
        raise _load_error(
            "policy_yaml_invalid",
            f"Audit policy YAML is invalid: {exc}",
            path=display_path,
        ) from exc
    if not isinstance(raw, dict):
        raise _load_error(
            "policy_schema_invalid",
            "Audit policy root must be a mapping.",
            path=display_path,
        )
    _reject_non_string_keys(raw, display_path)
    if raw.get("schema_version") != 1:
        raise _load_error(
            "policy_schema_unsupported",
            f"Unsupported audit policy schema_version: {raw.get('schema_version')!r}.",
            path=display_path,
        )
    try:
        policy = AuditPolicy.model_validate(raw)
    except ValidationError as exc:
        raise _load_error(
            "policy_schema_invalid",
            f"Audit policy schema is invalid: {exc}",
            path=display_path,
        ) from exc

    loaded_provenance = LoadedPolicyProvenance(
        path=display_path,
        sha256=hashlib.sha256(payload).hexdigest(),
        loaded_at=datetime.now(timezone.utc),
    )
    return policy.model_copy(update={"loaded_provenance": loaded_provenance})


def validate_audit_policy(
    policy: AuditPolicy,
    ledger: CoverageLedger,
    registry: RuleRegistry,
) -> tuple[AuditPolicyIssue, ...]:
    """Return all safe-to-accumulate semantic policy defects."""
    issues: list[AuditPolicyIssue] = []
    ledger_sources = {source.source_id: source for source in ledger.sources}
    ledger_items = {
        item.item_id: (source, item)
        for source in ledger.sources
        for item in source.items
    }

    seen_profile_ids: set[str] = set()
    for profile in policy.profiles:
        if profile.profile_id in seen_profile_ids:
            issues.append(
                AuditPolicyIssue(
                    code="duplicate_profile_id",
                    message=f"Duplicate profile_id {profile.profile_id!r}.",
                    profile_id=profile.profile_id,
                )
            )
        seen_profile_ids.add(profile.profile_id)
        issues.extend(_validate_profile_selectors(profile.profile_id, profile.selectors))
        issues.extend(_validate_requested_tags(profile.profile_id, profile.requested_opt_in_tags))

        seen_source_ids: set[str] = set()
        for source_policy in profile.sources:
            if source_policy.source_id in seen_source_ids:
                issues.append(
                    AuditPolicyIssue(
                        code="duplicate_source_policy",
                        message=(
                            f"Profile {profile.profile_id!r} repeats source_id "
                            f"{source_policy.source_id!r}."
                        ),
                        profile_id=profile.profile_id,
                        source_id=source_policy.source_id,
                    )
                )
            seen_source_ids.add(source_policy.source_id)

            ledger_source = ledger_sources.get(source_policy.source_id)
            if ledger_source is None:
                issues.append(
                    AuditPolicyIssue(
                        code="unknown_source_id",
                        message=f"Unknown source_id {source_policy.source_id!r}.",
                        profile_id=profile.profile_id,
                        source_id=source_policy.source_id,
                    )
                )
                continue

            issues.extend(
                _validate_source_policy(
                    profile_id=profile.profile_id,
                    source_policy=source_policy,
                    ledger_source=ledger_source,
                    ledger_items=ledger_items,
                    registry=registry,
                )
            )

    issues.extend(_validate_nginx_policy(policy.nginx))

    unique = {issue: None for issue in issues}
    return tuple(sorted(unique.keys(), key=_issue_sort_key))


def resolve_audit_policy(
    policy: AuditPolicy,
    target: AuditTarget,
    ledger: CoverageLedger,
) -> ResolvedAuditPolicy:
    """Resolve exactly one target profile and expand inherited item defaults."""
    target_issue = _target_issue(target)
    if target_issue is not None:
        raise AuditPolicyResolveError(target_issue)

    normalized_target = _normalize_target_label(target.mode, target.target)
    matching_profiles = [
        profile
        for profile in policy.profiles
        if any(
            _selector_matches(selector, target, normalized_target)
            for selector in profile.selectors
        )
    ]
    if not matching_profiles:
        raise AuditPolicyResolveError(
            AuditPolicyIssue(
                code="no_matching_profile",
                message=(
                    "Audit policy does not define a matching profile for "
                    f"{target.mode}:{target.server_type or 'generic'}:{target.target}."
                ),
                path=policy.loaded_provenance.path if policy.loaded_provenance else None,
            )
        )
    if len(matching_profiles) > 1:
        raise AuditPolicyResolveError(
            AuditPolicyIssue(
                code="multiple_matching_profiles",
                message=(
                    "Audit policy resolved more than one matching profile for "
                    f"{target.mode}:{target.server_type or 'generic'}:{target.target}."
                ),
                profile_id=",".join(profile.profile_id for profile in matching_profiles),
                path=policy.loaded_provenance.path if policy.loaded_provenance else None,
            )
        )

    profile = matching_profiles[0]
    ledger_sources = {source.source_id: source for source in ledger.sources}
    resolved_sources = tuple(
        _resolve_source_policy(policy, source_policy, ledger_sources[source_policy.source_id])
        for source_policy in profile.sources
    )
    raw_sha256 = _raw_policy_sha(policy)
    resolved = ResolvedAuditPolicy(
        schema_version=1,
        policy_id=policy.policy_id,
        policy_version=policy.policy_version,
        profile_id=profile.profile_id,
        raw_sha256=raw_sha256,
        resolved_sha256="0" * 64,
        target=ResolvedTarget(
            mode=target.mode,
            server_type=target.server_type,
            target=normalized_target,
        ),
        requested_opt_in_tags=profile.requested_opt_in_tags,
        sources=resolved_sources,
        nginx=policy.nginx,
    )
    return resolved.model_copy(
        update={"resolved_sha256": _resolved_policy_sha(resolved)}
    )


def requested_opt_in_tags(
    resolved_policy: ResolvedAuditPolicy | None,
) -> frozenset[str]:
    """Return the effective policy-requested opt-in tags."""
    if resolved_policy is None:
        return frozenset()
    return frozenset(resolved_policy.requested_opt_in_tags)


def required_rule_ids(
    resolved_policy: ResolvedAuditPolicy | None,
) -> frozenset[str]:
    """Return every explicitly required rule_id from a resolved policy."""
    if resolved_policy is None:
        return frozenset()
    return frozenset(
        rule_id
        for source in resolved_policy.sources
        for control in source.controls
        for rule_id in control.required_rule_ids
    )


def attach_audit_context(
    result: AnalysisResult,
    policy: ResolvedAuditPolicy | None,
    manifest: RuleExecutionManifest,
) -> AnalysisResult:
    """Attach typed policy/manifest data and additive JSON-safe metadata."""
    attached = result.model_copy(deep=True)
    metadata = dict(attached.metadata)
    metadata["audit_policy"] = (
        policy.model_dump(mode="json")
        if policy is not None
        else None
    )
    metadata["rule_execution"] = manifest.model_dump(mode="json")
    attached.metadata = metadata
    attached.audit_policy = policy
    attached.rule_execution = manifest
    return attached


def build_analysis_manifest(
    *,
    recorder: RuleExecutionRecorder,
    policy: ResolvedAuditPolicy | None,
    mode: str,
    server_type: str | None,
    registry: RuleRegistry,
) -> RuleExecutionManifest:
    """Build a manifest for one analysis result, including policy-required skips."""
    for rule_id in sorted(required_rule_ids(policy)):
        if rule_id in recorder.selected_rule_ids():
            continue
        recorder.select(rule_id)
        recorder.skipped(
            rule_id,
            reason=_required_rule_skip_reason(
                rule_id,
                mode=mode,
                server_type=server_type,
                registry=registry,
            ),
        )

    selection = RuleSelection(
        registry_revision=current_registry_revision(registry),
        selected_rule_ids=recorder.selected_rule_ids(),
    )
    return build_rule_execution_manifest(selection, recorder.events())


def _validate_profile_selectors(
    profile_id: str,
    selectors: tuple[TargetSelector, ...],
) -> list[AuditPolicyIssue]:
    issues: list[AuditPolicyIssue] = []
    for selector in selectors:
        selector_issue = _selector_issue(selector, profile_id=profile_id)
        if selector_issue is not None:
            issues.append(selector_issue)
    return issues


def _validate_requested_tags(
    profile_id: str,
    tags: tuple[str, ...],
) -> list[AuditPolicyIssue]:
    return [
        AuditPolicyIssue(
            code="unknown_opt_in_tag",
            message=f"Unknown opt-in tag {tag!r}.",
            profile_id=profile_id,
        )
        for tag in tags
        if tag not in OPT_IN_TAGS
    ]


_ALL_UPSTREAM_FAMILIES = frozenset({"proxy", "fastcgi", "grpc", "uwsgi"})


def _validate_nginx_policy(
    nginx_policy: NginxPolicy | None,
) -> list[AuditPolicyIssue]:
    issues: list[AuditPolicyIssue] = []
    if nginx_policy is None:
        return issues

    if nginx_policy.reverse_proxy_headers is not None:
        issues.extend(_validate_nginx_reverse_proxy_policy(nginx_policy))
    if nginx_policy.logging is not None:
        issues.extend(_validate_nginx_logging_policy(nginx_policy))
    if nginx_policy.sensitive_locations is not None:
        issues.extend(_validate_nginx_sensitive_location_policy(nginx_policy))
    return issues


def _validate_nginx_reverse_proxy_policy(
    nginx_policy: NginxPolicy,
) -> list[AuditPolicyIssue]:
    issues: list[AuditPolicyIssue] = []
    section = nginx_policy.reverse_proxy_headers
    assert section is not None
    profiles = section.profiles
    seen_profile_ids: set[str] = set()
    for profile in profiles:
        if profile.profile_id in seen_profile_ids:
            issues.append(
                AuditPolicyIssue(
                    code="duplicate_nginx_reverse_proxy_profile_id",
                    message=(
                        "nginx.reverse_proxy_headers repeats profile_id "
                        f"{profile.profile_id!r}."
                    ),
                    profile_id=profile.profile_id,
                )
            )
        seen_profile_ids.add(profile.profile_id)

    for index, profile in enumerate(profiles):
        for other in profiles[index + 1 :]:
            if not _reverse_proxy_selectors_overlap(profile.applies_to, other.applies_to):
                continue
            if _normalized_reverse_proxy_profile(profile) == _normalized_reverse_proxy_profile(other):
                continue
            issues.append(
                AuditPolicyIssue(
                    code="overlapping_nginx_reverse_proxy_profiles",
                    message=(
                        "nginx.reverse_proxy_headers profiles "
                        f"{profile.profile_id!r} and {other.profile_id!r} overlap "
                        "without equivalent normalized requirements."
                    ),
                    profile_id=f"{profile.profile_id},{other.profile_id}",
                )
            )

    return issues


def _validate_nginx_logging_policy(
    nginx_policy: NginxPolicy,
) -> list[AuditPolicyIssue]:
    issues: list[AuditPolicyIssue] = []
    section = nginx_policy.logging
    assert section is not None
    profiles = section.profiles
    seen_profile_ids: set[str] = set()
    for profile in profiles:
        if profile.profile_id in seen_profile_ids:
            issues.append(
                AuditPolicyIssue(
                    code="duplicate_nginx_logging_profile_id",
                    message=(
                        "nginx.logging repeats profile_id "
                        f"{profile.profile_id!r}."
                    ),
                    profile_id=profile.profile_id,
                )
            )
        seen_profile_ids.add(profile.profile_id)

    for index, profile in enumerate(profiles):
        for other in profiles[index + 1 :]:
            if not _logging_selectors_overlap(profile.applies_to, other.applies_to):
                continue
            if _normalized_logging_profile(profile) == _normalized_logging_profile(other):
                continue
            issues.append(
                AuditPolicyIssue(
                    code="overlapping_nginx_logging_profiles",
                    message=(
                        "nginx.logging profiles "
                        f"{profile.profile_id!r} and {other.profile_id!r} overlap "
                        "without equivalent normalized requirements."
                    ),
                    profile_id=f"{profile.profile_id},{other.profile_id}",
                )
            )

    return issues


def _validate_nginx_sensitive_location_policy(
    nginx_policy: NginxPolicy,
) -> list[AuditPolicyIssue]:
    issues: list[AuditPolicyIssue] = []
    section = nginx_policy.sensitive_locations
    assert section is not None
    catalog = section.catalog
    seen_entry_ids: set[str] = set()
    for entry in catalog:
        if entry.entry_id in seen_entry_ids:
            issues.append(
                AuditPolicyIssue(
                    code="duplicate_nginx_sensitive_location_entry_id",
                    message=(
                        "nginx.sensitive_locations repeats entry_id "
                        f"{entry.entry_id!r}."
                    ),
                    item_id=entry.entry_id,
                )
            )
        seen_entry_ids.add(entry.entry_id)

    for index, entry in enumerate(catalog):
        for other in catalog[index + 1 :]:
            if not _sensitive_location_entries_overlap(entry, other):
                continue
            if _normalized_sensitive_location_entry(entry) == _normalized_sensitive_location_entry(other):
                continue
            issues.append(
                AuditPolicyIssue(
                    code="overlapping_nginx_sensitive_location_entries",
                    message=(
                        "nginx.sensitive_locations entries "
                        f"{entry.entry_id!r} and {other.entry_id!r} overlap "
                        "without equivalent normalized requirements."
                    ),
                    item_id=f"{entry.entry_id},{other.entry_id}",
                )
            )
    return issues


def _reverse_proxy_selectors_overlap(
    left: ReverseProxyRouteSelector,
    right: ReverseProxyRouteSelector,
) -> bool:
    return (
        _selector_dimension_overlap(
            left.upstream_families,
            right.upstream_families,
            all_values=_ALL_UPSTREAM_FAMILIES,
            normalize=lambda value: value,
        )
        and _selector_dimension_overlap(
            left.server_names,
            right.server_names,
            all_values=None,
            normalize=lambda value: value.lower(),
        )
        and _selector_dimension_overlap(
            left.location_patterns,
            right.location_patterns,
            all_values=None,
            normalize=_normalize_expression,
        )
    )


def _selector_dimension_overlap(
    left: tuple[str, ...],
    right: tuple[str, ...],
    *,
    all_values: frozenset[str] | None,
    normalize,
) -> bool:
    if not left or not right:
        return True
    left_values = {normalize(value) for value in left}
    right_values = {normalize(value) for value in right}
    if all_values is not None:
        if left_values == all_values or right_values == all_values:
            return True
    return bool(left_values & right_values)


def _logging_selectors_overlap(
    left: NginxLoggingSelector,
    right: NginxLoggingSelector,
) -> bool:
    return (
        _selector_dimension_overlap(
            left.server_names,
            right.server_names,
            all_values=None,
            normalize=lambda value: value.lower(),
        )
        and _selector_dimension_overlap(
            left.location_patterns,
            right.location_patterns,
            all_values=None,
            normalize=_normalize_expression,
        )
    )


def _sensitive_location_entries_overlap(
    left: NginxSensitiveLocationEntry,
    right: NginxSensitiveLocationEntry,
) -> bool:
    if not _selector_dimension_overlap(
        left.server_names,
        right.server_names,
        all_values=None,
        normalize=lambda value: value.lower(),
    ):
        return False

    left_samples = {_normalize_sensitive_uri(value) for value in left.sample_uris}
    right_samples = {_normalize_sensitive_uri(value) for value in right.sample_uris}
    if left_samples & right_samples:
        return True

    if (
        left.declared_location is not None
        and right.declared_location is not None
        and _normalized_location_selector(left.declared_location)
        == _normalized_location_selector(right.declared_location)
    ):
        return True

    if left.declared_location is not None and any(
        _sample_matches_declared_location(sample, left.declared_location)
        for sample in right_samples
    ):
        return True

    if right.declared_location is not None and any(
        _sample_matches_declared_location(sample, right.declared_location)
        for sample in left_samples
    ):
        return True

    return False


def _normalized_reverse_proxy_profile(
    profile: ReverseProxyHeaderProfile,
) -> dict[str, object]:
    request_required = {
        header.lower(): sorted(
            {
                _normalize_expression(value)
                for value in requirement.any_of
            }
        )
        for header, requirement in profile.request_headers.required.items()
    }
    host_policy = profile.request_headers.host
    return {
        "selector": {
            "upstream_families": sorted(set(profile.applies_to.upstream_families)),
            "server_names": sorted(
                {
                    server_name.lower()
                    for server_name in profile.applies_to.server_names
                }
            ),
            "location_patterns": sorted(
                {
                    _normalize_expression(pattern)
                    for pattern in profile.applies_to.location_patterns
                }
            ),
        },
        "request": {
            "required": request_required,
            "host": (
                {
                    "allowed_values": sorted(
                        {
                            _normalize_expression(value)
                            for value in host_policy.allowed_values
                        }
                    ),
                    "allow_fixed_literals": host_policy.allow_fixed_literals,
                }
                if host_policy is not None
                else None
            ),
            "forbidden_client_variables": sorted(
                {
                    _normalize_expression(value).lower()
                    for value in profile.request_headers.forbidden_client_variables
                }
            ),
        },
        "response": {
            "must_hide": sorted(
                {header.lower() for header in profile.response_headers.must_hide}
            ),
            "must_not_pass": sorted(
                {header.lower() for header in profile.response_headers.must_not_pass}
            ),
            "allow_explicit_pass": sorted(
                {header.lower() for header in profile.response_headers.allow_explicit_pass}
            ),
        },
    }


def _normalized_logging_profile(
    profile: NginxLoggingProfile,
) -> dict[str, object]:
    access = profile.access
    error = profile.error
    return {
        "selector": {
            "server_names": sorted(
                {server_name.lower() for server_name in profile.applies_to.server_names}
            ),
            "location_patterns": sorted(
                {_normalize_expression(pattern) for pattern in profile.applies_to.location_patterns}
            ),
        },
        "access": (
            {
                "required": access.required,
                "allow_off": access.allow_off,
                "conditional": {
                    "mode": access.conditional.mode,
                    "allowed_conditions": sorted(
                        {
                            _normalize_expression(value)
                            for value in access.conditional.allowed_conditions
                        }
                    ),
                },
                "destinations": {
                    "allowed": sorted(
                        (
                            entry.kind,
                            _normalize_expression(entry.path or ""),
                            _normalize_expression(entry.prefix or ""),
                        )
                        for entry in access.destinations.allowed
                    ),
                    "require_at_least_one_remote": access.destinations.require_at_least_one_remote,
                    "allow_variable_paths": access.destinations.allow_variable_paths,
                },
                "formats": {
                    "allowed_names": sorted(
                        {_normalize_expression(value) for value in access.formats.allowed_names}
                    ),
                    "require_escape": access.formats.require_escape,
                    "required_field_groups": {
                        group_name.lower(): sorted(
                            {
                                _normalize_expression(variable).lower()
                                for variable in variables
                            }
                        )
                        for group_name, variables in access.formats.required_field_groups.items()
                    },
                    "forbidden_variables": sorted(
                        {
                            _normalize_expression(variable).lower()
                            for variable in access.formats.forbidden_variables
                        }
                    ),
                },
            }
            if access is not None
            else None
        ),
        "error": (
            {
                "required": error.required,
                "require_explicit_destination": error.require_explicit_destination,
                "allowed_kinds": sorted(set(error.destinations.allowed_kinds)),
                "forbidden_paths": sorted(
                    {_normalize_expression(path) for path in error.destinations.forbidden_paths}
                ),
                "threshold": {
                    "most_restrictive_allowed": error.threshold.most_restrictive_allowed,
                    "allow_debug": error.threshold.allow_debug,
                },
            }
            if error is not None
            else None
        ),
    }


def _normalized_sensitive_location_entry(
    entry: NginxSensitiveLocationEntry,
) -> dict[str, object]:
    return {
        "kind": entry.kind,
        "server_names": sorted({server_name.lower() for server_name in entry.server_names}),
        "declared_location": (
            _normalized_location_selector(entry.declared_location)
            if entry.declared_location is not None
            else None
        ),
        "sample_uris": sorted({_normalize_sensitive_uri(uri) for uri in entry.sample_uris}),
        "exposure": entry.exposure,
        "required_controls": _normalized_sensitive_requirement(entry.required_controls),
    }


def _normalized_location_selector(
    selector: NginxLocationSelector,
) -> dict[str, object]:
    return {
        "modifier": selector.modifier,
        "pattern": _normalize_expression(selector.pattern),
        "source_path": selector.source_path,
    }


def _normalized_sensitive_requirement(requirement) -> dict[str, object]:
    leaf_name = next(
        name
        for name in (
            "internal",
            "deny_all",
            "auth_basic",
            "auth_request",
            "auth_jwt",
            "auth_oidc",
            "ip_allowlist",
        )
        if getattr(requirement, name) is not None
    ) if not requirement.all_of and not requirement.one_of else None
    if leaf_name is not None:
        if leaf_name == "ip_allowlist":
            ip_allowlist = requirement.ip_allowlist
            assert ip_allowlist is not None
            return {
                "leaf": "ip_allowlist",
                "allowed_cidrs": sorted({_normalize_ip_or_cidr(value) for value in ip_allowlist.allowed_cidrs}),
                "require_deny_all_fallback": ip_allowlist.require_deny_all_fallback,
            }
        return {"leaf": leaf_name}
    key = "all_of" if requirement.all_of else "one_of"
    children = requirement.all_of if requirement.all_of else requirement.one_of
    return {
        "composite": key,
        "satisfy": requirement.satisfy,
        "children": [_normalized_sensitive_requirement(child) for child in children],
    }


def _normalize_expression(value: str) -> str:
    return " ".join(value.strip().split())


def _normalize_sensitive_uri(value: str) -> str:
    return _normalize_expression(value)


def _normalize_ip_or_cidr(value: str) -> str:
    normalized = str(value).strip()
    if "/" in normalized:
        return str(ipaddress.ip_network(normalized, strict=True))
    ip_addr = ipaddress.ip_address(normalized)
    suffix = "/32" if ip_addr.version == 4 else "/128"
    return f"{ip_addr.compressed}{suffix}"


def _sample_matches_declared_location(
    sample_uri: str,
    selector: NginxLocationSelector,
) -> bool:
    normalized_sample = _normalize_sensitive_uri(sample_uri)
    pattern = selector.pattern
    if selector.modifier == "exact":
        return normalized_sample == pattern
    if selector.modifier in {"prefix", "prefix_no_regex"}:
        return normalized_sample.startswith(pattern)
    if selector.modifier == "named":
        return False
    flags = re.IGNORECASE if selector.modifier == "regex_i" else 0
    return re.search(pattern, normalized_sample, flags) is not None


def _validate_source_policy(
    *,
    profile_id: str,
    source_policy: SourcePolicy,
    ledger_source: CoverageSource,
    ledger_items: dict[str, tuple[CoverageSource, CoverageItem]],
    registry: RuleRegistry,
) -> list[AuditPolicyIssue]:
    issues: list[AuditPolicyIssue] = []
    seen_control_ids: set[str] = set()
    for control in source_policy.controls:
        if control.item_id in seen_control_ids:
            issues.append(
                AuditPolicyIssue(
                    code="duplicate_control_policy",
                    message=(
                        f"Source policy {source_policy.source_id!r} repeats item_id "
                        f"{control.item_id!r}."
                    ),
                    profile_id=profile_id,
                    source_id=source_policy.source_id,
                    item_id=control.item_id,
                )
            )
        seen_control_ids.add(control.item_id)

        source_and_item = ledger_items.get(control.item_id)
        if source_and_item is None:
            issues.append(
                AuditPolicyIssue(
                    code="unknown_item_id",
                    message=f"Unknown item_id {control.item_id!r}.",
                    profile_id=profile_id,
                    source_id=source_policy.source_id,
                    item_id=control.item_id,
                )
            )
            continue

        actual_source, ledger_item = source_and_item
        if actual_source.source_id != source_policy.source_id:
            issues.append(
                AuditPolicyIssue(
                    code="item_source_mismatch",
                    message=(
                        f"Item {control.item_id!r} belongs to source "
                        f"{actual_source.source_id!r}, not {source_policy.source_id!r}."
                    ),
                    profile_id=profile_id,
                    source_id=source_policy.source_id,
                    item_id=control.item_id,
                )
            )
            continue

        issues.extend(
            _validate_control_policy(
                profile_id=profile_id,
                source_id=source_policy.source_id,
                control=control,
                ledger_item=ledger_item,
                registry=registry,
            )
        )
    return issues


def _validate_control_policy(
    *,
    profile_id: str,
    source_id: str,
    control: ControlPolicy,
    ledger_item: CoverageItem,
    registry: RuleRegistry,
) -> list[AuditPolicyIssue]:
    issues: list[AuditPolicyIssue] = []
    if (
        control.disposition == "not-applicable"
        and control.required_rule_ids
    ):
        issues.append(
            AuditPolicyIssue(
                code="invalid_not_applicable_override",
                message=(
                    "A not-applicable control override cannot require rule evidence."
                ),
                profile_id=profile_id,
                source_id=source_id,
                item_id=control.item_id,
            )
        )
    if (
        control.evidence_expectation == "operator-review"
        and control.disposition != "review"
    ):
        issues.append(
            AuditPolicyIssue(
                code="invalid_review_expectation",
                message=(
                    "operator-review evidence expectation requires disposition 'review'."
                ),
                profile_id=profile_id,
                source_id=source_id,
                item_id=control.item_id,
            )
        )

    for rule_id in control.required_rule_ids:
        if registry.get_meta(rule_id) is None:
            issues.append(
                AuditPolicyIssue(
                    code="unknown_rule_id",
                    message=f"Unknown rule_id {rule_id!r}.",
                    profile_id=profile_id,
                    source_id=source_id,
                    item_id=control.item_id,
                    rule_id=rule_id,
                )
            )
            continue
        if rule_id not in ledger_item.evidence.rule_ids:
            issues.append(
                AuditPolicyIssue(
                    code="rule_not_evidence_for_item",
                    message=(
                        f"Rule {rule_id!r} is not registered as evidence for "
                        f"{control.item_id!r}."
                    ),
                    profile_id=profile_id,
                    source_id=source_id,
                    item_id=control.item_id,
                    rule_id=rule_id,
                )
            )
            continue
        if (
            control.evidence_expectation == "declared-direct"
            and not _has_declared_direct_evidence(ledger_item, rule_id)
        ):
            issues.append(
                AuditPolicyIssue(
                    code="derived_rule_cannot_satisfy_direct",
                    message=(
                        f"Rule {rule_id!r} cannot satisfy declared-direct "
                        f"expectation for {control.item_id!r}."
                    ),
                    profile_id=profile_id,
                    source_id=source_id,
                    item_id=control.item_id,
                    rule_id=rule_id,
                )
            )
    return issues


def _resolve_source_policy(
    policy: AuditPolicy,
    source_policy: SourcePolicy,
    ledger_source: CoverageSource,
) -> ResolvedSourcePolicy:
    control_overrides = {
        control.item_id: control
        for control in source_policy.controls
    }
    source_disposition = source_policy.disposition or policy.defaults.disposition
    inherited_from = (
        "source" if source_policy.disposition is not None else "policy-default"
    )

    resolved_controls = []
    for ledger_item in ledger_source.items:
        if ledger_item.applicability != "applicable":
            continue
        override = control_overrides.get(ledger_item.item_id)
        if override is None:
            resolved_controls.append(
                ResolvedControlPolicy(
                    item_id=ledger_item.item_id,
                    disposition=source_disposition,
                    evidence_expectation=policy.defaults.evidence_expectation,
                    required_rule_ids=(),
                    rationale=_default_rationale(source_disposition, inherited_from),
                    inherited_from=inherited_from,
                )
            )
            continue

        resolved_controls.append(
            ResolvedControlPolicy(
                item_id=override.item_id,
                disposition=override.disposition,
                evidence_expectation=override.evidence_expectation,
                required_rule_ids=override.required_rule_ids,
                rationale=override.rationale,
                ticket_ref=override.ticket_ref,
                review_due=override.review_due,
                inherited_from="control",
            )
        )

    return ResolvedSourcePolicy(
        source_id=source_policy.source_id,
        controls=tuple(resolved_controls),
    )


def _selector_matches(
    selector: TargetSelector,
    target: AuditTarget,
    normalized_target: str,
) -> bool:
    if selector.mode != target.mode:
        return False
    if target.mode == "local" and selector.server_type != target.server_type:
        return False
    if target.mode == "external" and selector.server_type not in {None, "generic"}:
        return False
    if selector.target_glob is None:
        return True
    target_segments = normalized_target.split("/")
    pattern_segments = selector.target_glob.split("/")
    if len(pattern_segments) == 1:
        return fnmatchcase(target_segments[-1], pattern_segments[0])
    if len(target_segments) != len(pattern_segments):
        return False
    return all(
        fnmatchcase(target_segment, pattern_segment)
        for target_segment, pattern_segment in zip(target_segments, pattern_segments)
    )


def _selector_issue(
    selector: TargetSelector,
    *,
    profile_id: str,
) -> AuditPolicyIssue | None:
    if selector.mode == "local" and selector.server_type is None:
        return AuditPolicyIssue(
            code="invalid_target_selector",
            message="Local selectors require server_type in schema version 1.",
            profile_id=profile_id,
        )
    if selector.mode == "external" and selector.server_type not in {None, "generic"}:
        return AuditPolicyIssue(
            code="invalid_target_selector",
            message=(
                "External selectors may omit server_type or use 'generic' only."
            ),
            profile_id=profile_id,
        )
    if selector.target_glob is not None and _unsafe_target_glob(selector.target_glob):
        return AuditPolicyIssue(
            code="unsafe_target_glob",
            message=(
                f"Unsupported or unsafe target_glob {selector.target_glob!r}; "
                "schema version 1 allows only bounded path-segment globs."
            ),
            profile_id=profile_id,
        )
    return None


def _target_issue(target: AuditTarget) -> AuditPolicyIssue | None:
    if target.mode == "local" and target.server_type is None:
        return AuditPolicyIssue(
            code="invalid_target_selector",
            message="Local audit targets require server_type for policy resolution.",
        )
    if target.mode == "external" and target.server_type not in {None, "generic"}:
        return AuditPolicyIssue(
            code="invalid_target_selector",
            message="External audit targets may omit server_type or use 'generic' only.",
        )
    return None


def _unsafe_target_glob(target_glob: str) -> bool:
    if "\\" in target_glob:
        return True
    if "**" in target_glob:
        return True
    if any(token in target_glob for token in ("[", "]", "{", "}", "$")):
        return True
    segments = target_glob.split("/")
    return any(segment in {"..", "."} for segment in segments)


def _has_declared_direct_evidence(item: CoverageItem, rule_id: str) -> bool:
    return any(
        claim.rule_id == rule_id
        and claim.origin == "declared"
        and claim.strength == "direct"
        and _claim_matches_item_reference(item, claim.standard, claim.reference)
        for claim in item.evidence.registry_references
    )


def _claim_matches_item_reference(
    item: CoverageItem,
    standard: str,
    reference: str,
) -> bool:
    return any(
        control.standard == standard
        and (
            control.reference == reference
            or reference in control.grouped_references
        )
        for control in item.references
    )


def _normalize_target_label(mode: str, target: str) -> str:
    if mode == "local":
        return PurePath(target).as_posix()
    return target.strip()


def _raw_policy_sha(policy: AuditPolicy) -> str:
    if policy.loaded_provenance is not None:
        return policy.loaded_provenance.sha256
    payload = json.dumps(
        policy.model_dump(mode="json", exclude={"loaded_provenance"}),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _resolved_policy_sha(policy: ResolvedAuditPolicy) -> str:
    payload = policy.model_dump(mode="json")
    payload["resolved_sha256"] = None
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _default_rationale(disposition: str, inherited_from: str) -> str:
    if inherited_from == "source":
        return f"Inherited from source-level default disposition {disposition!r}."
    return f"Inherited from policy default disposition {disposition!r}."


def _required_rule_skip_reason(
    rule_id: str,
    *,
    mode: str,
    server_type: str | None,
    registry: RuleRegistry,
) -> str:
    meta = registry.get_meta(rule_id)
    if meta is None:
        return "prerequisite-failed"
    if mode == "local" and meta.category == "external":
        return "mode-incompatible"
    if mode == "external" and meta.category in {"local", "universal"}:
        return "mode-incompatible"
    if (
        mode == "local"
        and meta.server_type is not None
        and server_type is not None
        and meta.server_type != server_type
    ):
        return "server-incompatible"
    return "input-unavailable"


def _reject_unsafe_yaml(text: str, display_path: str) -> None:
    try:
        for token in yaml.scan(text):
            if isinstance(token, (AliasToken, AnchorToken, TagToken)):
                raise _load_error(
                    "policy_yaml_invalid",
                    "Audit policy cannot contain YAML aliases, anchors, or tags.",
                    path=display_path,
                )
            if isinstance(token, ScalarToken) and token.value == "<<":
                raise _load_error(
                    "policy_yaml_invalid",
                    "Audit policy cannot contain YAML merge keys.",
                    path=display_path,
                )
    except AuditPolicyLoadError:
        raise
    except yaml.YAMLError as exc:
        raise _load_error(
            "policy_yaml_invalid",
            f"Audit policy YAML is invalid: {exc}",
            path=display_path,
        ) from exc


def _reject_non_string_keys(value: Any, display_path: str) -> None:
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise _load_error(
                "policy_yaml_invalid",
                "Audit policy mappings must use scalar string keys.",
                path=display_path,
            )
        for child in value.values():
            _reject_non_string_keys(child, display_path)
    elif isinstance(value, list):
        for child in value:
            _reject_non_string_keys(child, display_path)


def _load_error(
    code: str,
    message: str,
    *,
    path: str | None = None,
) -> AuditPolicyLoadError:
    return AuditPolicyLoadError(
        AuditPolicyIssue(code=code, message=message, path=path)
    )


def _issue_sort_key(
    issue: AuditPolicyIssue,
) -> tuple[str, str, str, str, str, str, str]:
    return (
        issue.profile_id or "",
        issue.source_id or "",
        issue.item_id or "",
        issue.rule_id or "",
        issue.path or "",
        issue.code,
        issue.message,
    )


__all__ = [
    "AuditPolicyLoadError",
    "AuditPolicyResolveError",
    "DEFAULT_POLICY_MAX_BYTES",
    "attach_audit_context",
    "build_analysis_manifest",
    "load_audit_policy",
    "requested_opt_in_tags",
    "required_rule_ids",
    "resolve_audit_policy",
    "validate_audit_policy",
]
