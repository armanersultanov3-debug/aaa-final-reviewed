from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import socket
import ssl
from typing import Any, Literal

from OpenSSL import SSL as _OSSL
from pydantic import BaseModel, ConfigDict, Field

from webconf_audit.audit_policy import (
    AuditPolicyLoadError,
    AuditPolicyResolveError,
    attach_audit_context,
    build_analysis_manifest,
    load_audit_policy,
    resolve_audit_policy,
    validate_audit_policy,
)
from webconf_audit.coverage_ledger import load_coverage_ledger
from webconf_audit.execution_manifest import RuleExecutionRecorder
from webconf_audit.external.recon import (
    ProbeAttempt,
    ProbeTarget,
    TLSInfo,
    _attempt_to_metadata,
    _build_observed_tls_context,
    _complete_openssl_handshake,
    _extract_tls_info_from_openssl,
)
from webconf_audit.external.recon.tls_probe import (
    DEFAULT_PROBE_TIMEOUT_SECONDS,
    probe_chain_depth,
    probe_ocsp_stapling,
    probe_server_cipher_preference,
    probe_tls_versions,
    supported_protocol_labels,
    verify_certificate_chain,
)
from webconf_audit.external.rules._runner import (
    register_external_rule_metas,
    run_external_tls_rules,
)
from webconf_audit.external.rules._helpers import _hostname_matches_san
from webconf_audit.fingerprints import finding_fingerprint
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
    AuditPolicy,
    AuditTarget,
    TLSInventory,
    TLSInventoryEntry,
    TLSObservationRequirement,
)
from webconf_audit.rule_registry import registry

TLSObservationState = Literal[
    "observed",
    "failed",
    "unavailable",
    "not-requested",
    "not-applicable",
]

_TLS_INVENTORY_CONTROL_ID = "external.tls_inventory"
_BOUNDED_TLS_LIMITATION = (
    "Bounded TLS observation within the declared endpoint/SNI inventory."
)
_TLS_FINDING_REQUIREMENTS: dict[str, TLSObservationRequirement] = {
    "external.cert_chain_incomplete": "certificate_chain",
    "external.cert_chain_length_unusual": "certificate_chain",
    "external.cert_san_mismatch": "certificate_name",
    "external.certificate_expired": "certificate_chain",
    "external.certificate_expires_soon": "certificate_chain",
    "external.ocsp_stapling_not_observed": "ocsp_stapling",
    "external.tls_1_0_supported": "protocol_support",
    "external.tls_1_1_supported": "protocol_support",
    "external.tls_1_3_not_supported": "protocol_support",
    "external.tls_aead_cipher_not_negotiated": "negotiated_cipher",
    "external.tls_certificate_self_signed": "certificate_chain",
    "external.tls_ct_log_evidence_missing": "certificate_chain",
    "external.tls_forward_secrecy_not_observed": "negotiated_cipher",
    "external.tls_must_staple_not_observed": "ocsp_stapling",
    "external.tls_negotiated_compression": "negotiated_cipher",
    "external.tls_secure_renegotiation_not_observed": "negotiated_cipher",
    "external.tls_server_cipher_preference_not_observed": "negotiated_cipher",
    "external.tls_weak_signature_algorithm": "certificate_chain",
    "external.weak_cipher_suite": "negotiated_cipher",
}


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class TLSObservation(_StrictModel):
    requirement: TLSObservationRequirement
    state: TLSObservationState
    reason: str
    evidence_refs: tuple[str, ...] = Field(default=(), max_length=128)


class TLSInventoryIdentity(_StrictModel):
    connect_host: str
    connect_port: int
    sni_name: str | None = None
    http_host: str | None = None


class TLSInventoryEntryResult(_StrictModel):
    schema_version: Literal[1] = 1
    inventory_id: str
    entry_id: str
    identity: TLSInventoryIdentity
    probe_url: str
    observations: tuple[TLSObservation, ...] = Field(default=(), max_length=128)
    finding_fingerprints: tuple[str, ...] = Field(default=(), max_length=512)
    related_rule_ids: tuple[str, ...] = Field(default=(), max_length=256)
    started_at: datetime | None = None
    ended_at: datetime | None = None
    limitations: tuple[str, ...] = Field(default=(), max_length=128)


class TLSInventoryEntryAnalysis(_StrictModel):
    result: TLSInventoryEntryResult
    findings: tuple[Finding, ...] = Field(default=(), max_length=512)
    issues: tuple[AnalysisIssue, ...] = Field(default=(), max_length=128)
    probe_attempts: tuple[dict[str, Any], ...] = Field(default=(), max_length=32)


def analyze_external_tls_inventory(
    policy: AuditPolicy | str | os.PathLike[str],
    inventory_id: str,
) -> AnalysisResult:
    _ensure_rules_loaded()
    target_id = f"tls-inventory/{inventory_id}"
    loaded_policy, resolved_policy, policy_issues = _load_inventory_policy(
        policy,
        inventory_id,
    )
    if policy_issues:
        return AnalysisResult(
            mode="external",
            target=target_id,
            issues=policy_issues,
        )

    assert loaded_policy is not None
    assert resolved_policy is not None
    inventory = _select_inventory(loaded_policy, inventory_id)
    if inventory is None:
        return AnalysisResult(
            mode="external",
            target=target_id,
            issues=[
                _issue(
                    code="tls_inventory_not_found",
                    message=(
                        f"Audit policy does not define TLS inventory {inventory_id!r}."
                    ),
                    target=target_id,
                )
            ],
        )

    recorder = RuleExecutionRecorder()
    probe_attempts: list[dict[str, Any]] = []
    findings: list[Finding] = []
    issues: list[AnalysisIssue] = []
    entry_analyses: list[TLSInventoryEntryAnalysis] = []

    for entry in inventory.entries:
        analysis = _probe_inventory_entry(
            entry,
            inventory,
            policy=loaded_policy,
            execution_recorder=recorder,
        )
        analysis = _offset_probe_references(analysis, len(probe_attempts))
        entry_analyses.append(analysis)
        probe_attempts.extend(analysis.probe_attempts)
        issues.extend(analysis.issues)
        findings.extend(
            _scoped_inventory_findings(
                inventory=inventory,
                entry=entry,
                findings=analysis.findings,
            )
        )

    observation_complete, missing_evidence = _observation_completeness(
        inventory,
        entry_analyses,
    )
    inventory_metadata = _inventory_metadata(
        inventory=inventory,
        entry_analyses=entry_analyses,
        probe_attempts=probe_attempts,
        observation_complete=observation_complete,
        missing_evidence=missing_evidence,
    )
    control_assessment = _inventory_control_assessment(
        inventory=inventory,
        entry_analyses=entry_analyses,
        findings=findings,
        missing_evidence=missing_evidence,
        observation_complete=observation_complete,
        policy_source=(
            loaded_policy.loaded_provenance.path
            if loaded_policy.loaded_provenance is not None
            else "<in-memory-policy>"
        ),
    )
    result = AnalysisResult(
        mode="external",
        target=target_id,
        findings=findings,
        issues=issues,
        metadata=inventory_metadata,
        control_assessments=[control_assessment],
    )
    result = _attach_entry_fingerprints(result)
    manifest = build_analysis_manifest(
        recorder=recorder,
        policy=resolved_policy,
        mode="external",
        server_type=None,
        registry=registry,
    )
    return attach_audit_context(result, resolved_policy, manifest)


def _load_inventory_policy(
    policy: AuditPolicy | str | os.PathLike[str],
    inventory_id: str,
) -> tuple[AuditPolicy | None, Any | None, list[AnalysisIssue]]:
    target_id = f"tls-inventory/{inventory_id}"
    try:
        loaded_policy = (
            load_audit_policy(Path(policy))
            if isinstance(policy, (str, os.PathLike))
            else policy
        )
    except AuditPolicyLoadError as exc:
        return None, None, [_policy_issue(exc.issue.code, exc.issue.message, target_id)]

    ledger = load_coverage_ledger()
    validation_issues = validate_audit_policy(loaded_policy, ledger, registry)
    if validation_issues:
        return (
            None,
            None,
            [_policy_issue(issue.code, issue.message, target_id, path=issue.path) for issue in validation_issues],
        )

    try:
        resolved = resolve_audit_policy(
            loaded_policy,
            AuditTarget(mode="external", target=target_id),
            ledger,
        )
    except AuditPolicyResolveError as exc:
        return None, None, [_policy_issue(exc.issue.code, exc.issue.message, target_id)]
    return loaded_policy, resolved, []


def _policy_issue(
    code: str,
    message: str,
    target: str,
    *,
    path: str | None = None,
) -> AnalysisIssue:
    location = SourceLocation(mode="external", kind="check", target=target)
    if path is not None:
        location.file_path = path
    return AnalysisIssue(
        code=code,
        level="error",
        message=message,
        location=location,
    )


def _issue(code: str, message: str, target: str) -> AnalysisIssue:
    return AnalysisIssue(
        code=code,
        level="error",
        message=message,
        location=SourceLocation(mode="external", kind="check", target=target),
    )


def _ensure_rules_loaded() -> None:
    registry.ensure_loaded("webconf_audit.external.rules")
    register_external_rule_metas()


def _select_inventory(
    policy: AuditPolicy,
    inventory_id: str,
) -> TLSInventory | None:
    if policy.external is None:
        return None
    for inventory in policy.external.tls_inventories:
        if inventory.inventory_id == inventory_id:
            return inventory
    return None


def _probe_inventory_entry(
    entry: TLSInventoryEntry,
    inventory: TLSInventory,
    *,
    policy: AuditPolicy,
    execution_recorder: RuleExecutionRecorder | None = None,
) -> TLSInventoryEntryAnalysis:
    started_at = _utc_now()
    display_host = entry.http_host or entry.sni_name or entry.connect_host
    probe_target = ProbeTarget(
        scheme="https",
        host=display_host,
        port=entry.connect_port,
        path=entry.path,
    )
    limitations = [_BOUNDED_TLS_LIMITATION]
    tls_info, handshake_error = _observe_tls_inventory_tls_info(entry)
    attempt = ProbeAttempt(
        target=probe_target,
        tcp_open=tls_info is not None,
        tls_info=tls_info,
        error_message=handshake_error,
    )
    if tls_info is not None:
        attempt, chain_error, protocol_error, cipher_error, ocsp_error = _enrich_tls_attempt(
            attempt,
            entry=entry,
            inventory=inventory,
            policy=policy,
        )
        for error in (chain_error, protocol_error, cipher_error, ocsp_error):
            if error is not None:
                limitations.append(error)
    observations = _entry_observations(
        entry=entry,
        inventory=inventory,
        attempt=attempt,
        handshake_error=handshake_error,
    )
    findings = tuple(
        run_external_tls_rules(
            [attempt],
            probe_target.url,
            expected_certificate_names=_expected_certificate_names(entry),
            execution_recorder=execution_recorder,
        )
    )
    ended_at = _utc_now()
    related_rule_ids = tuple(sorted({finding.rule_id for finding in findings}))
    result = TLSInventoryEntryResult(
        inventory_id=inventory.inventory_id,
        entry_id=entry.entry_id,
        identity=TLSInventoryIdentity(
            connect_host=entry.connect_host,
            connect_port=entry.connect_port,
            sni_name=entry.sni_name,
            http_host=entry.http_host,
        ),
        probe_url=probe_target.url,
        observations=observations,
        related_rule_ids=related_rule_ids,
        started_at=started_at,
        ended_at=ended_at,
        limitations=tuple(sorted(set(limitations))),
    )
    return TLSInventoryEntryAnalysis(
        result=result,
        findings=findings,
        probe_attempts=(_attempt_to_metadata(attempt),),
    )


def _observe_tls_inventory_tls_info(
    entry: TLSInventoryEntry,
) -> tuple[TLSInfo | None, str | None]:
    raw_sock: socket.socket | None = None
    tls_conn: _OSSL.Connection | None = None
    ocsp_state = {"seen": False, "response": b""}
    sct_state = {"response": b""}
    try:
        context = _build_observed_tls_context(
            ocsp_state=ocsp_state,
            sct_state=sct_state,
        )
        raw_sock = socket.create_connection(
            (entry.connect_host, entry.connect_port),
            timeout=DEFAULT_PROBE_TIMEOUT_SECONDS,
        )
        raw_sock.settimeout(DEFAULT_PROBE_TIMEOUT_SECONDS)
        tls_conn = _OSSL.Connection(context, raw_sock)
        if entry.sni_name is not None:
            tls_conn.set_tlsext_host_name(entry.sni_name.encode("idna"))
        if hasattr(tls_conn, "request_ocsp"):
            tls_conn.request_ocsp()
        tls_conn.set_connect_state()
        _complete_openssl_handshake(tls_conn)
        return (
            _extract_tls_info_from_openssl(
                tls_conn,
                ocsp_state=ocsp_state,
                sct_state=sct_state,
            ),
            None,
        )
    except (OSError, _OSSL.Error, ssl.SSLError, UnicodeError) as exc:
        return None, str(exc)
    finally:
        if tls_conn is not None:
            try:
                tls_conn.close()
            except Exception:
                pass
        if raw_sock is not None:
            try:
                raw_sock.close()
            except Exception:
                pass


def _enrich_tls_attempt(
    attempt: ProbeAttempt,
    *,
    entry: TLSInventoryEntry,
    inventory: TLSInventory,
    policy: AuditPolicy,
) -> tuple[ProbeAttempt, str | None, str | None, str | None, str | None]:
    tls_info = attempt.tls_info
    assert tls_info is not None
    cafile = _inventory_ca_path(policy, inventory)
    chain_result = verify_certificate_chain(
        entry.connect_host,
        entry.connect_port,
        sni_name=entry.sni_name,
        cafile=cafile,
    )
    protocol_results = probe_tls_versions(
        entry.connect_host,
        entry.connect_port,
        sni_name=entry.sni_name,
    )
    preference_result = probe_server_cipher_preference(
        entry.connect_host,
        entry.connect_port,
        sni_name=entry.sni_name,
    )
    ocsp_result = probe_ocsp_stapling(
        entry.connect_host,
        entry.connect_port,
        sni_name=entry.sni_name,
    )
    depth_result = probe_chain_depth(
        entry.connect_host,
        entry.connect_port,
        sni_name=entry.sni_name,
    )
    enriched = attempt.tls_info.__class__(
        protocol_version=tls_info.protocol_version,
        cert_not_before=tls_info.cert_not_before,
        cert_not_after=tls_info.cert_not_after,
        cert_subject=tls_info.cert_subject,
        cert_issuer=tls_info.cert_issuer,
        cipher_name=tls_info.cipher_name,
        cipher_bits=tls_info.cipher_bits,
        cipher_protocol=tls_info.cipher_protocol,
        cert_san=tls_info.cert_san,
        renegotiation_info_observed=tls_info.renegotiation_info_observed,
        negotiated_compression=tls_info.negotiated_compression,
        negotiated_cipher_is_aead=tls_info.negotiated_cipher_is_aead,
        supported_protocols=supported_protocol_labels(protocol_results),
        cert_chain_complete=chain_result.verified,
        cert_chain_error=chain_result.error_message,
        cert_chain_depth=depth_result.depth,
        embedded_scts=tls_info.embedded_scts,
        stapled_scts=tls_info.stapled_scts,
        chain_certificates=tls_info.chain_certificates,
        chain_signature_algorithms=tls_info.chain_signature_algorithms,
        cert_must_staple=tls_info.cert_must_staple,
        server_cipher_preference=preference_result.server_order,
        cipher_preference_first_cipher=preference_result.first_cipher,
        cipher_preference_reversed_cipher=preference_result.reversed_cipher,
        cipher_preference_error=preference_result.error_message,
        ocsp_stapled=(
            ocsp_result.stapled
            if ocsp_result.stapled is not None
            else tls_info.ocsp_stapled
        ),
        ocsp_stapling_error=ocsp_result.error_message,
    )
    return (
        attempt.__class__(
            target=attempt.target,
            tcp_open=attempt.tcp_open,
            effective_method=attempt.effective_method,
            status_code=attempt.status_code,
            reason_phrase=attempt.reason_phrase,
            server_header=attempt.server_header,
            strict_transport_security_header=attempt.strict_transport_security_header,
            location_header=attempt.location_header,
            content_type_header=attempt.content_type_header,
            x_frame_options_header=attempt.x_frame_options_header,
            x_content_type_options_header=attempt.x_content_type_options_header,
            content_security_policy_header=attempt.content_security_policy_header,
            referrer_policy_header=attempt.referrer_policy_header,
            permissions_policy_header=attempt.permissions_policy_header,
            cache_control_header=attempt.cache_control_header,
            x_dns_prefetch_control_header=attempt.x_dns_prefetch_control_header,
            x_powered_by_header=attempt.x_powered_by_header,
            x_aspnet_version_header=attempt.x_aspnet_version_header,
            x_aspnetmvc_version_header=attempt.x_aspnetmvc_version_header,
            via_header=attempt.via_header,
            etag_header=attempt.etag_header,
            cross_origin_embedder_policy_header=attempt.cross_origin_embedder_policy_header,
            cross_origin_opener_policy_header=attempt.cross_origin_opener_policy_header,
            cross_origin_resource_policy_header=attempt.cross_origin_resource_policy_header,
            access_control_allow_origin_header=attempt.access_control_allow_origin_header,
            access_control_allow_credentials_header=attempt.access_control_allow_credentials_header,
            allow_header=attempt.allow_header,
            set_cookie_headers=attempt.set_cookie_headers,
            body_snippet=attempt.body_snippet,
            html_recon=attempt.html_recon,
            tls_info=enriched,
            options_observation=attempt.options_observation,
            unknown_host_probe=attempt.unknown_host_probe,
            error_message=attempt.error_message,
        ),
        chain_result.error_message,
        _protocol_probe_limitation(protocol_results),
        preference_result.error_message,
        ocsp_result.error_message,
    )


def _protocol_probe_limitation(results: list[Any]) -> str | None:
    if any(result.supported for result in results):
        return None
    errors = sorted(
        {
            result.error_message
            for result in results
            if result.error_message
        }
    )
    if not errors:
        return "TLS protocol support observation did not complete."
    return "TLS protocol support observation did not complete: " + "; ".join(errors)


def _entry_observations(
    *,
    entry: TLSInventoryEntry,
    inventory: TLSInventory,
    attempt: ProbeAttempt,
    handshake_error: str | None,
) -> tuple[TLSObservation, ...]:
    observations: list[TLSObservation] = []
    tls_info = attempt.tls_info
    for requirement in inventory.required_evidence:
        if requirement in entry.not_applicable:
            observations.append(
                TLSObservation(
                    requirement=requirement,
                    state="not-applicable",
                    reason=entry.not_applicable[requirement].reason,
                )
            )
            continue
        if requirement == "handshake":
            observations.append(
                _handshake_observation(
                    tls_info=tls_info,
                    handshake_error=handshake_error,
                )
            )
            continue
        if tls_info is None:
            observations.append(
                TLSObservation(
                    requirement=requirement,
                    state="failed",
                    reason=handshake_error or "TLS handshake did not complete.",
                )
            )
            continue
        if requirement == "certificate_name":
            observations.append(_certificate_name_observation(entry, tls_info))
        elif requirement == "certificate_chain":
            observations.append(_certificate_chain_observation(tls_info))
        elif requirement == "protocol_support":
            observations.append(_protocol_support_observation(tls_info))
        elif requirement == "negotiated_cipher":
            observations.append(_negotiated_cipher_observation(tls_info))
        elif requirement == "ocsp_stapling":
            observations.append(_ocsp_stapling_observation(tls_info))
    return tuple(observations)


def _handshake_observation(
    *,
    tls_info: TLSInfo | None,
    handshake_error: str | None,
) -> TLSObservation:
    if tls_info is None:
        return TLSObservation(
            requirement="handshake",
            state="failed",
            reason=handshake_error or "TLS handshake did not complete.",
        )
    return TLSObservation(
        requirement="handshake",
        state="observed",
        reason="TLS handshake completed.",
        evidence_refs=("probe_attempts[0].tls_info",),
    )


def _certificate_name_observation(
    entry: TLSInventoryEntry,
    tls_info: TLSInfo,
) -> TLSObservation:
    expected_names = _expected_certificate_names(entry)
    if not expected_names:
        return TLSObservation(
            requirement="certificate_name",
            state="not-requested",
            reason="No expected certificate names were declared.",
        )
    if not tls_info.cert_san:
        return TLSObservation(
            requirement="certificate_name",
            state="failed",
            reason="The served certificate did not expose SAN names.",
            evidence_refs=("probe_attempts[0].tls_info.cert_san",),
        )
    if all(
        _hostname_matches_san(name, tls_info.cert_san)
        for name in expected_names
    ):
        return TLSObservation(
            requirement="certificate_name",
            state="observed",
            reason="The served certificate matched every expected name.",
            evidence_refs=("probe_attempts[0].tls_info.cert_san",),
        )
    return TLSObservation(
        requirement="certificate_name",
        state="failed",
        reason="The served certificate did not match every expected name.",
        evidence_refs=("probe_attempts[0].tls_info.cert_san",),
    )


def _certificate_chain_observation(tls_info: TLSInfo) -> TLSObservation:
    if tls_info.cert_chain_complete is True:
        return TLSObservation(
            requirement="certificate_chain",
            state="observed",
            reason="Certificate chain verification completed successfully.",
            evidence_refs=(
                "probe_attempts[0].tls_info.cert_chain_complete",
                "probe_attempts[0].tls_info.cert_chain_depth",
            ),
        )
    if tls_info.cert_chain_complete is False:
        return TLSObservation(
            requirement="certificate_chain",
            state="failed",
            reason=tls_info.cert_chain_error or "Certificate chain verification failed.",
            evidence_refs=("probe_attempts[0].tls_info.cert_chain_complete",),
        )
    return TLSObservation(
        requirement="certificate_chain",
        state="unavailable",
        reason=tls_info.cert_chain_error or "Certificate chain verification did not complete.",
        evidence_refs=("probe_attempts[0].tls_info.cert_chain_complete",),
    )


def _protocol_support_observation(tls_info: TLSInfo) -> TLSObservation:
    if tls_info.supported_protocols:
        return TLSObservation(
            requirement="protocol_support",
            state="observed",
            reason="Bounded TLS protocol support observation completed.",
            evidence_refs=("probe_attempts[0].tls_info.supported_protocols",),
        )
    return TLSObservation(
        requirement="protocol_support",
        state="unavailable",
        reason="Bounded TLS protocol support observation did not complete.",
        evidence_refs=("probe_attempts[0].tls_info.supported_protocols",),
    )


def _negotiated_cipher_observation(tls_info: TLSInfo) -> TLSObservation:
    if tls_info.cipher_name is None:
        return TLSObservation(
            requirement="negotiated_cipher",
            state="unavailable",
            reason="The negotiated cipher could not be observed.",
        )
    if tls_info.server_cipher_preference is None:
        return TLSObservation(
            requirement="negotiated_cipher",
            state="unavailable",
            reason=(
                tls_info.cipher_preference_error
                or "Bounded server cipher preference observation did not complete."
            ),
            evidence_refs=("probe_attempts[0].tls_info.cipher_name",),
        )
    return TLSObservation(
        requirement="negotiated_cipher",
        state="observed",
        reason="Negotiated cipher and bounded cipher preference observation completed.",
        evidence_refs=(
            "probe_attempts[0].tls_info.cipher_name",
            "probe_attempts[0].tls_info.server_cipher_preference",
        ),
    )


def _ocsp_stapling_observation(tls_info: TLSInfo) -> TLSObservation:
    if tls_info.ocsp_stapled is True:
        return TLSObservation(
            requirement="ocsp_stapling",
            state="observed",
            reason="OCSP stapling was observed during TLS handshake.",
            evidence_refs=("probe_attempts[0].tls_info.ocsp_stapled",),
        )
    if tls_info.ocsp_stapled is False:
        return TLSObservation(
            requirement="ocsp_stapling",
            state="failed",
            reason="OCSP stapling was not observed during the bounded TLS probe.",
            evidence_refs=("probe_attempts[0].tls_info.ocsp_stapled",),
        )
    return TLSObservation(
        requirement="ocsp_stapling",
        state="unavailable",
        reason=(
            tls_info.ocsp_stapling_error
            or "OCSP stapling observation did not complete."
        ),
        evidence_refs=("probe_attempts[0].tls_info.ocsp_stapled",),
    )


def _inventory_ca_path(
    policy: AuditPolicy,
    inventory: TLSInventory,
) -> str | None:
    if inventory.trust.mode != "custom" or inventory.trust.ca_path is None:
        return None
    ca_path = Path(inventory.trust.ca_path)
    if ca_path.is_absolute():
        return str(ca_path)
    if policy.loaded_provenance is None:
        return str(ca_path)
    return str(Path(policy.loaded_provenance.path).resolve().parent / ca_path)


def _expected_certificate_names(entry: TLSInventoryEntry) -> tuple[str, ...]:
    if entry.expected_certificate_names:
        return entry.expected_certificate_names
    if entry.sni_name is not None:
        return (entry.sni_name,)
    return ()


def _observation_completeness(
    inventory: TLSInventory,
    entry_analyses: list[TLSInventoryEntryAnalysis],
) -> tuple[bool, list[str]]:
    missing: list[str] = []
    for analysis in entry_analyses:
        for observation in analysis.result.observations:
            if observation.requirement not in inventory.required_evidence:
                continue
            if observation.state not in {"observed", "not-applicable"}:
                missing.append(
                    f"{analysis.result.entry_id}:{observation.requirement}"
                )
    return not missing, sorted(set(missing))


def _inventory_metadata(
    *,
    inventory: TLSInventory,
    entry_analyses: list[TLSInventoryEntryAnalysis],
    probe_attempts: list[dict[str, Any]],
    observation_complete: bool,
    missing_evidence: list[str],
) -> dict[str, Any]:
    return {
        "probe_attempts": probe_attempts,
        "tls_inventory": {
            "inventory_id": inventory.inventory_id,
            "environment": inventory.environment,
            "declared_complete": inventory.declared_complete,
            "completeness_attestation": (
                inventory.completeness_attestation.model_dump(mode="json")
                if inventory.completeness_attestation is not None
                else None
            ),
            "required_evidence": list(inventory.required_evidence),
            "observation_complete": observation_complete,
            "missing_evidence": missing_evidence,
            "entries": [
                analysis.result.model_dump(mode="json")
                for analysis in entry_analyses
            ],
            "limitations": [_BOUNDED_TLS_LIMITATION],
        },
    }


def _inventory_control_assessment(
    *,
    inventory: TLSInventory,
    entry_analyses: list[TLSInventoryEntryAnalysis],
    findings: list[Finding],
    missing_evidence: list[str],
    observation_complete: bool,
    policy_source: str,
) -> PolicyControlAssessment:
    required_finding_failures: list[Finding] = []
    optional_findings: list[Finding] = []
    unmapped_findings: list[Finding] = []
    for finding in findings:
        requirement = _TLS_FINDING_REQUIREMENTS.get(finding.rule_id)
        if requirement is None:
            unmapped_findings.append(finding)
        elif requirement in inventory.required_evidence:
            required_finding_failures.append(finding)
        else:
            optional_findings.append(finding)

    not_applicable = bool(entry_analyses) and all(
        all(
            observation.state == "not-applicable"
            for observation in analysis.result.observations
            if observation.requirement in inventory.required_evidence
        )
        for analysis in entry_analyses
    )
    if required_finding_failures:
        status: Literal["pass", "fail", "not-applicable", "indeterminate"] = "fail"
        summary = (
            "Bounded TLS observation detected failing evidence for required "
            "endpoint/SNI inventory dimensions."
        )
    elif unmapped_findings:
        status = "indeterminate"
        summary = (
            "The TLS inventory is indeterminate because one or more TLS findings "
            "could not be mapped to a declared evidence dimension: "
            + ", ".join(sorted({finding.rule_id for finding in unmapped_findings}))
            + "."
        )
    elif not inventory.declared_complete:
        status = "indeterminate"
        summary = (
            "The TLS inventory is indeterminate because inventory completeness "
            "was not declared."
        )
    elif missing_evidence:
        status = "indeterminate"
        summary = (
            "The TLS inventory is indeterminate because mandatory observations "
            "did not complete: "
            + ", ".join(missing_evidence)
            + "."
        )
    elif not_applicable:
        status = "not-applicable"
        summary = (
            "Every declared TLS inventory entry was marked not applicable for the "
            "required evidence dimensions."
        )
    else:
        status = "pass"
        summary = (
            "Declared endpoint/SNI TLS inventory completed with bounded TLS "
            "observation for every required entry."
        )

    evidence = tuple(
        ControlAssessmentEvidence(
            kind="unsupported",
            status=(
                "observed"
                if all(
                    observation.state in {"observed", "not-applicable"}
                    for observation in analysis.result.observations
                    if observation.requirement in inventory.required_evidence
                )
                else "incomplete"
            ),
            message=(
                f"Entry {analysis.result.entry_id} recorded "
                f"{len(analysis.result.observations)} observation(s)."
            ),
            declared_scope_id=f"tls-inventory:{inventory.inventory_id}:{analysis.result.entry_id}",
            values=tuple(
                f"{observation.requirement}:{observation.state}"
                for observation in analysis.result.observations
            ),
        )
        for analysis in entry_analyses
    )
    evidence_refs = sorted(
        {
            reference
            for analysis in entry_analyses
            for observation in analysis.result.observations
            for reference in observation.evidence_refs
        }
    )
    limitations = sorted(
        {
            limitation
            for analysis in entry_analyses
            for limitation in analysis.result.limitations
        }
    )
    limitations = sorted(
        {
            *limitations,
            *(
                "Optional TLS evidence produced a finding for "
                f"{finding.rule_id}, so the result remains bounded to the "
                "declared required_evidence dimensions."
                for finding in optional_findings
            ),
            *(
                "TLS finding "
                f"{finding.rule_id} could not be mapped to a declared "
                "required_evidence dimension."
                for finding in unmapped_findings
            ),
        }
    )
    return PolicyControlAssessment(
        control_id=_TLS_INVENTORY_CONTROL_ID,
        title="Declared endpoint/SNI TLS inventory",
        status=status,
        scope=ControlAssessmentScope(
            server_scope_id=inventory.inventory_id,
            route_scope_id=inventory.inventory_id,
            route_selector=f"tls-inventory/{inventory.inventory_id}",
        ),
        summary=summary,
        evidence=evidence,
        related_rule_ids=tuple(sorted({finding.rule_id for finding in findings})),
        policy_source=policy_source,
        metadata={
            "inventory_id": inventory.inventory_id,
            "inventory_complete": inventory.declared_complete,
            "observations_complete": observation_complete,
            "required_evidence": list(inventory.required_evidence),
            "evidence_references": evidence_refs,
            "missing_evidence": missing_evidence,
            "limitations": limitations,
        },
    )


def _scoped_inventory_findings(
    *,
    inventory: TLSInventory,
    entry: TLSInventoryEntry,
    findings: tuple[Finding, ...],
) -> list[Finding]:
    scoped: list[Finding] = []
    scope_id = f"tls-inventory:{inventory.inventory_id}:{entry.entry_id}"
    identity = {
        "connect_host": entry.connect_host,
        "connect_port": entry.connect_port,
        "sni_name": entry.sni_name,
        "http_host": entry.http_host,
    }
    for finding in findings:
        metadata = dict(finding.metadata)
        metadata["scope_id"] = scope_id
        metadata["tls_inventory_identity"] = identity
        scoped.append(finding.model_copy(update={"metadata": metadata}))
    return scoped


def _attach_entry_fingerprints(result: AnalysisResult) -> AnalysisResult:
    updated = result.model_copy(deep=True)
    inventory = updated.metadata.get("tls_inventory")
    if not isinstance(inventory, dict):
        return updated
    entries = inventory.get("entries")
    if not isinstance(entries, list):
        return updated
    scoped_findings: dict[str, list[str]] = {}
    for finding in updated.findings:
        scope_id = finding.metadata.get("scope_id")
        if not isinstance(scope_id, str):
            continue
        scoped_findings.setdefault(scope_id, []).append(
            finding_fingerprint(updated, finding)
        )
    inventory_id = inventory.get("inventory_id")
    if not isinstance(inventory_id, str):
        return updated
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        entry_id = entry.get("entry_id")
        if not isinstance(entry_id, str):
            continue
        scope_id = f"tls-inventory:{inventory_id}:{entry_id}"
        entry["finding_fingerprints"] = sorted(scoped_findings.get(scope_id, ()))
    return updated


def _offset_probe_references(
    analysis: TLSInventoryEntryAnalysis,
    offset: int,
) -> TLSInventoryEntryAnalysis:
    if offset == 0:
        return analysis
    observations = tuple(
        observation.model_copy(
            update={
                "evidence_refs": tuple(
                    _shift_probe_reference(reference, offset)
                    for reference in observation.evidence_refs
                )
            }
        )
        for observation in analysis.result.observations
    )
    return analysis.model_copy(
        update={
            "result": analysis.result.model_copy(
                update={"observations": observations}
            )
        }
    )


def _shift_probe_reference(reference: str, offset: int) -> str:
    prefix = "probe_attempts["
    if not reference.startswith(prefix):
        return reference
    suffix = reference[len(prefix):]
    if "]" not in suffix:
        return reference
    index_text, rest = suffix.split("]", 1)
    if not index_text.isdigit():
        return reference
    return f"probe_attempts[{int(index_text) + offset}]{rest}"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


__all__ = [
    "TLSInventoryEntryAnalysis",
    "TLSInventoryEntryResult",
    "TLSObservation",
    "TLSObservationState",
    "analyze_external_tls_inventory",
]
