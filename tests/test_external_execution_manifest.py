from __future__ import annotations

from webconf_audit.external.recon import ProbeAttempt, ProbeTarget, ServerIdentification


def _attempt() -> ProbeAttempt:
    return ProbeAttempt(
        target=ProbeTarget(scheme="https", host="example.test", port=443, path="/"),
        tcp_open=True,
        status_code=200,
    )


def test_external_runner_records_per_rule_completion_and_server_skips(
    monkeypatch,
) -> None:
    from webconf_audit.execution_manifest import (
        RuleExecutionRecorder,
        RuleSelection,
        build_rule_execution_manifest,
    )
    from webconf_audit.external.rules import _runner as runner_module

    monkeypatch.setattr(runner_module, "collect_https_findings", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(runner_module, "collect_header_findings", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(runner_module, "find_nginx_redirect_target_unexpected", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(runner_module, "find_nginx_default_index_page_body", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        runner_module,
        "find_iis_server_header_removal_not_applied",
        lambda *_args, **_kwargs: [],
    )
    monkeypatch.setattr(runner_module, "collect_cors_findings", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(runner_module, "collect_method_findings", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(runner_module, "collect_cookie_findings", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(runner_module, "collect_tls_findings", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(runner_module, "find_unknown_host_runtime_response", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        runner_module,
        "collect_sensitive_path_findings",
        lambda *_args, **_kwargs: [],
    )
    monkeypatch.setattr(
        runner_module,
        "collect_conditional_findings",
        lambda *_args, **_kwargs: [],
    )

    recorder = RuleExecutionRecorder()
    runner_module.run_external_rules(
        [_attempt()],
        "https://example.test",
        sensitive_path_probes=[],
        server_identification=ServerIdentification(
            server_type="nginx",
            confidence="high",
            evidence=(),
        ),
        execution_recorder=recorder,
    )

    manifest = build_rule_execution_manifest(
        RuleSelection(
            registry_revision="registry:test",
            selected_rule_ids=recorder.selected_rule_ids(),
        ),
        recorder.events(),
    )

    assert "external.nginx.default_welcome_page" in manifest.completed_rule_ids
    skipped = {entry.rule_id: entry.reason for entry in manifest.skipped_rules}
    assert skipped["external.apache.default_welcome_page"] == "server-incompatible"
    assert "external.certificate_expired" in manifest.completed_rule_ids


def test_external_runner_omits_runtime_only_rules_missing_from_registry(
    monkeypatch,
) -> None:
    from webconf_audit.execution_manifest import RuleExecutionRecorder
    from webconf_audit.external.rules import _runner as runner_module

    monkeypatch.setattr(runner_module, "collect_https_findings", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(runner_module, "collect_header_findings", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(runner_module, "find_nginx_redirect_target_unexpected", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(runner_module, "find_nginx_default_index_page_body", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        runner_module,
        "find_iis_server_header_removal_not_applied",
        lambda *_args, **_kwargs: [],
    )
    monkeypatch.setattr(runner_module, "collect_cors_findings", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(runner_module, "collect_method_findings", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(runner_module, "collect_cookie_findings", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(runner_module, "collect_tls_findings", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(runner_module, "find_unknown_host_runtime_response", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        runner_module,
        "collect_sensitive_path_findings",
        lambda *_args, **_kwargs: [],
    )
    monkeypatch.setattr(
        runner_module,
        "collect_conditional_findings",
        lambda *_args, **_kwargs: [],
    )
    original_get_meta = runner_module.registry.get_meta

    def _get_meta(rule_id: str):
        if rule_id in {
            "external.nginx.redirect_target_unexpected",
            "external.nginx.default_index_page_body",
            "external.iis.server_header_removal_not_applied",
            "external.unknown_host_runtime_response",
        }:
            return None
        return original_get_meta(rule_id)

    monkeypatch.setattr(runner_module.registry, "get_meta", _get_meta)

    recorder = RuleExecutionRecorder()
    runner_module.run_external_rules(
        [_attempt()],
        "https://example.test",
        sensitive_path_probes=[],
        server_identification=ServerIdentification(
            server_type="nginx",
            confidence="high",
            evidence=(),
        ),
        execution_recorder=recorder,
        record_runtime_only_rules=True,
    )

    selected = set(recorder.selected_rule_ids())
    assert "external.https_not_available" in selected
    assert "external.nginx.redirect_target_unexpected" not in selected
    assert "external.nginx.default_index_page_body" not in selected
    assert "external.iis.server_header_removal_not_applied" not in selected
    assert "external.unknown_host_runtime_response" not in selected


def test_external_runner_marks_unavailable_groups_as_input_unavailable() -> None:
    from webconf_audit.execution_manifest import (
        RuleExecutionRecorder,
        RuleSelection,
        build_rule_execution_manifest,
    )
    from webconf_audit.external.rules import _runner as runner_module

    recorder = RuleExecutionRecorder()
    runner_module.run_external_rules(
        [
            ProbeAttempt(
                target=ProbeTarget(scheme="https", host="example.test", port=443, path="/"),
                tcp_open=False,
                error_message="TCP connection failed or timed out.",
            )
        ],
        "https://example.test",
        sensitive_path_probes=[],
        server_identification=None,
        execution_recorder=recorder,
    )

    manifest = build_rule_execution_manifest(
        RuleSelection(
            registry_revision="registry:test",
            selected_rule_ids=recorder.selected_rule_ids(),
        ),
        recorder.events(),
    )

    skipped = {entry.rule_id: entry.reason for entry in manifest.skipped_rules}
    assert skipped["external.https_not_available"] == "input-unavailable"
    assert skipped["external.x_frame_options_missing"] == "input-unavailable"
    assert skipped["external.cookie_missing_httponly"] == "input-unavailable"
    assert skipped["external.certificate_expired"] == "input-unavailable"
    assert skipped["external.nginx.default_welcome_page"] == "input-unavailable"
