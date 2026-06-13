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
    monkeypatch.setattr(runner_module, "collect_disclosure_findings", lambda *_args, **_kwargs: [])
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
            selected_rule_ids=tuple(
                meta.rule_id for meta in runner_module._EXTERNAL_RULE_METAS
            ),
        ),
        recorder.events(),
    )

    assert "external.nginx.default_welcome_page" in manifest.completed_rule_ids
    skipped = {entry.rule_id: entry.reason for entry in manifest.skipped_rules}
    assert skipped["external.apache.default_welcome_page"] == "server-incompatible"
    assert "external.certificate_expired" in manifest.completed_rule_ids
