from __future__ import annotations

from pathlib import Path

from webconf_audit.local.lighttpd import analyze_lighttpd_config
from webconf_audit.models import AnalysisResult


_FIXTURE_ROOT = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "webserver-configs"
    / "lighttpd"
    / "edge-cases"
)
_HEADER_NOISE_RULE_IDS = frozenset(
    {
        "lighttpd.missing_content_security_policy",
        "lighttpd.missing_permissions_policy",
        "lighttpd.missing_referrer_policy",
        "lighttpd.missing_strict_transport_security",
        "lighttpd.missing_x_content_type_options",
        "lighttpd.missing_x_frame_options",
        "universal.missing_content_security_policy",
        "universal.missing_referrer_policy",
        "universal.missing_x_content_type_options",
        "universal.missing_x_frame_options",
    }
)
_PATH_NOISE_RULE_IDS = frozenset(
    {
        "lighttpd.backup_temp_files_access_not_denied",
        "lighttpd.config_data_files_access_not_denied",
        "lighttpd.generated_artifacts_access_not_denied",
        "lighttpd.url_access_deny_missing",
        "lighttpd.vcs_metadata_access_not_denied",
    }
)
_LOGGING_AND_LIMIT_RULE_IDS = frozenset(
    {
        "lighttpd.access_log_missing",
        "lighttpd.error_log_missing",
        "lighttpd.max_connections_missing",
        "lighttpd.max_request_size_missing",
        "lighttpd.max_request_size_too_large",
    }
)


def _fixture_path(name: str) -> Path:
    return _FIXTURE_ROOT / name


def _analyze_fixture(name: str, *, host: str | None = None) -> AnalysisResult:
    return analyze_lighttpd_config(str(_fixture_path(name)), host=host)


def _rule_ids(result: AnalysisResult) -> set[str]:
    return {finding.rule_id for finding in result.findings}


def test_redirect_only_socket_80_fixture_stays_free_of_header_path_and_logging_noise() -> None:
    result = _analyze_fixture("redirect-only-socket-80.conf")
    rule_ids = _rule_ids(result)

    assert result.issues == []
    assert _HEADER_NOISE_RULE_IDS.isdisjoint(rule_ids)
    assert _PATH_NOISE_RULE_IDS.isdisjoint(rule_ids)
    assert _LOGGING_AND_LIMIT_RULE_IDS.isdisjoint(rule_ids)
    assert "lighttpd.missing_http_method_restrictions" in rule_ids


def test_host_conditional_url_redirect_fixture_stays_host_precise() -> None:
    default_result = _analyze_fixture("host-conditional-url-redirect.conf")
    redirected_host = _analyze_fixture(
        "host-conditional-url-redirect.conf",
        host="example.com",
    )
    legacy_host = _analyze_fixture(
        "host-conditional-url-redirect.conf",
        host="legacy.example.com",
    )
    other_host = _analyze_fixture(
        "host-conditional-url-redirect.conf",
        host="other.example.com",
    )

    assert all(
        result.issues == []
        for result in (default_result, redirected_host, legacy_host, other_host)
    )
    assert "lighttpd.missing_http_to_https_redirect" not in _rule_ids(default_result)
    assert "lighttpd.missing_http_to_https_redirect" not in _rule_ids(redirected_host)
    assert "lighttpd.missing_http_to_https_redirect" in _rule_ids(legacy_host)
    assert "lighttpd.missing_http_to_https_redirect" not in _rule_ids(other_host)
    assert _HEADER_NOISE_RULE_IDS.isdisjoint(_rule_ids(redirected_host))
    assert _PATH_NOISE_RULE_IDS.isdisjoint(_rule_ids(redirected_host))


def test_inheritance_request_context_fixture_respects_host_specific_header_overrides() -> None:
    default_result = _analyze_fixture("inheritance-request-context.conf")
    secure_host = _analyze_fixture(
        "inheritance-request-context.conf",
        host="secure.example.com",
    )
    audit_host = _analyze_fixture(
        "inheritance-request-context.conf",
        host="audit.example.com",
    )
    other_host = _analyze_fixture(
        "inheritance-request-context.conf",
        host="other.example.com",
    )

    assert all(
        result.issues == []
        for result in (default_result, secure_host, audit_host, other_host)
    )
    assert "lighttpd.missing_strict_transport_security" in _rule_ids(default_result)
    assert "lighttpd.missing_strict_transport_security" not in _rule_ids(secure_host)
    assert "lighttpd.missing_strict_transport_security" in _rule_ids(other_host)
    assert {
        "lighttpd.access_log_missing",
        "lighttpd.error_log_missing",
        "lighttpd.missing_x_content_type_options",
    }.isdisjoint(_rule_ids(secure_host))
    assert {
        "lighttpd.access_log_missing",
        "lighttpd.error_log_missing",
    }.isdisjoint(_rule_ids(audit_host))
