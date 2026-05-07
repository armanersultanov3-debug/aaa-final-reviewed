from __future__ import annotations

from typing import TYPE_CHECKING

from webconf_audit.external.safe_probe_catalog import SAFE_PATH_RULE_METAS
from webconf_audit.external.rules._conditional import collect_conditional_findings
from webconf_audit.external.rules._cookies import collect_cookie_findings
from webconf_audit.external.rules._cors import collect_cors_findings
from webconf_audit.external.rules._disclosure import collect_disclosure_findings
from webconf_audit.external.rules._headers import collect_header_findings
from webconf_audit.external.rules._https import collect_https_findings
from webconf_audit.external.rules._methods import collect_method_findings
from webconf_audit.external.rules._sensitive_paths import collect_sensitive_path_findings
from webconf_audit.external.rules._tls import collect_tls_findings
from webconf_audit.models import Finding
from webconf_audit.rule_registry import RuleMeta, RuleRegistry, registry
from webconf_audit.standards import asvs_5, cwe, owasp_top10_2021

if TYPE_CHECKING:
    from webconf_audit.external.recon import (
        ProbeAttempt,
        SensitivePathProbe,
        ServerIdentification,
    )

# ---------------------------------------------------------------------------
# Metadata-only registration for list-rules / introspection.
# External rules are monolithic (private _find_* + public collect_*),
# not modular @rule-decorated files.
# ---------------------------------------------------------------------------

_EXTERNAL_RULE_METAS = [
    # -- _conditional.py (server-specific, conditional) --
    RuleMeta(rule_id="external.nginx.version_disclosed_in_server_header", title="Nginx version disclosed in Server header", severity="low", description="Nginx version disclosed in Server header", recommendation="Suppress version details in the Server header.", category="external", input_kind="probe", condition="nginx", order=600),
    RuleMeta(rule_id="external.nginx.default_welcome_page", title="Default nginx welcome page exposed", severity="medium", description="Default nginx welcome page exposed", recommendation="Replace or remove the default welcome page.", category="external", input_kind="probe", condition="nginx", order=601),
    RuleMeta(rule_id="external.apache.version_disclosed_in_server_header", title="Apache version disclosed in Server header", severity="low", description="Apache version disclosed in Server header", recommendation="Set ServerTokens Prod.", category="external", input_kind="probe", condition="apache", order=602),
    RuleMeta(rule_id="external.apache.mod_status_public", title="Apache mod_status exposed publicly", severity="medium", description="Apache mod_status exposed publicly", recommendation="Restrict mod_status access.", category="external", input_kind="probe", condition="apache", order=603),
    RuleMeta(rule_id="external.apache.etag_inode_disclosure", title="Apache ETag reveals inode metadata", severity="low", description="Apache ETag reveals inode metadata", recommendation="Configure FileETag to exclude inode.", category="external", input_kind="probe", condition="apache", order=604),
    RuleMeta(rule_id="external.apache.default_welcome_page", title="Default Apache welcome page exposed", severity="medium", description="Default Apache welcome page exposed", recommendation="Replace or remove the default Apache welcome page.", category="external", input_kind="probe", condition="apache", order=605),
    RuleMeta(rule_id="external.iis.aspnet_version_header_present", title="IIS X-AspNet-Version header present", severity="low", description="IIS X-AspNet-Version header present", recommendation="Remove X-AspNet-Version header.", category="external", input_kind="probe", condition="iis", order=606),
    RuleMeta(rule_id="external.iis.detailed_error_page", title="Detailed IIS error page exposed", severity="medium", description="Detailed IIS error page exposed", recommendation="Configure custom error pages.", category="external", input_kind="probe", condition="iis", order=607),
    RuleMeta(rule_id="external.iis.default_welcome_page", title="Default IIS welcome page exposed", severity="medium", description="Default IIS welcome page exposed", recommendation="Replace or remove the default IIS welcome page.", category="external", input_kind="probe", condition="iis", order=608),
    RuleMeta(rule_id="external.lighttpd.version_in_server_header", title="lighttpd version disclosed in Server header", severity="low", description="lighttpd version disclosed in Server header", recommendation="Set server.tag to blank.", category="external", input_kind="probe", condition="lighttpd", order=609),
    RuleMeta(rule_id="external.lighttpd.mod_status_public", title="lighttpd mod_status exposed publicly", severity="medium", description="lighttpd mod_status exposed publicly", recommendation="Restrict mod_status access.", category="external", input_kind="probe", condition="lighttpd", order=610),
    RuleMeta(rule_id="external.lighttpd.default_welcome_page", title="Default lighttpd welcome page exposed", severity="medium", description="Default lighttpd welcome page exposed", recommendation="Replace or remove the default lighttpd welcome page.", category="external", input_kind="probe", condition="lighttpd", order=611),
    # -- _cookies.py --
    RuleMeta(rule_id="external.cookie_missing_secure_on_https", title="Session cookie missing Secure flag", severity="low", description="Session cookie missing Secure flag on HTTPS.", recommendation="Add the Secure flag to cookies.", category="external", input_kind="probe", order=612),
    RuleMeta(rule_id="external.cookie_missing_httponly", title="Session cookie missing HttpOnly flag", severity="low", description="Session cookie missing HttpOnly flag.", recommendation="Add the HttpOnly flag to cookies.", category="external", input_kind="probe", order=613),
    RuleMeta(rule_id="external.cookie_missing_samesite", title="Session cookie missing SameSite attribute", severity="low", description="Session cookie missing SameSite attribute.", recommendation="Add the SameSite attribute to cookies.", category="external", input_kind="probe", order=614),
    RuleMeta(rule_id="external.cookie_samesite_none_without_secure", title="SameSite=None cookie missing Secure flag", severity="low", description="Session cookie with SameSite=None missing Secure flag.", recommendation="Add the Secure flag when using SameSite=None.", category="external", input_kind="probe", order=615),
    # -- _cors.py --
    RuleMeta(rule_id="external.cors_wildcard_origin", title="CORS allows any origin", severity="low", description="CORS allows any origin.", recommendation="Restrict Access-Control-Allow-Origin.", category="external", input_kind="probe", order=620),
    RuleMeta(rule_id="external.cors_wildcard_with_credentials", title="CORS wildcard origin with credentials", severity="medium", description="CORS wildcard origin with credentials.", recommendation="Do not combine wildcard origin with credentials.", category="external", input_kind="probe", order=621),
    # -- _disclosure.py --
    RuleMeta(rule_id="external.server_version_disclosed", title="Server version disclosed", severity="low", description="Server version disclosed in response headers.", recommendation="Suppress version information.", category="external", input_kind="probe", order=630),
    RuleMeta(rule_id="external.x_powered_by_header_present", title="X-Powered-By header present", severity="low", description="X-Powered-By header present.", recommendation="Remove the X-Powered-By header.", category="external", input_kind="probe", order=631),
    RuleMeta(rule_id="external.x_aspnet_version_header_present", title="X-AspNet-Version header present", severity="low", description="X-AspNet-Version header present.", recommendation="Remove the X-AspNet-Version header.", category="external", input_kind="probe", order=632),
    # -- _headers.py --
    RuleMeta(rule_id="external.x_frame_options_missing", title="X-Frame-Options header missing", severity="low", description="X-Frame-Options header missing.", recommendation="Add X-Frame-Options header.", category="external", input_kind="probe", order=640),
    RuleMeta(rule_id="external.x_frame_options_invalid", title="X-Frame-Options header value invalid", severity="low", description="X-Frame-Options header value invalid.", recommendation="Use DENY or SAMEORIGIN.", category="external", input_kind="probe", order=641),
    RuleMeta(rule_id="external.x_content_type_options_missing", title="X-Content-Type-Options header missing", severity="low", description="X-Content-Type-Options header missing.", recommendation="Add X-Content-Type-Options: nosniff.", category="external", input_kind="probe", order=642),
    RuleMeta(rule_id="external.x_content_type_options_invalid", title="X-Content-Type-Options header value invalid", severity="low", description="X-Content-Type-Options header value invalid.", recommendation="Use nosniff.", category="external", input_kind="probe", order=643),
    RuleMeta(rule_id="external.content_security_policy_missing", title="Content-Security-Policy header missing", severity="medium", description="Content-Security-Policy header missing.", recommendation="Add a Content-Security-Policy header.", category="external", input_kind="probe", order=644),
    RuleMeta(rule_id="external.content_security_policy_unsafe_inline", title="CSP allows unsafe-inline", severity="medium", description="Content-Security-Policy allows unsafe-inline.", recommendation="Remove unsafe-inline from CSP.", category="external", input_kind="probe", order=645),
    RuleMeta(rule_id="external.content_security_policy_unsafe_eval", title="CSP allows unsafe-eval", severity="medium", description="Content-Security-Policy allows unsafe-eval.", recommendation="Remove unsafe-eval from CSP.", category="external", input_kind="probe", order=646),
    RuleMeta(rule_id="external.content_security_policy_missing_frame_ancestors", title="CSP missing frame-ancestors", severity="low", description="Content-Security-Policy missing frame-ancestors directive.", recommendation="Add frame-ancestors to CSP.", category="external", input_kind="probe", standards=(cwe(1021), owasp_top10_2021("A05:2021"), asvs_5("3.4.6")), order=647),
    RuleMeta(rule_id="external.content_security_policy_object_src_not_none", title="CSP object-src is not restricted", severity="low", description="Content-Security-Policy does not effectively restrict object-src to 'none'.", recommendation="Set object-src 'none' or rely on default-src 'none'.", category="external", input_kind="probe", standards=(cwe(693), owasp_top10_2021("A05:2021"), asvs_5("3.4.3", coverage="partial", note="CSP object-src minimum policy quality.")), order=648),
    RuleMeta(rule_id="external.content_security_policy_base_uri_not_restricted", title="CSP base-uri is not restricted", severity="low", description="Content-Security-Policy does not restrict base-uri to 'none' or 'self'.", recommendation="Set base-uri 'none' or base-uri 'self'.", category="external", input_kind="probe", standards=(cwe(693), owasp_top10_2021("A05:2021"), asvs_5("3.4.3", coverage="partial", note="CSP base-uri minimum policy quality.")), order=649),
    RuleMeta(rule_id="external.content_security_policy_missing_reporting_endpoint", title="CSP missing reporting endpoint", severity="low", description="Content-Security-Policy does not include report-uri or report-to.", recommendation="Add report-to or report-uri to CSP.", category="external", input_kind="probe", standards=(cwe(693), owasp_top10_2021("A05:2021"), asvs_5("3.4.7", coverage="partial", note="CSP reporting endpoint configured.")), order=650),
    RuleMeta(rule_id="external.referrer_policy_missing", title="Referrer-Policy header missing", severity="info", description="Referrer-Policy header missing.", recommendation="Add a Referrer-Policy header.", category="external", input_kind="probe", order=651),
    RuleMeta(rule_id="external.referrer_policy_unsafe", title="Unsafe Referrer-Policy value", severity="low", description="Unsafe Referrer-Policy value.", recommendation="Use a restrictive Referrer-Policy.", category="external", input_kind="probe", order=652),
    RuleMeta(rule_id="external.permissions_policy_missing", title="Permissions-Policy header missing", severity="info", description="Permissions-Policy header missing.", recommendation="Add a Permissions-Policy header.", category="external", input_kind="probe", order=653),
    RuleMeta(rule_id="external.coep_missing", title="Cross-Origin-Embedder-Policy header missing", severity="info", description="Cross-Origin-Embedder-Policy header missing.", recommendation="Add a COEP header.", category="external", input_kind="probe", order=654),
    RuleMeta(rule_id="external.coop_missing", title="Cross-Origin-Opener-Policy header missing", severity="info", description="Cross-Origin-Opener-Policy header missing.", recommendation="Add a COOP header.", category="external", input_kind="probe", order=655),
    RuleMeta(rule_id="external.corp_missing", title="Cross-Origin-Resource-Policy header missing", severity="info", description="Cross-Origin-Resource-Policy header missing.", recommendation="Add a CORP header.", category="external", input_kind="probe", order=656),
    # -- _https.py --
    RuleMeta(rule_id="external.https_not_available", title="HTTPS not available", severity="medium", description="HTTPS not available.", recommendation="Enable HTTPS.", category="external", input_kind="probe", order=660),
    RuleMeta(rule_id="external.http_not_redirected_to_https", title="HTTP not redirected to HTTPS", severity="low", description="HTTP not redirected to HTTPS.", recommendation="Redirect HTTP to HTTPS.", category="external", input_kind="probe", order=661),
    RuleMeta(rule_id="external.hsts_header_missing", title="HSTS header missing", severity="low", description="HSTS header missing.", recommendation="Add Strict-Transport-Security header.", category="external", input_kind="probe", order=662),
    RuleMeta(rule_id="external.hsts_header_invalid", title="HSTS header value invalid", severity="medium", description="HSTS header value invalid.", recommendation="Fix the HSTS header value.", category="external", input_kind="probe", order=663),
    RuleMeta(rule_id="external.hsts_max_age_too_short", title="HSTS max-age too short", severity="low", description="HSTS max-age too short.", recommendation="Increase HSTS max-age.", category="external", input_kind="probe", order=664),
    RuleMeta(rule_id="external.hsts_missing_include_subdomains", title="HSTS missing includeSubDomains", severity="info", description="HSTS missing includeSubDomains.", recommendation="Add includeSubDomains to HSTS.", category="external", input_kind="probe", order=665),
    RuleMeta(rule_id="external.http_redirect_not_permanent", title="HTTP-to-HTTPS redirect is not permanent", severity="info", description="HTTP-to-HTTPS redirect is not permanent.", recommendation="Use a 301 redirect.", category="external", input_kind="probe", order=666),
    # -- _methods.py --
    RuleMeta(rule_id="external.trace_method_allowed", title="TRACE method allowed", severity="low", description="TRACE method allowed.", recommendation="Disable TRACE method.", category="external", input_kind="probe", order=670),
    RuleMeta(rule_id="external.allow_header_dangerous_methods", title="Dangerous HTTP methods in Allow header", severity="medium", description="Dangerous HTTP methods in Allow header.", recommendation="Remove dangerous methods.", category="external", input_kind="probe", order=671),
    RuleMeta(rule_id="external.options_method_exposed", title="OPTIONS method exposes allowed methods", severity="info", description="OPTIONS method exposes allowed methods.", recommendation="Restrict OPTIONS responses.", category="external", input_kind="probe", order=672),
    RuleMeta(rule_id="external.dangerous_http_methods_enabled", title="Dangerous HTTP methods enabled", severity="medium", description="Dangerous HTTP methods enabled.", recommendation="Disable dangerous methods.", category="external", input_kind="probe", order=673),
    RuleMeta(rule_id="external.trace_method_exposed_via_options", title="TRACE method exposed via OPTIONS", severity="low", description="TRACE method exposed via OPTIONS.", recommendation="Disable TRACE method.", category="external", input_kind="probe", order=674),
    RuleMeta(rule_id="external.webdav_methods_exposed", title="WebDAV methods exposed", severity="medium", description="WebDAV methods exposed.", recommendation="Disable WebDAV unless required.", category="external", input_kind="probe", order=675),
    # -- _sensitive_paths.py / safe_probe_catalog.py --
    *SAFE_PATH_RULE_METAS,
    # -- _tls.py --
    RuleMeta(rule_id="external.certificate_expired", title="TLS certificate expired", severity="high", description="TLS certificate expired.", recommendation="Renew the certificate.", category="external", input_kind="probe", order=700),
    RuleMeta(rule_id="external.certificate_expires_soon", title="TLS certificate expires soon", severity="medium", description="TLS certificate expires soon.", recommendation="Renew the certificate.", category="external", input_kind="probe", order=701),
    RuleMeta(rule_id="external.tls_certificate_self_signed", title="TLS certificate appears self-signed", severity="medium", description="TLS certificate appears self-signed.", recommendation="Use a CA-issued certificate.", category="external", input_kind="probe", order=702),
    RuleMeta(rule_id="external.tls_1_0_supported", title="TLS 1.0 supported", severity="high", description="TLS 1.0 supported.", recommendation="Disable TLS 1.0.", category="external", input_kind="probe", order=703),
    RuleMeta(rule_id="external.tls_1_1_supported", title="TLS 1.1 supported", severity="medium", description="TLS 1.1 supported.", recommendation="Disable TLS 1.1.", category="external", input_kind="probe", order=704),
    RuleMeta(rule_id="external.tls_1_3_not_supported", title="TLS 1.3 not supported", severity="low", description="TLS 1.3 not supported.", recommendation="Enable TLS 1.3.", category="external", input_kind="probe", order=705),
    RuleMeta(rule_id="external.weak_cipher_suite", title="Weak TLS cipher suite negotiated", severity="high", description="Weak TLS cipher suite negotiated.", recommendation="Remove weak cipher suites.", category="external", input_kind="probe", order=706),
    RuleMeta(rule_id="external.tls_forward_secrecy_not_observed", title="TLS forward secrecy not observed", severity="medium", description="TLS forward secrecy not observed.", recommendation="Prefer TLS 1.3 or ECDHE/DHE TLS 1.2 cipher suites.", category="external", input_kind="probe", order=707),
    RuleMeta(rule_id="external.tls_server_cipher_preference_not_observed", title="TLS server cipher preference not observed", severity="low", description="TLS server cipher preference not observed.", recommendation="Prefer server cipher order for TLS 1.2.", category="external", input_kind="probe", order=708),
    RuleMeta(rule_id="external.ocsp_stapling_not_observed", title="OCSP stapling not observed", severity="low", description="OCSP stapling not observed.", recommendation="Enable OCSP stapling where supported.", category="external", input_kind="probe", order=709),
    RuleMeta(rule_id="external.cert_chain_incomplete", title="Certificate chain verification failed", severity="medium", description="Certificate chain verification failed.", recommendation="Fix the certificate chain.", category="external", input_kind="probe", order=710),
    RuleMeta(rule_id="external.cert_chain_length_unusual", title="Unusual certificate chain length", severity="low", description="Unusual certificate chain length.", recommendation="Review the certificate chain.", category="external", input_kind="probe", order=711),
    RuleMeta(rule_id="external.cert_san_mismatch", title="Certificate SAN does not match hostname", severity="medium", description="Certificate SAN does not match target hostname.", recommendation="Issue a certificate with correct SAN.", category="external", input_kind="probe", order=712),
]

def register_external_rule_metas(target_registry: RuleRegistry | None = None) -> None:
    """Register metadata-only external rules into the target registry."""
    active_registry = target_registry or registry
    seen_rule_ids: set[str] = set()
    for meta in _EXTERNAL_RULE_METAS:
        if meta.rule_id in seen_rule_ids:
            raise ValueError(
                f"Duplicate external rule_id in _EXTERNAL_RULE_METAS: {meta.rule_id!r}"
            )
        seen_rule_ids.add(meta.rule_id)
        if active_registry.get_meta(meta.rule_id) is None:
            active_registry.register_meta(meta)


register_external_rule_metas()


def run_external_rules(
    probe_attempts: list["ProbeAttempt"],
    target: str,
    sensitive_path_probes: list["SensitivePathProbe"] | None = None,
    server_identification: "ServerIdentification | None" = None,
) -> list[Finding]:
    path_probes = sensitive_path_probes or []
    findings: list[Finding] = []
    findings.extend(collect_https_findings(probe_attempts, target))
    findings.extend(collect_header_findings(probe_attempts))
    findings.extend(
        collect_disclosure_findings(
            probe_attempts,
            server_identification=server_identification,
        )
    )
    findings.extend(collect_cors_findings(probe_attempts))
    findings.extend(collect_method_findings(probe_attempts))
    findings.extend(collect_cookie_findings(probe_attempts))
    findings.extend(collect_tls_findings(probe_attempts, target))
    findings.extend(
        collect_sensitive_path_findings(
            path_probes,
            server_identification=server_identification,
        )
    )
    findings.extend(
        collect_conditional_findings(
            probe_attempts,
            path_probes,
            server_identification=server_identification,
        )
    )
    return findings


__all__ = ["register_external_rule_metas", "run_external_rules"]
