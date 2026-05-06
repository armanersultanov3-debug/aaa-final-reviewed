from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

from webconf_audit.models import Severity
from webconf_audit.rule_registry import RuleMeta, StandardReference

SafeProbeMethod = Literal["GET", "HEAD", "OPTIONS"]
BodyMatcherKind = Literal["contains", "regex"]
CONDITIONAL_SAFE_PROBE_CONFIDENCES = frozenset({"medium", "high"})


@dataclass(frozen=True, slots=True)
class BodyMatcher:
    kind: BodyMatcherKind
    pattern: str
    case_sensitive: bool = False


@dataclass(frozen=True, slots=True)
class BinaryBodyMatcher:
    prefix: bytes


@dataclass(frozen=True, slots=True)
class IdentifiedServerSuppression:
    server_type: str
    paths: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class SafePathRule:
    rule_id: str
    title: str
    severity: Severity
    description: str
    recommendation: str
    paths: tuple[str, ...]
    order: int
    method: SafeProbeMethod = "GET"
    default_paths: tuple[str, ...] = ()
    body_matchers: tuple[BodyMatcher, ...] = ()
    binary_body_matchers: tuple[BinaryBodyMatcher, ...] = ()
    content_type_matchers: tuple[str, ...] = ()
    suppress_when_identified: tuple[IdentifiedServerSuppression, ...] = ()
    standards: tuple[StandardReference, ...] = ()
    metadata_recommendation: str | None = None

    def to_rule_meta(self) -> RuleMeta:
        return RuleMeta(
            rule_id=self.rule_id,
            title=self.title,
            severity=self.severity,
            description=self.description,
            recommendation=self.metadata_recommendation or self.recommendation,
            category="external",
            input_kind="probe",
            standards=self.standards,
            order=self.order,
        )


@dataclass(frozen=True, slots=True)
class ConditionalSafePathProbe:
    path: str
    server_type: str
    method: SafeProbeMethod = "GET"
    minimum_confidences: frozenset[str] = CONDITIONAL_SAFE_PROBE_CONFIDENCES


SAFE_PATH_RULES: tuple[SafePathRule, ...] = (
    SafePathRule(
        rule_id="external.git_metadata_exposed",
        title="Git metadata exposed",
        severity="high",
        description=(
            "The /.git/HEAD file is externally accessible and contains Git metadata. "
            "This may allow attackers to reconstruct source code or discover "
            "sensitive information."
        ),
        recommendation="Block external access to the /.git/ directory on the web server.",
        paths=("/.git/HEAD",),
        body_matchers=(BodyMatcher("contains", "ref:", case_sensitive=True),),
        order=680,
        metadata_recommendation="Block access to .git/.",
    ),
    SafePathRule(
        rule_id="external.server_status_exposed",
        title="Server status page exposed",
        severity="medium",
        description=(
            "The /server-status endpoint is externally accessible. This page can "
            "disclose internal server metrics, client IPs, and request details to "
            "unauthenticated users."
        ),
        recommendation=(
            "Restrict access to /server-status to trusted networks or disable it "
            "in the server configuration."
        ),
        paths=("/server-status", "/server-status?auto"),
        default_paths=("/server-status",),
        suppress_when_identified=(
            IdentifiedServerSuppression("apache"),
            IdentifiedServerSuppression("lighttpd", paths=("/server-status",)),
        ),
        order=681,
        metadata_recommendation="Restrict access to status page.",
    ),
    SafePathRule(
        rule_id="external.server_info_exposed",
        title="Server info page exposed",
        severity="medium",
        description=(
            "The /server-info endpoint is externally accessible. This page can "
            "disclose detailed server configuration, loaded modules, and internal "
            "settings."
        ),
        recommendation=(
            "Restrict access to /server-info to trusted networks or disable it "
            "in the server configuration."
        ),
        paths=("/server-info",),
        order=682,
        metadata_recommendation="Restrict access to info page.",
    ),
    SafePathRule(
        rule_id="external.nginx_status_exposed",
        title="Nginx status page exposed",
        severity="low",
        description=(
            "The /nginx_status endpoint is externally accessible. This stub status "
            "page discloses connection and request counters that may aid "
            "reconnaissance."
        ),
        recommendation=(
            "Restrict access to the nginx stub_status endpoint to trusted networks "
            "or disable it."
        ),
        paths=("/nginx_status",),
        order=683,
        metadata_recommendation="Restrict access to stub_status.",
    ),
    SafePathRule(
        rule_id="external.env_file_exposed",
        title=".env file exposed",
        severity="high",
        description=(
            "The /.env file is externally accessible and appears to contain "
            "environment variable assignments. This can expose secrets and "
            "deployment configuration."
        ),
        recommendation=(
            "Block public access to /.env files and move secrets to a secure "
            "secret-management mechanism."
        ),
        paths=("/.env",),
        body_matchers=(BodyMatcher("regex", r"(?m)^[A-Za-z_][A-Za-z0-9_]*\s*="),),
        order=684,
        metadata_recommendation="Block access to .env files.",
    ),
    SafePathRule(
        rule_id="external.htaccess_exposed",
        title=".htaccess file exposed",
        severity="medium",
        description=(
            "The /.htaccess file is externally accessible. It can disclose Apache "
            "rewrite rules, access-control directives, and internal application "
            "structure."
        ),
        recommendation="Deny external access to Apache configuration files such as .htaccess.",
        paths=("/.htaccess",),
        order=685,
        metadata_recommendation="Block access to .htaccess files.",
    ),
    SafePathRule(
        rule_id="external.htpasswd_exposed",
        title=".htpasswd file exposed",
        severity="high",
        description=(
            "The /.htpasswd file is externally accessible. It can expose password "
            "hashes or account names used for HTTP authentication."
        ),
        recommendation=(
            "Block public access to .htpasswd files and rotate any credentials "
            "that may have been exposed."
        ),
        paths=("/.htpasswd",),
        order=686,
        metadata_recommendation="Block access to .htpasswd files.",
    ),
    SafePathRule(
        rule_id="external.wordpress_admin_panel_exposed",
        title="WordPress admin panel exposed",
        severity="low",
        description=(
            "The /wp-admin/ endpoint is externally reachable. Public access to the "
            "administrative login surface increases enumeration and brute-force "
            "exposure."
        ),
        recommendation=(
            "Restrict access to the WordPress admin panel with additional network "
            "or identity controls where practical."
        ),
        paths=("/wp-admin/",),
        order=687,
        metadata_recommendation="Restrict access to wp-admin.",
    ),
    SafePathRule(
        rule_id="external.phpinfo_exposed",
        title="phpinfo page exposed",
        severity="medium",
        description=(
            "The /phpinfo.php page is externally accessible and appears to disclose "
            "PHP runtime and environment details."
        ),
        recommendation=(
            "Remove phpinfo pages from production systems or restrict them to "
            "trusted administrators."
        ),
        paths=("/phpinfo.php",),
        body_matchers=(BodyMatcher("contains", "phpinfo()"),),
        order=688,
        metadata_recommendation="Remove phpinfo files.",
    ),
    SafePathRule(
        rule_id="external.elmah_axd_exposed",
        title="ELMAH error log endpoint exposed",
        severity="medium",
        description=(
            "The /elmah.axd endpoint is externally accessible. It can expose "
            "application errors, stack traces, request data, and sensitive "
            "operational details."
        ),
        recommendation="Restrict ELMAH access to trusted users or disable the endpoint in production.",
        paths=("/elmah.axd",),
        order=689,
        metadata_recommendation="Restrict access to elmah.axd.",
    ),
    SafePathRule(
        rule_id="external.trace_axd_exposed",
        title="ASP.NET trace endpoint exposed",
        severity="high",
        description=(
            "The /trace.axd endpoint is externally accessible. ASP.NET trace output "
            "can expose requests, headers, session data, and internal application "
            "behavior."
        ),
        recommendation=(
            "Disable ASP.NET tracing in production or restrict access to trusted "
            "administrators."
        ),
        paths=("/trace.axd",),
        order=690,
        metadata_recommendation="Disable trace.axd.",
    ),
    SafePathRule(
        rule_id="external.web_config_exposed",
        title="web.config exposed",
        severity="high",
        description=(
            "The /web.config file is externally accessible and appears to contain "
            "IIS or ASP.NET configuration data."
        ),
        recommendation=(
            "Block direct access to web.config and rotate any secrets that may "
            "have been disclosed."
        ),
        paths=("/web.config",),
        body_matchers=(BodyMatcher("contains", "<configuration"),),
        order=691,
        metadata_recommendation="Block access to web.config.",
    ),
    SafePathRule(
        rule_id="external.robots_txt_exposed",
        title="robots.txt exposed",
        severity="info",
        description=(
            "The /robots.txt file is externally accessible. It may reveal "
            "administrative or non-indexed paths that are useful during "
            "reconnaissance."
        ),
        recommendation=(
            "Review robots.txt contents to avoid disclosing sensitive or "
            "unnecessary internal paths."
        ),
        paths=("/robots.txt",),
        order=692,
        metadata_recommendation="Review robots.txt contents.",
    ),
    SafePathRule(
        rule_id="external.sitemap_xml_exposed",
        title="sitemap.xml exposed",
        severity="info",
        description=(
            "The /sitemap.xml file is externally accessible. It may reveal site "
            "structure and endpoints that aid reconnaissance."
        ),
        recommendation=(
            "Review sitemap contents to ensure they do not advertise sensitive or "
            "unnecessary endpoints."
        ),
        paths=("/sitemap.xml",),
        order=693,
        metadata_recommendation="Review sitemap.xml contents.",
    ),
    SafePathRule(
        rule_id="external.svn_metadata_exposed",
        title="SVN metadata exposed",
        severity="medium",
        description=(
            "The /.svn/entries file is externally accessible. Subversion metadata "
            "can disclose repository structure and historical project details."
        ),
        recommendation=(
            "Block public access to .svn directories and remove any "
            "version-control metadata from deployed web roots."
        ),
        paths=("/.svn/entries",),
        order=694,
        metadata_recommendation="Block access to .svn/.",
    ),
    SafePathRule(
        rule_id="external.backup_archive_exposed",
        title="Backup archive exposed",
        severity="medium",
        description=(
            "A common backup archive path is externally accessible. Public backup "
            "archives often contain source code, configuration files, database "
            "exports, or other sensitive deployment data."
        ),
        recommendation=(
            "Remove backup archives from the web root and block public access to "
            "backup file extensions at the web server."
        ),
        paths=(
            "/backup.zip",
            "/backup.tar.gz",
            "/site.zip",
            "/www.zip",
        ),
        binary_body_matchers=(
            BinaryBodyMatcher(b"PK\x03\x04"),
            BinaryBodyMatcher(b"\x1f\x8b"),
        ),
        content_type_matchers=(
            "application/zip",
            "application/x-zip-compressed",
            "application/gzip",
            "application/x-gzip",
        ),
        order=695,
        metadata_recommendation="Remove backup archives from the web root.",
    ),
    SafePathRule(
        rule_id="external.database_dump_exposed",
        title="Database dump exposed",
        severity="high",
        description=(
            "A common database dump path is externally accessible and its body "
            "resembles SQL dump content. This can expose application data and "
            "schema details."
        ),
        recommendation=(
            "Remove database dumps from the web root, rotate any exposed secrets, "
            "and block public access to dump files."
        ),
        paths=(
            "/backup.sql",
            "/db.sql",
            "/dump.sql",
        ),
        body_matchers=(
            BodyMatcher(
                "regex",
                r"(?im)\b(?:create\s+table|insert\s+into|mysql\s+dump|begin\s+transaction)\b",
            ),
        ),
        order=696,
        metadata_recommendation="Remove database dumps from the web root.",
    ),
    SafePathRule(
        rule_id="external.dependency_manifest_exposed",
        title="Dependency manifest exposed",
        severity="low",
        description=(
            "A common dependency manifest or lockfile is externally accessible. "
            "These files can disclose framework choices, package versions, and "
            "application structure useful during reconnaissance."
        ),
        recommendation=(
            "Avoid serving dependency manifests and lockfiles from the public "
            "web root unless intentionally required."
        ),
        paths=(
            "/composer.json",
            "/composer.lock",
            "/package.json",
            "/package-lock.json",
            "/yarn.lock",
        ),
        body_matchers=(
            BodyMatcher(
                "regex",
                r"""(?im)(?:"(?:require|dependencies|devDependencies|packages|scripts)"\s*:|^# yarn lockfile|^__metadata:)""",
            ),
        ),
        order=697,
        metadata_recommendation="Block public access to dependency manifests.",
    ),
    SafePathRule(
        rule_id="external.npmrc_exposed",
        title=".npmrc file exposed",
        severity="high",
        description=(
            "The /.npmrc file is externally accessible and appears to contain npm "
            "configuration. This file may expose private registry settings or "
            "authentication tokens."
        ),
        recommendation=(
            "Block public access to .npmrc files and rotate any registry tokens "
            "that may have been exposed."
        ),
        paths=("/.npmrc",),
        body_matchers=(
            BodyMatcher(
                "regex",
                r"(?im)^(?:registry|always-auth|//[^=\s]+:_authToken)\s*=",
            ),
        ),
        order=698,
        metadata_recommendation="Block public access to .npmrc files.",
    ),
)

CONDITIONAL_SAFE_PATH_PROBES: tuple[ConditionalSafePathProbe, ...] = (
    ConditionalSafePathProbe(path="/server-status?auto", server_type="apache"),
)


def _conditional_safe_probe_paths_by_server_type(
    probes: tuple[ConditionalSafePathProbe, ...],
    confidence: str | None = None,
) -> dict[str, tuple[str, ...]]:
    return {
        server_type: tuple(
            probe.path
            for probe in probes
            if probe.server_type == server_type
            and (confidence is None or confidence in probe.minimum_confidences)
        )
        for server_type in sorted({probe.server_type for probe in probes})
    }


DEFAULT_SAFE_PROBE_PATHS: tuple[str, ...] = tuple(
    path for rule in SAFE_PATH_RULES for path in (rule.default_paths or rule.paths)
)
CONDITIONAL_SAFE_PROBE_PATHS_BY_SERVER_TYPE: dict[str, tuple[str, ...]] = (
    _conditional_safe_probe_paths_by_server_type(CONDITIONAL_SAFE_PATH_PROBES)
)
SAFE_PATH_RULE_METAS: tuple[RuleMeta, ...] = tuple(
    rule.to_rule_meta() for rule in SAFE_PATH_RULES
)


def safe_probe_paths_for_identification(
    server_type: str | None,
    confidence: str | None,
) -> tuple[str, ...]:
    if server_type is None or confidence is None:
        return DEFAULT_SAFE_PROBE_PATHS

    conditional_paths = _conditional_safe_probe_paths_by_server_type(
        CONDITIONAL_SAFE_PATH_PROBES,
        confidence,
    ).get(server_type, ())
    if not conditional_paths:
        return DEFAULT_SAFE_PROBE_PATHS

    return DEFAULT_SAFE_PROBE_PATHS + tuple(
        path for path in conditional_paths if path not in DEFAULT_SAFE_PROBE_PATHS
    )


def body_matcher_matches(matcher: BodyMatcher, body_snippet: str | None) -> bool:
    if body_snippet is None:
        return False
    if matcher.kind == "contains":
        if matcher.case_sensitive:
            return matcher.pattern in body_snippet
        return matcher.pattern.lower() in body_snippet.lower()
    if matcher.kind == "regex":
        flags = 0 if matcher.case_sensitive else re.IGNORECASE
        return re.search(matcher.pattern, body_snippet, flags) is not None
    raise ValueError(f"Unsupported body matcher kind: {matcher.kind}")


def binary_body_matcher_matches(
    matcher: BinaryBodyMatcher,
    raw_body_prefix: bytes | None,
) -> bool:
    if raw_body_prefix is None:
        return False
    return raw_body_prefix.startswith(matcher.prefix)


def content_type_matches(expected: str, content_type: str | None) -> bool:
    if content_type is None:
        return False
    media_type = content_type.split(";", 1)[0].strip().lower()
    return media_type == expected.lower()


__all__ = [
    "BinaryBodyMatcher",
    "BodyMatcher",
    "CONDITIONAL_SAFE_PROBE_CONFIDENCES",
    "CONDITIONAL_SAFE_PROBE_PATHS_BY_SERVER_TYPE",
    "CONDITIONAL_SAFE_PATH_PROBES",
    "DEFAULT_SAFE_PROBE_PATHS",
    "IdentifiedServerSuppression",
    "SAFE_PATH_RULE_METAS",
    "SAFE_PATH_RULES",
    "SafePathRule",
    "SafeProbeMethod",
    "binary_body_matcher_matches",
    "body_matcher_matches",
    "content_type_matches",
    "safe_probe_paths_for_identification",
]
