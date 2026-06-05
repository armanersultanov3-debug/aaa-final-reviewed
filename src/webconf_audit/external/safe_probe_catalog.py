"""Declarative catalog of safe external sensitive-path probes.

Each :class:`SafePathRule` describes a single ``GET``/``HEAD``/``OPTIONS``
probe with a body matcher, severity, and standards metadata. The
catalog backs the ``external.*_exposed`` rule family; new safe-probe
rules are added by extending the catalog rather than by adding a
bespoke finder per path. See ``docs/roadmap.md`` STD-GAP-015 for the
growth policy and the safety rules each entry must satisfy.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

from webconf_audit.models import Severity
from webconf_audit.rule_registry import RuleMeta, StandardReference
from webconf_audit.standards import asvs_5, cwe, owasp_top10_2021

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


def _partial_asvs(requirement: str, note: str) -> StandardReference:
    return asvs_5(requirement, coverage="partial", note=note)


def _configuration_exposure_standards(note: str) -> tuple[StandardReference, ...]:
    return (
        cwe(538),
        owasp_top10_2021("A05:2021"),
        _partial_asvs("13.4.7", note),
    )


def _credential_exposure_standards(note: str) -> tuple[StandardReference, ...]:
    return (
        cwe(522),
        owasp_top10_2021("A07:2021"),
        _partial_asvs("13.4.7", note),
    )


def _information_disclosure_standards() -> tuple[StandardReference, ...]:
    return (
        cwe(200),
        owasp_top10_2021("A05:2021"),
    )


def _admin_surface_standards() -> tuple[StandardReference, ...]:
    return (
        cwe(306),
        owasp_top10_2021("A01:2021"),
    )


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
        paths=(
            "/.env",
            "/.env.local",
            "/.env.production",
            "/.env.staging",
        ),
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
            "/backup.7z",
            "/backup.rar",
            "/site.zip",
            "/www.zip",
        ),
        binary_body_matchers=(
            BinaryBodyMatcher(b"PK\x03\x04"),
            BinaryBodyMatcher(b"\x1f\x8b"),
            BinaryBodyMatcher(b"7z\xbc\xaf\x27\x1c"),
            BinaryBodyMatcher(b"Rar!\x1a\x07"),
        ),
        content_type_matchers=(
            "application/zip",
            "application/x-zip-compressed",
            "application/gzip",
            "application/x-gzip",
            "application/x-7z-compressed",
            "application/vnd.rar",
            "application/x-rar-compressed",
        ),
        order=695,
        metadata_recommendation="Remove backup archives from the web root.",
    ),
    SafePathRule(
        rule_id="external.backup_file_exposed",
        title="Backup file exposed",
        severity="medium",
        description=(
            "A common backup or temporary file path is externally accessible. "
            "These files can disclose source code, configuration, or build-time "
            "artifacts."
        ),
        recommendation=(
            "Remove backup and temporary files from the web root and block "
            "public access to backup file extensions."
        ),
        paths=(
            "/index.php.bak",
            "/index.php.old",
            "/index.php.backup",
            "/index.php.orig",
            "/index.php.save",
            "/index.php.swp",
            "/index.php.tmp",
            "/index.php~",
        ),
        order=696,
        standards=(
            cwe(538),
            owasp_top10_2021("A05:2021"),
            asvs_5(
                "13.4.7",
                coverage="partial",
                note="Backup/temp file exposure only.",
            ),
        ),
        metadata_recommendation="Remove backup and temporary files from the web root.",
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
            "/database.sql",
            "/db.sql",
            "/dump.sql",
            "/mysql.sql",
            "/production.sql",
        ),
        body_matchers=(
            BodyMatcher(
                "regex",
                r"(?im)\b(?:create\s+table|insert\s+into|mysql\s+dump|begin\s+transaction)\b",
            ),
        ),
        order=697,
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
            "/Pipfile",
            "/Pipfile.lock",
            "/Gemfile",
            "/Gemfile.lock",
            "/package.json",
            "/package-lock.json",
            "/pnpm-lock.yaml",
            "/poetry.lock",
            "/requirements.txt",
            "/yarn.lock",
            "/go.mod",
            "/go.sum",
            "/Cargo.toml",
            "/Cargo.lock",
        ),
        body_matchers=(
            BodyMatcher(
                "regex",
                r"""(?im)(?:"(?:require|dependencies|devDependencies|packages|scripts)"\s*:|"pipfile-spec"\s*:|^# yarn lockfile|^__metadata:|^lockfileVersion:|^\[\[package\]\]|^\[package\]|^\[packages\]|^gem\s+["']|^GEM\s*$|^module\s+\S+|^\S+\s+v\d+\.\d+\.\d+(?:[-+][^\s]+)?\s+h1:|^[A-Za-z0-9_.-]+(?:==|>=|<=|~=|!=|>|<)[^\s]+)""",
            ),
        ),
        order=698,
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
                r"(?im)^(?:(?:@[^=\s:]+:)?registry|always-auth|_authToken|//[^=\s]+:_authToken)\s*=",
            ),
        ),
        order=699,
        metadata_recommendation="Block public access to .npmrc files.",
    ),
    SafePathRule(
        rule_id="external.laravel_storage_logs_exposed",
        title="Laravel storage log file exposed",
        severity="high",
        description=(
            "The /storage/logs/laravel.log file is externally accessible and "
            "appears to contain Laravel application log output. Public log files "
            "can disclose stack traces, request data, and secrets."
        ),
        recommendation=(
            "Block public access to Laravel log files and move application logs "
            "outside the web root."
        ),
        paths=("/storage/logs/laravel.log",),
        body_matchers=(
            BodyMatcher(
                "regex",
                r"(?im)^(?:\[[^\]]+\]\s+)?(?:local|production|staging|testing)\.(?:EMERGENCY|ALERT|CRITICAL|ERROR|WARNING|NOTICE|INFO|DEBUG):",
            ),
        ),
        standards=(
            cwe(538),
            owasp_top10_2021("A05:2021"),
            asvs_5(
                "13.4.7",
                coverage="partial",
                note="Publicly exposed application log file.",
            ),
        ),
        order=720,
        metadata_recommendation="Block public access to Laravel log files.",
    ),
    SafePathRule(
        rule_id="external.symfony_profiler_exposed",
        title="Symfony profiler exposed",
        severity="high",
        description=(
            "The /_profiler/empty/search/results endpoint is externally "
            "accessible and appears to expose Symfony profiler output. This can "
            "disclose debug data, routes, headers, and internal application "
            "details."
        ),
        recommendation=(
            "Disable the Symfony profiler in production or restrict access to "
            "trusted administrators."
        ),
        paths=("/_profiler/empty/search/results?limit=10",),
        body_matchers=(
            BodyMatcher(
                "regex",
                r"(?i)(Symfony Profiler|<title>\s*Profiler\s*</title>|Symfony-Debug-Toolbar)",
            ),
        ),
        standards=(
            cwe(200),
            owasp_top10_2021("A05:2021"),
        ),
        order=721,
        metadata_recommendation="Disable or restrict Symfony profiler in production.",
    ),
    SafePathRule(
        rule_id="external.adminer_panel_exposed",
        title="Adminer panel exposed",
        severity="low",
        description=(
            "The /adminer.php endpoint is externally accessible and appears to "
            "expose an Adminer database administration login surface. Public "
            "database admin panels increase reconnaissance and brute-force "
            "exposure."
        ),
        recommendation=(
            "Restrict Adminer to trusted administrators or remove it from "
            "production deployments."
        ),
        paths=("/adminer.php",),
        body_matchers=(
            BodyMatcher(
                "regex",
                r"(?i)<title>\s*(?:login\s*-\s*)?adminer\s*</title>",
            ),
        ),
        standards=(
            cwe(200),
            owasp_top10_2021("A05:2021"),
        ),
        order=722,
        metadata_recommendation="Restrict or remove Adminer in production.",
    ),
    SafePathRule(
        rule_id="external.phpmyadmin_dashboard_exposed",
        title="phpMyAdmin dashboard exposed",
        severity="high",
        description=(
            "The /phpmyadmin/index.php endpoint is externally accessible and "
            "appears to expose a phpMyAdmin dashboard without an intervening "
            "login prompt. This can grant unauthenticated access to database "
            "administration features."
        ),
        recommendation=(
            "Require authentication for phpMyAdmin, restrict it to trusted "
            "administrators, or remove it from production."
        ),
        paths=("/phpmyadmin/index.php",),
        body_matchers=(
            BodyMatcher("regex", r"(?i)server_(?:sql|status)\.php"),
            BodyMatcher("regex", r"(?i)server_(?:variables|databases)\.php"),
        ),
        standards=(
            cwe(306),
            owasp_top10_2021("A01:2021"),
        ),
        order=723,
        metadata_recommendation="Require authentication for phpMyAdmin.",
    ),
    SafePathRule(
        rule_id="external.springboot_actuator_env_exposed",
        title="Spring Boot Actuator env endpoint exposed",
        severity="medium",
        description=(
            "The /actuator/env endpoint is externally accessible and appears to "
            "expose Spring Boot environment metadata. This can disclose "
            "application configuration and deployment details."
        ),
        recommendation=(
            "Disable the env actuator in production or restrict access to "
            "trusted administrators."
        ),
        paths=("/actuator/env",),
        body_matchers=(
            BodyMatcher("regex", r"(?i)(applicationConfig|activeProfiles)"),
            BodyMatcher("regex", r"(?i)(server\.port|local\.server\.port)"),
        ),
        standards=(
            cwe(200),
            owasp_top10_2021("A05:2021"),
        ),
        order=724,
        metadata_recommendation="Disable or restrict the env actuator endpoint.",
    ),
    SafePathRule(
        rule_id="external.wordpress_wp_config_bak_exposed",
        title="WordPress wp-config.php.bak exposed",
        severity="high",
        description=(
            "The /wp-config.php.bak file is externally accessible and appears to "
            "contain WordPress database configuration. This can expose database "
            "credentials and other deployment secrets."
        ),
        recommendation=(
            "Remove backup copies of wp-config.php from the web root and block "
            "public access to backup file extensions."
        ),
        paths=("/wp-config.php.bak",),
        body_matchers=(
            BodyMatcher("regex", r"(?im)\b(?:DB_NAME|DBNAME|DB_USERNAME)\b"),
            BodyMatcher("regex", r"(?im)\b(?:DB_PASSWORD|PASSWORD)\b"),
        ),
        standards=(
            cwe(538),
            owasp_top10_2021("A05:2021"),
            asvs_5(
                "13.4.7",
                coverage="partial",
                note="Backup copy of a sensitive configuration file.",
            ),
        ),
        order=725,
        metadata_recommendation="Remove backup wp-config files from the web root.",
    ),
    SafePathRule(
        rule_id="external.wordpress_wp_config_tilde_exposed",
        title="WordPress wp-config.php~ exposed",
        severity="high",
        description=(
            "The /wp-config.php~ file is externally accessible and appears to "
            "contain WordPress database configuration. This can expose database "
            "credentials and other deployment secrets."
        ),
        recommendation=(
            "Remove editor backup copies of wp-config.php from the web root and "
            "block public access to temporary file extensions."
        ),
        paths=("/wp-config.php~",),
        body_matchers=(
            BodyMatcher("regex", r"(?im)\b(?:DB_NAME|DBNAME|DB_USERNAME)\b"),
            BodyMatcher("regex", r"(?im)\b(?:DB_PASSWORD|PASSWORD)\b"),
        ),
        standards=(
            cwe(538),
            owasp_top10_2021("A05:2021"),
            asvs_5(
                "13.4.7",
                coverage="partial",
                note="Editor backup copy of a sensitive configuration file.",
            ),
        ),
        order=726,
        metadata_recommendation="Remove temporary wp-config files from the web root.",
    ),
    SafePathRule(
        rule_id="external.searchreplacedb2_exposed",
        title="Search Replace DB tool exposed",
        severity="high",
        description=(
            "The /searchreplacedb2.php endpoint is externally accessible and "
            "appears to expose the Search Replace DB administration utility. "
            "Public database maintenance tools can disclose internal database "
            "details and enable unauthorized administrative actions."
        ),
        recommendation=(
            "Remove Search Replace DB from production or restrict it to trusted "
            "administrators."
        ),
        paths=("/searchreplacedb2.php",),
        body_matchers=(
            BodyMatcher("contains", "Database details", case_sensitive=True),
            BodyMatcher("contains", "Safe Search Replace", case_sensitive=True),
        ),
        standards=(
            cwe(306),
            owasp_top10_2021("A01:2021"),
        ),
        order=727,
        metadata_recommendation="Remove or restrict Search Replace DB in production.",
    ),
    SafePathRule(
        rule_id="external.webpack_config_exposed",
        title="webpack.config.js exposed",
        severity="low",
        description=(
            "The /webpack.config.js file is externally accessible and appears to "
            "contain build configuration. This can disclose internal asset "
            "pipelines, source layout, and environment-specific settings."
        ),
        recommendation=(
            "Avoid serving webpack.config.js from the public web root and keep "
            "build configuration outside exposed paths."
        ),
        paths=("/webpack.config.js",),
        body_matchers=(
            BodyMatcher("regex", r"(?im)\b(?:module\.exports|export\s+default)\b"),
            BodyMatcher("regex", r"(?im)\b(?:entry|output|plugins|rules?)\b"),
        ),
        standards=(
            cwe(538),
            owasp_top10_2021("A05:2021"),
            asvs_5(
                "13.4.7",
                coverage="partial",
                note="Publicly exposed build configuration file.",
            ),
        ),
        order=728,
        metadata_recommendation="Do not serve webpack.config.js publicly.",
    ),
    SafePathRule(
        rule_id="external.webpack_mix_exposed",
        title="webpack.mix.js exposed",
        severity="low",
        description=(
            "The /webpack.mix.js file is externally accessible and appears to "
            "contain Laravel Mix build configuration. This can disclose asset "
            "build paths and internal deployment structure."
        ),
        recommendation=(
            "Avoid serving webpack.mix.js from the public web root and keep "
            "build configuration outside exposed paths."
        ),
        paths=("/webpack.mix.js",),
        body_matchers=(
            BodyMatcher("regex", r"(?im)\bconst\s+mix\b"),
            BodyMatcher("regex", r"(?im)\bmix\."),
        ),
        standards=(
            cwe(538),
            owasp_top10_2021("A05:2021"),
            asvs_5(
                "13.4.7",
                coverage="partial",
                note="Publicly exposed asset build configuration file.",
            ),
        ),
        order=729,
        metadata_recommendation="Do not serve webpack.mix.js publicly.",
    ),
    SafePathRule(
        rule_id="external.aws_credentials_exposed",
        title="AWS shared credentials file exposed",
        severity="high",
        description=(
            "The /.aws/credentials file is externally accessible and appears to "
            "contain AWS shared credentials. This can expose cloud access keys "
            "and permit unauthorized access to AWS resources."
        ),
        recommendation=(
            "Block public access to AWS credential files and rotate any access "
            "keys that may have been exposed."
        ),
        paths=("/.aws/credentials",),
        body_matchers=(
            BodyMatcher("regex", r"(?im)^\s*\[[^\]\r\n]+\]\s*$"),
            BodyMatcher("regex", r"(?im)^\s*aws_access_key_id\s*="),
            BodyMatcher("regex", r"(?im)^\s*aws_secret_access_key\s*="),
        ),
        standards=_credential_exposure_standards(
            "Publicly exposed AWS shared credentials file."
        ),
        order=730,
        metadata_recommendation="Block public access to AWS credentials files.",
    ),
    SafePathRule(
        rule_id="external.aws_config_exposed",
        title="AWS CLI config file exposed",
        severity="medium",
        description=(
            "The /.aws/config file is externally accessible and appears to "
            "contain AWS CLI configuration. This can disclose account, region, "
            "and profile details useful for cloud reconnaissance."
        ),
        recommendation=(
            "Block public access to AWS CLI configuration files and move "
            "deployment-specific configuration outside the web root."
        ),
        paths=("/.aws/config",),
        body_matchers=(
            BodyMatcher("regex", r"(?im)^\s*\[(?:default|profile\s+[^\]]+)\]\s*$"),
            BodyMatcher("regex", r"(?im)^\s*(?:region|output|role_arn)\s*="),
        ),
        standards=_configuration_exposure_standards(
            "Publicly exposed AWS CLI configuration file."
        ),
        order=731,
        metadata_recommendation="Block public access to AWS CLI config files.",
    ),
    SafePathRule(
        rule_id="external.docker_config_exposed",
        title="Docker config.json exposed",
        severity="high",
        description=(
            "The /.docker/config.json file is externally accessible and appears "
            "to contain Docker client configuration. This can expose registry "
            "credentials or private registry endpoints."
        ),
        recommendation=(
            "Block public access to Docker client configuration files and "
            "rotate any registry credentials that may have been exposed."
        ),
        paths=("/.docker/config.json",),
        body_matchers=(
            BodyMatcher("regex", r'(?i)"(?:auths|credsStore|credHelpers)"\s*:'),
        ),
        standards=_credential_exposure_standards(
            "Publicly exposed Docker client credential/configuration file."
        ),
        order=732,
        metadata_recommendation="Block public access to Docker config.json.",
    ),
    SafePathRule(
        rule_id="external.kube_config_exposed",
        title="Kubernetes kubeconfig exposed",
        severity="high",
        description=(
            "The /.kube/config file is externally accessible and appears to "
            "contain Kubernetes client configuration. This can expose cluster "
            "endpoints, identities, and authentication material."
        ),
        recommendation=(
            "Block public access to kubeconfig files and rotate any credentials "
            "or certificates that may have been exposed."
        ),
        paths=("/.kube/config",),
        body_matchers=(
            BodyMatcher("regex", r"(?im)^\s*clusters\s*:"),
            BodyMatcher("regex", r"(?im)^\s*contexts\s*:"),
            BodyMatcher("regex", r"(?im)^\s*users\s*:"),
        ),
        standards=_credential_exposure_standards(
            "Publicly exposed Kubernetes client configuration file."
        ),
        order=733,
        metadata_recommendation="Block public access to kubeconfig files.",
    ),
    SafePathRule(
        rule_id="external.ssh_private_key_exposed",
        title="SSH private key exposed",
        severity="high",
        description=(
            "A common SSH private key path is externally accessible and appears "
            "to contain private key material. This can enable unauthorized "
            "access to infrastructure and deployment systems."
        ),
        recommendation=(
            "Block public access to private key files and rotate any keys that "
            "may have been exposed."
        ),
        paths=("/id_rsa", "/id_ed25519", "/id_ecdsa"),
        body_matchers=(
            BodyMatcher(
                "regex",
                r"-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----",
            ),
        ),
        standards=_credential_exposure_standards(
            "Publicly exposed SSH private key material."
        ),
        order=734,
        metadata_recommendation="Block public access to private key files.",
    ),
    SafePathRule(
        rule_id="external.ssh_authorized_keys_exposed",
        title="SSH authorized_keys file exposed",
        severity="medium",
        description=(
            "The /.ssh/authorized_keys file is externally accessible and appears "
            "to contain authorized SSH keys. This can disclose administrative "
            "usernames and infrastructure access patterns."
        ),
        recommendation=(
            "Block public access to authorized_keys files and keep SSH access "
            "control data outside the web root."
        ),
        paths=("/.ssh/authorized_keys",),
        body_matchers=(
            BodyMatcher(
                "regex",
                r"(?im)^(?:ssh-rsa|ssh-ed25519|ecdsa-sha2-[^\s]+)\s+[A-Za-z0-9+/=]+(?:\s+.*)?$",
            ),
        ),
        standards=_configuration_exposure_standards(
            "Publicly exposed SSH authorized_keys file."
        ),
        order=735,
        metadata_recommendation="Block public access to authorized_keys files.",
    ),
    SafePathRule(
        rule_id="external.gcp_service_account_exposed",
        title="GCP service account key exposed",
        severity="high",
        description=(
            "The /credentials.json file is externally accessible and appears to "
            "contain a Google Cloud service account key. This can expose "
            "private-key material for machine identities."
        ),
        recommendation=(
            "Block public access to service-account key files and rotate any "
            "keys that may have been exposed."
        ),
        paths=("/credentials.json",),
        body_matchers=(
            BodyMatcher("regex", r'(?i)"type"\s*:\s*"service_account"'),
            BodyMatcher("regex", r'(?i)"private_key"\s*:\s*"-----BEGIN'),
        ),
        standards=_credential_exposure_standards(
            "Publicly exposed GCP service account key file."
        ),
        order=736,
        metadata_recommendation="Block public access to GCP service-account keys.",
    ),
    SafePathRule(
        rule_id="external.springboot_actuator_heapdump_exposed",
        title="Spring Boot Actuator heapdump exposed",
        severity="high",
        description=(
            "The /actuator/heapdump endpoint is externally accessible and "
            "appears to return a JVM heap dump. Heap dumps can contain secrets, "
            "session data, and application memory contents."
        ),
        recommendation=(
            "Disable the heapdump actuator in production or restrict it to "
            "trusted administrators."
        ),
        paths=("/actuator/heapdump",),
        binary_body_matchers=(BinaryBodyMatcher(b"JAVA PROFILE"),),
        standards=_information_disclosure_standards(),
        order=737,
        metadata_recommendation="Disable or restrict the heapdump actuator endpoint.",
    ),
    SafePathRule(
        rule_id="external.springboot_actuator_threaddump_exposed",
        title="Spring Boot Actuator threaddump exposed",
        severity="medium",
        description=(
            "The /actuator/threaddump endpoint is externally accessible and "
            "appears to expose JVM thread dump data. This can disclose thread "
            "names, stack traces, and internal application behavior."
        ),
        recommendation=(
            "Disable the threaddump actuator in production or restrict access "
            "to trusted administrators."
        ),
        paths=("/actuator/threaddump",),
        body_matchers=(
            BodyMatcher("regex", r'(?i)"threadName"\s*:'),
            BodyMatcher("regex", r'(?i)"stackTrace"\s*:'),
        ),
        standards=_information_disclosure_standards(),
        order=738,
        metadata_recommendation="Disable or restrict the threaddump actuator endpoint.",
    ),
    SafePathRule(
        rule_id="external.springboot_actuator_configprops_exposed",
        title="Spring Boot Actuator configprops exposed",
        severity="medium",
        description=(
            "The /actuator/configprops endpoint is externally accessible and "
            "appears to expose Spring Boot configuration properties. This can "
            "disclose application settings and deployment metadata."
        ),
        recommendation=(
            "Disable the configprops actuator in production or restrict access "
            "to trusted administrators."
        ),
        paths=("/actuator/configprops",),
        body_matchers=(
            BodyMatcher("regex", r'(?i)"contexts"\s*:'),
            BodyMatcher("regex", r'(?i)"(?:properties|beans)"\s*:'),
        ),
        standards=_information_disclosure_standards(),
        order=739,
        metadata_recommendation="Disable or restrict the configprops actuator endpoint.",
    ),
    SafePathRule(
        rule_id="external.springboot_actuator_beans_exposed",
        title="Spring Boot Actuator beans exposed",
        severity="low",
        description=(
            "The /actuator/beans endpoint is externally accessible and appears "
            "to expose the Spring bean graph. This can disclose application "
            "components and framework internals useful for reconnaissance."
        ),
        recommendation=(
            "Disable the beans actuator in production or restrict access to "
            "trusted administrators."
        ),
        paths=("/actuator/beans",),
        body_matchers=(BodyMatcher("regex", r'(?i)"beans"\s*:'),),
        standards=_information_disclosure_standards(),
        order=740,
        metadata_recommendation="Disable or restrict the beans actuator endpoint.",
    ),
    SafePathRule(
        rule_id="external.springboot_actuator_mappings_exposed",
        title="Spring Boot Actuator mappings exposed",
        severity="low",
        description=(
            "The /actuator/mappings endpoint is externally accessible and "
            "appears to expose route mappings. This can disclose internal "
            "application endpoints and handler details."
        ),
        recommendation=(
            "Disable the mappings actuator in production or restrict access to "
            "trusted administrators."
        ),
        paths=("/actuator/mappings",),
        body_matchers=(BodyMatcher("regex", r'(?i)"mappings"\s*:'),),
        standards=_information_disclosure_standards(),
        order=741,
        metadata_recommendation="Disable or restrict the mappings actuator endpoint.",
    ),
    SafePathRule(
        rule_id="external.rails_master_key_exposed",
        title="Rails master.key exposed",
        severity="high",
        description=(
            "A common Rails master key path is externally accessible and "
            "appears to contain the Rails master key. This can permit "
            "decryption of encrypted application secrets."
        ),
        recommendation=(
            "Block public access to Rails master.key files and rotate the key "
            "if exposure is suspected."
        ),
        paths=("/config/master.key", "/master.key"),
        body_matchers=(BodyMatcher("regex", r"(?i)^[a-f0-9]{32}\s*$"),),
        standards=_credential_exposure_standards(
            "Publicly exposed Rails master key."
        ),
        order=742,
        metadata_recommendation="Block public access to Rails master.key files.",
    ),
    SafePathRule(
        rule_id="external.rails_credentials_yml_enc_exposed",
        title="Rails credentials.yml.enc exposed",
        severity="medium",
        description=(
            "The /config/credentials.yml.enc file is externally accessible. "
            "Even though the file is encrypted, its public exposure discloses "
            "sensitive deployment artifacts and can aid attackers when combined "
            "with other leaks."
        ),
        recommendation=(
            "Block public access to encrypted credential files and keep Rails "
            "secret material outside the web root."
        ),
        paths=("/config/credentials.yml.enc",),
        body_matchers=(
            BodyMatcher("regex", r"(?m)^[A-Za-z0-9+/=]{32,}\s*$"),
        ),
        standards=_configuration_exposure_standards(
            "Publicly exposed encrypted Rails credentials file."
        ),
        order=743,
        metadata_recommendation="Block public access to Rails credentials.yml.enc.",
    ),
    SafePathRule(
        rule_id="external.rails_database_yml_exposed",
        title="Rails database.yml exposed",
        severity="high",
        description=(
            "A common Rails database.yml path is externally accessible and "
            "appears to contain database connection settings. This can disclose "
            "database names, adapters, and credentials."
        ),
        recommendation=(
            "Block public access to Rails database.yml files and move database "
            "configuration outside exposed paths."
        ),
        paths=("/config/database.yml", "/database.yml"),
        body_matchers=(
            BodyMatcher("regex", r"(?im)^\s*adapter\s*:"),
            BodyMatcher("regex", r"(?im)^\s*database\s*:"),
        ),
        standards=_configuration_exposure_standards(
            "Publicly exposed Rails database configuration file."
        ),
        order=744,
        metadata_recommendation="Block public access to Rails database.yml files.",
    ),
    SafePathRule(
        rule_id="external.drupal_settings_php_exposed",
        title="Drupal settings.php exposed",
        severity="high",
        description=(
            "The /sites/default/settings.php file is externally accessible and "
            "appears to contain Drupal settings. This can disclose database "
            "configuration and deployment secrets."
        ),
        recommendation=(
            "Block public access to Drupal settings.php and rotate any secrets "
            "that may have been exposed."
        ),
        paths=("/sites/default/settings.php",),
        body_matchers=(
            BodyMatcher("contains", "<?php", case_sensitive=True),
            BodyMatcher("regex", r"(?im)\$databases\s*="),
        ),
        standards=_configuration_exposure_standards(
            "Publicly exposed Drupal settings.php file."
        ),
        order=745,
        metadata_recommendation="Block public access to Drupal settings.php.",
    ),
    SafePathRule(
        rule_id="external.magento_env_php_exposed",
        title="Magento env.php exposed",
        severity="high",
        description=(
            "The /app/etc/env.php file is externally accessible and appears to "
            "contain Magento environment configuration. This can expose "
            "cryptographic keys, database settings, and deployment secrets."
        ),
        recommendation=(
            "Block public access to Magento env.php and rotate any secrets that "
            "may have been exposed."
        ),
        paths=("/app/etc/env.php",),
        body_matchers=(
            BodyMatcher("regex", r"(?i)return\s+(?:array\s*\(|\[)"),
            BodyMatcher("regex", r"""(?i)['"](?:crypt|db)['"]\s*=>"""),
        ),
        standards=_configuration_exposure_standards(
            "Publicly exposed Magento env.php file."
        ),
        order=746,
        metadata_recommendation="Block public access to Magento env.php.",
    ),
    SafePathRule(
        rule_id="external.joomla_configuration_php_exposed",
        title="Joomla configuration.php exposed",
        severity="high",
        description=(
            "The /configuration.php file is externally accessible and appears "
            "to contain Joomla configuration. This can disclose database "
            "settings and site secrets."
        ),
        recommendation=(
            "Block public access to Joomla configuration.php and rotate any "
            "secrets that may have been exposed."
        ),
        paths=("/configuration.php",),
        body_matchers=(BodyMatcher("contains", "class JConfig", case_sensitive=True),),
        standards=_configuration_exposure_standards(
            "Publicly exposed Joomla configuration.php file."
        ),
        order=747,
        metadata_recommendation="Block public access to Joomla configuration.php.",
    ),
    SafePathRule(
        rule_id="external.werkzeug_debug_console_exposed",
        title="Werkzeug debug console exposed",
        severity="high",
        description=(
            "The /console endpoint is externally accessible and appears to "
            "expose the Werkzeug debug console. This surface can disclose "
            "internal details and may permit dangerous debugging actions."
        ),
        recommendation=(
            "Disable the Werkzeug debugger in production or restrict access to "
            "trusted administrators."
        ),
        paths=("/console",),
        body_matchers=(
            BodyMatcher("regex", r"(?i)<title>\s*Console\s*</title>"),
            BodyMatcher("contains", "Werkzeug"),
        ),
        standards=_admin_surface_standards(),
        order=748,
        metadata_recommendation="Disable or restrict the Werkzeug debug console.",
    ),
    SafePathRule(
        rule_id="external.swagger_ui_exposed",
        title="Swagger UI exposed",
        severity="low",
        description=(
            "A common Swagger UI path is externally accessible and appears to "
            "expose interactive API documentation. This can disclose API shape "
            "and routes useful during reconnaissance."
        ),
        recommendation=(
            "Review whether Swagger UI should be publicly reachable and restrict "
            "it to trusted users where appropriate."
        ),
        paths=("/swagger-ui/", "/swagger-ui.html"),
        body_matchers=(
            BodyMatcher(
                "regex",
                r"(?i)(<title>\s*Swagger UI\s*</title>|swagger-ui-bundle\.js)",
            ),
        ),
        standards=_information_disclosure_standards(),
        order=749,
        metadata_recommendation="Restrict public access to Swagger UI.",
    ),
    SafePathRule(
        rule_id="external.openapi_spec_exposed",
        title="OpenAPI specification exposed",
        severity="low",
        description=(
            "A common OpenAPI spec path is externally accessible and appears to "
            "expose API schema data. This can disclose endpoints, models, and "
            "internal API structure."
        ),
        recommendation=(
            "Review whether OpenAPI schemas should be public and restrict them "
            "to trusted users where practical."
        ),
        paths=("/v2/api-docs", "/v3/api-docs", "/api-docs"),
        body_matchers=(
            BodyMatcher(
                "regex",
                r'(?i)"(?:openapi|swagger)"\s*:\s*"(?:3\.[0-9.]*|2\.0)"',
            ),
        ),
        standards=_information_disclosure_standards(),
        order=750,
        metadata_recommendation="Review whether OpenAPI specs should be public.",
    ),
    SafePathRule(
        rule_id="external.gitlab_ci_yml_exposed",
        title=".gitlab-ci.yml exposed",
        severity="low",
        description=(
            "The /.gitlab-ci.yml file is externally accessible and appears to "
            "contain GitLab CI pipeline configuration. This can disclose build "
            "steps, images, and internal deployment workflows."
        ),
        recommendation=(
            "Avoid serving CI configuration files from the public web root and "
            "keep pipeline definitions outside exposed paths."
        ),
        paths=("/.gitlab-ci.yml",),
        body_matchers=(
            BodyMatcher("regex", r"(?im)^\s*stages\s*:"),
            BodyMatcher("regex", r"(?im)^\s*(?:script|image)\s*:"),
        ),
        standards=_configuration_exposure_standards(
            "Publicly exposed GitLab CI configuration file."
        ),
        order=751,
        metadata_recommendation="Do not serve GitLab CI configuration files publicly.",
    ),
    SafePathRule(
        rule_id="external.github_workflow_exposed",
        title="GitHub Actions workflow exposed",
        severity="low",
        description=(
            "A common GitHub Actions workflow path is externally accessible and "
            "appears to contain workflow configuration. This can disclose build "
            "jobs, triggers, and CI infrastructure details."
        ),
        recommendation=(
            "Avoid serving GitHub Actions workflow files from the public web "
            "root and keep CI definitions outside exposed paths."
        ),
        paths=(
            "/.github/workflows/ci.yml",
            "/.github/workflows/main.yml",
            "/.github/workflows/build.yml",
        ),
        body_matchers=(
            BodyMatcher("regex", r"(?im)^\s*on\s*:"),
            BodyMatcher("regex", r"(?im)^\s*jobs\s*:"),
            BodyMatcher("regex", r"(?im)^\s*runs-on\s*:"),
        ),
        standards=_configuration_exposure_standards(
            "Publicly exposed GitHub Actions workflow file."
        ),
        order=752,
        metadata_recommendation="Do not serve GitHub Actions workflow files publicly.",
    ),
    SafePathRule(
        rule_id="external.travis_ci_exposed",
        title=".travis.yml exposed",
        severity="low",
        description=(
            "The /.travis.yml file is externally accessible and appears to "
            "contain Travis CI configuration. This can disclose build and test "
            "steps useful during reconnaissance."
        ),
        recommendation=(
            "Avoid serving Travis CI configuration files from the public web "
            "root and keep pipeline definitions outside exposed paths."
        ),
        paths=("/.travis.yml",),
        body_matchers=(
            BodyMatcher("regex", r"(?im)^\s*language\s*:"),
            BodyMatcher("regex", r"(?im)^\s*script\s*:"),
        ),
        standards=_configuration_exposure_standards(
            "Publicly exposed Travis CI configuration file."
        ),
        order=753,
        metadata_recommendation="Do not serve Travis CI configuration files publicly.",
    ),
    SafePathRule(
        rule_id="external.jenkinsfile_exposed",
        title="Jenkinsfile exposed",
        severity="low",
        description=(
            "The /Jenkinsfile path is externally accessible and appears to "
            "contain Jenkins pipeline configuration. This can disclose build "
            "logic and deployment workflow details."
        ),
        recommendation=(
            "Avoid serving Jenkins pipeline definitions from the public web "
            "root and keep them outside exposed paths."
        ),
        paths=("/Jenkinsfile",),
        body_matchers=(BodyMatcher("regex", r"(?im)\b(?:pipeline|node)\s*\{"),),
        standards=_configuration_exposure_standards(
            "Publicly exposed Jenkins pipeline definition."
        ),
        order=754,
        metadata_recommendation="Do not serve Jenkinsfile publicly.",
    ),
    SafePathRule(
        rule_id="external.circleci_config_exposed",
        title="CircleCI config exposed",
        severity="low",
        description=(
            "The /.circleci/config.yml file is externally accessible and "
            "appears to contain CircleCI configuration. This can disclose CI "
            "jobs and internal pipeline structure."
        ),
        recommendation=(
            "Avoid serving CircleCI configuration files from the public web "
            "root and keep them outside exposed paths."
        ),
        paths=("/.circleci/config.yml",),
        body_matchers=(
            BodyMatcher("regex", r"""(?im)^\s*version\s*:\s*['"]?2(?:\.\d+)?['"]?\s*$"""),
            BodyMatcher("regex", r"(?im)^\s*jobs\s*:"),
        ),
        standards=_configuration_exposure_standards(
            "Publicly exposed CircleCI configuration file."
        ),
        order=755,
        metadata_recommendation="Do not serve CircleCI configuration files publicly.",
    ),
    SafePathRule(
        rule_id="external.dockerfile_exposed",
        title="Dockerfile exposed",
        severity="low",
        description=(
            "The /Dockerfile path is externally accessible and appears to "
            "contain Docker build instructions. This can disclose base images, "
            "build steps, and internal deployment assumptions."
        ),
        recommendation=(
            "Avoid serving Dockerfiles from the public web root and keep build "
            "artifacts outside exposed paths."
        ),
        paths=("/Dockerfile",),
        body_matchers=(
            BodyMatcher("regex", r"(?im)^\s*FROM\s+\S+"),
            BodyMatcher("regex", r"(?im)^\s*(?:RUN|COPY|CMD)\b"),
        ),
        standards=_configuration_exposure_standards(
            "Publicly exposed Docker build definition."
        ),
        order=756,
        metadata_recommendation="Do not serve Dockerfiles publicly.",
    ),
    SafePathRule(
        rule_id="external.docker_compose_exposed",
        title="docker-compose file exposed",
        severity="low",
        description=(
            "A common docker-compose file path is externally accessible and "
            "appears to contain container orchestration settings. This can "
            "disclose services, internal ports, and deployment structure."
        ),
        recommendation=(
            "Avoid serving docker-compose files from the public web root and "
            "keep deployment configuration outside exposed paths."
        ),
        paths=("/docker-compose.yml", "/docker-compose.yaml"),
        body_matchers=(BodyMatcher("regex", r"(?im)^\s*services\s*:"),),
        standards=_configuration_exposure_standards(
            "Publicly exposed docker-compose configuration file."
        ),
        order=757,
        metadata_recommendation="Do not serve docker-compose files publicly.",
    ),
    SafePathRule(
        rule_id="external.mercurial_metadata_exposed",
        title="Mercurial metadata exposed",
        severity="medium",
        description=(
            "The /.hg/requires file is externally accessible and appears to "
            "contain Mercurial repository metadata. This can disclose repository "
            "format details and confirm version-control metadata leakage."
        ),
        recommendation=(
            "Block public access to .hg directories and remove Mercurial "
            "repository metadata from deployed web roots."
        ),
        paths=("/.hg/requires",),
        body_matchers=(BodyMatcher("regex", r"(?im)^(?:revlogv1|store)\s*$"),),
        standards=_information_disclosure_standards(),
        order=758,
        metadata_recommendation="Block public access to Mercurial metadata.",
    ),
    SafePathRule(
        rule_id="external.bazaar_metadata_exposed",
        title="Bazaar metadata exposed",
        severity="medium",
        description=(
            "The /.bzr/branch/format file is externally accessible and appears "
            "to contain Bazaar repository metadata. This can confirm repository "
            "metadata leakage and aid source-code reconnaissance."
        ),
        recommendation=(
            "Block public access to .bzr directories and remove Bazaar "
            "repository metadata from deployed web roots."
        ),
        paths=("/.bzr/branch/format",),
        body_matchers=(
            BodyMatcher("contains", "Bazaar branch format", case_sensitive=True),
        ),
        standards=_information_disclosure_standards(),
        order=759,
        metadata_recommendation="Block public access to Bazaar metadata.",
    ),
    # ------------------------------------------------------------------
    # Batch-3: CMS admin / install surfaces (STD-GAP-015).
    # ------------------------------------------------------------------
    SafePathRule(
        rule_id="external.joomla_admin_panel_exposed",
        title="Joomla administrator panel exposed",
        severity="low",
        description=(
            "The /administrator/ endpoint is externally reachable and returns "
            "the Joomla administrator login surface. Public access to the "
            "administrative surface increases enumeration and brute-force exposure."
        ),
        recommendation=(
            "Restrict the Joomla /administrator/ path to trusted networks or "
            "place it behind an identity proxy."
        ),
        paths=("/administrator/",),
        body_matchers=(
            BodyMatcher("regex", r"(?i)joomla(?:[^a-z]|!|\s|<)"),
        ),
        standards=_admin_surface_standards(),
        order=760,
        metadata_recommendation="Restrict access to /administrator/.",
    ),
    SafePathRule(
        rule_id="external.drupal_user_login_exposed",
        title="Drupal user-login page exposed",
        severity="low",
        description=(
            "The /user/login endpoint returns a Drupal-branded login form and "
            "is externally reachable. Public access to authentication surfaces "
            "increases enumeration and brute-force exposure."
        ),
        recommendation=(
            "Restrict /user/login (and the Drupal admin surface generally) to "
            "trusted networks or place it behind an identity proxy."
        ),
        paths=("/user/login",),
        body_matchers=(
            BodyMatcher("regex", r"(?i)(?:drupal\.settings|name=\"form_id\"\s+value=\"user_login)"),
        ),
        standards=_admin_surface_standards(),
        order=761,
        metadata_recommendation="Restrict access to /user/login.",
    ),
    SafePathRule(
        rule_id="external.drupal_install_php_exposed",
        title="Drupal install.php exposed",
        severity="high",
        description=(
            "A Drupal install.php endpoint is externally reachable and returns "
            "the installer welcome page. Public access to the installer can "
            "allow unauthenticated site takeover during a re-install window."
        ),
        recommendation=(
            "Remove install.php from production deployments or block external "
            "access to it once the site is installed."
        ),
        paths=("/core/install.php", "/install.php"),
        body_matchers=(
            BodyMatcher("regex", r"(?i)drupal\s+\d+(?:\.\d+)?\s*installation"),
        ),
        standards=_admin_surface_standards(),
        order=762,
        metadata_recommendation="Remove or block external access to install.php.",
    ),
    SafePathRule(
        rule_id="external.magento_admin_panel_exposed",
        title="Magento admin panel exposed",
        severity="low",
        description=(
            "The /admin/ endpoint returns a Magento administrator login page "
            "and is externally reachable. Public access to the administrative "
            "surface increases enumeration and brute-force exposure."
        ),
        recommendation=(
            "Rename the Magento admin path (or block /admin/) and restrict it "
            "to trusted networks or an identity proxy."
        ),
        paths=("/admin/",),
        body_matchers=(
            BodyMatcher("regex", r"(?i)(?:magento[\s_-]+admin|var\s+BASE_URL\s*=)"),
        ),
        standards=_admin_surface_standards(),
        order=763,
        metadata_recommendation="Restrict access to the Magento admin path.",
    ),
    SafePathRule(
        rule_id="external.ghost_admin_exposed",
        title="Ghost admin panel exposed",
        severity="low",
        description=(
            "The /ghost/ endpoint returns the Ghost CMS administrator surface "
            "and is externally reachable. Public access to the administrative "
            "surface increases enumeration and brute-force exposure."
        ),
        recommendation=(
            "Restrict /ghost/ to trusted networks or place it behind an "
            "identity proxy."
        ),
        paths=("/ghost/",),
        body_matchers=(
            BodyMatcher("regex", r"(?i)(?:ghost[-_]admin|<title>[^<]*ghost[^<]*</title>)"),
        ),
        standards=_admin_surface_standards(),
        order=764,
        metadata_recommendation="Restrict access to /ghost/.",
    ),
    # ------------------------------------------------------------------
    # Batch-3: Database admin panels.
    # ------------------------------------------------------------------
    SafePathRule(
        rule_id="external.pgadmin_panel_exposed",
        title="pgAdmin panel exposed",
        severity="high",
        description=(
            "The /pgadmin4/ endpoint returns a pgAdmin PostgreSQL administration "
            "surface and is externally reachable. Public exposure of a database "
            "administration panel increases the risk of credential brute-force "
            "and direct database compromise."
        ),
        recommendation=(
            "Restrict pgAdmin to trusted administrators or remove it from "
            "production deployments."
        ),
        paths=("/pgadmin4/", "/pgadmin4/login"),
        body_matchers=(
            BodyMatcher("regex", r"(?i)pgadmin\s*(?:4|<)"),
        ),
        standards=_admin_surface_standards(),
        order=765,
        metadata_recommendation="Restrict access to pgAdmin.",
    ),
    SafePathRule(
        rule_id="external.phppgadmin_exposed",
        title="phpPgAdmin panel exposed",
        severity="high",
        description=(
            "The /phppgadmin/ endpoint returns a phpPgAdmin PostgreSQL "
            "administration surface and is externally reachable. Public exposure "
            "of a database administration panel increases the risk of credential "
            "brute-force and direct database compromise."
        ),
        recommendation=(
            "Restrict phpPgAdmin to trusted administrators or remove it from "
            "production deployments."
        ),
        paths=("/phppgadmin/",),
        body_matchers=(
            BodyMatcher("regex", r"(?i)phppgadmin"),
        ),
        standards=_admin_surface_standards(),
        order=766,
        metadata_recommendation="Restrict access to phpPgAdmin.",
    ),
    SafePathRule(
        rule_id="external.mongo_express_exposed",
        title="Mongo Express panel exposed",
        severity="high",
        description=(
            "The /mongo-express endpoint returns a Mongo Express MongoDB "
            "administration surface and is externally reachable. Mongo Express "
            "frequently ships without authentication; public exposure can grant "
            "unauthenticated database access."
        ),
        recommendation=(
            "Enable authentication on Mongo Express, restrict it to trusted "
            "administrators, or remove it from production deployments."
        ),
        paths=("/mongo-express", "/mongo-express/"),
        body_matchers=(
            BodyMatcher("regex", r"(?i)mongo[\s-]?express"),
        ),
        standards=_admin_surface_standards(),
        order=767,
        metadata_recommendation="Restrict access to Mongo Express.",
    ),
    SafePathRule(
        rule_id="external.elasticsearch_head_exposed",
        title="Elasticsearch head plugin exposed",
        severity="high",
        description=(
            "The /_plugin/head/ endpoint returns the Elasticsearch head cluster "
            "administration UI. Public exposure typically indicates that the "
            "Elasticsearch cluster itself is reachable without authentication, "
            "which can grant unauthenticated read/write access to indices."
        ),
        recommendation=(
            "Disable the head plugin in production, place Elasticsearch behind "
            "authentication, and restrict cluster access to trusted networks."
        ),
        paths=("/_plugin/head/",),
        body_matchers=(
            BodyMatcher("regex", r"(?i)(?:elasticsearch[\s-]+head|cluster_overview)"),
        ),
        standards=_admin_surface_standards(),
        order=768,
        metadata_recommendation="Disable or restrict access to the Elasticsearch head plugin.",
    ),
    # ------------------------------------------------------------------
    # Batch-3: Webmail surfaces.
    # ------------------------------------------------------------------
    SafePathRule(
        rule_id="external.roundcube_webmail_exposed",
        title="Roundcube webmail login exposed",
        severity="low",
        description=(
            "The /roundcube/ endpoint returns a Roundcube webmail login form "
            "and is externally reachable. Public exposure of a webmail login "
            "surface increases enumeration and brute-force exposure."
        ),
        recommendation=(
            "Restrict the Roundcube login surface to trusted networks or "
            "place it behind an identity proxy."
        ),
        paths=("/roundcube/", "/webmail/"),
        body_matchers=(
            BodyMatcher("regex", r"(?i)roundcube"),
        ),
        standards=_admin_surface_standards(),
        order=769,
        metadata_recommendation="Restrict access to the Roundcube login.",
    ),
    SafePathRule(
        rule_id="external.squirrelmail_exposed",
        title="SquirrelMail login exposed",
        severity="low",
        description=(
            "The /squirrelmail/ endpoint returns a SquirrelMail webmail login "
            "form. SquirrelMail is no longer actively maintained; public "
            "exposure carries both enumeration and unpatched-vulnerability risk."
        ),
        recommendation=(
            "Migrate off SquirrelMail and restrict the login surface to "
            "trusted networks in the interim."
        ),
        paths=("/squirrelmail/",),
        body_matchers=(
            BodyMatcher("regex", r"(?i)squirrelmail"),
        ),
        standards=_admin_surface_standards(),
        order=770,
        metadata_recommendation="Restrict or remove the SquirrelMail surface.",
    ),
    SafePathRule(
        rule_id="external.horde_webmail_exposed",
        title="Horde webmail login exposed",
        severity="low",
        description=(
            "The /horde/ endpoint returns a Horde webmail / groupware login "
            "form and is externally reachable. Public exposure of the login "
            "surface increases enumeration and brute-force exposure."
        ),
        recommendation=(
            "Restrict the Horde login surface to trusted networks or place it "
            "behind an identity proxy."
        ),
        paths=("/horde/",),
        body_matchers=(
            BodyMatcher("regex", r"(?i)horde(?:[\s_-]+application|[\s_-]+webmail|[\s_-]+groupware|</title>)"),
        ),
        standards=_admin_surface_standards(),
        order=771,
        metadata_recommendation="Restrict access to the Horde login.",
    ),
    # ------------------------------------------------------------------
    # Batch-3: Monitoring / metrics dashboards.
    # ------------------------------------------------------------------
    SafePathRule(
        rule_id="external.grafana_dashboard_exposed",
        title="Grafana dashboard exposed",
        severity="low",
        description=(
            "The /login endpoint returns the Grafana login surface and is "
            "externally reachable. Public exposure of the login surface "
            "increases enumeration and brute-force exposure; Grafana "
            "deployments with anonymous access enabled additionally leak "
            "dashboards directly."
        ),
        recommendation=(
            "Restrict Grafana to trusted networks, disable anonymous access, "
            "and place the login surface behind an identity proxy."
        ),
        paths=("/login",),
        body_matchers=(
            BodyMatcher("regex", r"(?i)(?:grafanaBootData|<title>[^<]*grafana[^<]*</title>)"),
        ),
        standards=_admin_surface_standards(),
        order=772,
        metadata_recommendation="Restrict access to the Grafana login.",
    ),
    SafePathRule(
        rule_id="external.prometheus_metrics_exposed",
        title="Prometheus metrics endpoint exposed",
        severity="medium",
        description=(
            "The /metrics endpoint is externally reachable and returns a "
            "Prometheus exposition-format scrape body. Public metrics expose "
            "internal counters, hostnames, build versions, and request paths "
            "that aid reconnaissance."
        ),
        recommendation=(
            "Restrict /metrics to trusted scrape sources (e.g. internal "
            "Prometheus servers) using network controls or an authenticating "
            "reverse proxy."
        ),
        paths=("/metrics",),
        body_matchers=(
            BodyMatcher("regex", r"(?m)^#\s+(?:HELP|TYPE)\s+\w+"),
        ),
        standards=_information_disclosure_standards(),
        order=773,
        metadata_recommendation="Restrict /metrics to trusted scrape sources.",
    ),
    SafePathRule(
        rule_id="external.kibana_dashboard_exposed",
        title="Kibana dashboard exposed",
        severity="low",
        description=(
            "The /api/status endpoint returns a Kibana status JSON document "
            "and is externally reachable. Public exposure of the Kibana surface "
            "leaks version information and increases the attack surface against "
            "an unauthenticated or weakly authenticated Elasticsearch cluster."
        ),
        recommendation=(
            "Restrict Kibana to trusted networks and require authentication, "
            "for example via Elastic Stack security or a reverse proxy."
        ),
        paths=("/api/status",),
        body_matchers=(
            # Require both the Kibana product name AND a Kibana-status
            # neighbour field (version / build_number / status). A bare
            # ``"build_number"`` JSON field alone is too generic — many
            # CI/build-info endpoints expose it.
            BodyMatcher(
                "regex",
                r"(?is)\"name\"\s*:\s*\"kibana\".*\"(?:version|build_number|status)\"\s*:",
            ),
        ),
        standards=_information_disclosure_standards(),
        order=774,
        metadata_recommendation="Restrict access to the Kibana status endpoint.",
    ),
    SafePathRule(
        rule_id="external.zabbix_dashboard_exposed",
        title="Zabbix login exposed",
        severity="low",
        description=(
            "The /zabbix/ endpoint returns a Zabbix monitoring frontend login "
            "form and is externally reachable. Public exposure of the login "
            "surface increases enumeration and brute-force exposure."
        ),
        recommendation=(
            "Restrict the Zabbix frontend to trusted networks or place it "
            "behind an identity proxy."
        ),
        paths=("/zabbix/", "/zabbix/index.php"),
        body_matchers=(
            BodyMatcher("regex", r"(?i)(?:zabbix\s*sia|<title>[^<]*zabbix[^<]*</title>)"),
        ),
        standards=_admin_surface_standards(),
        order=775,
        metadata_recommendation="Restrict access to the Zabbix frontend.",
    ),
    # ------------------------------------------------------------------
    # Batch-3: CI/CD and source-review dashboards.
    # ------------------------------------------------------------------
    SafePathRule(
        rule_id="external.sonarqube_dashboard_exposed",
        title="SonarQube dashboard exposed",
        severity="medium",
        description=(
            "The /sonarqube/ (or /sonar/) endpoint returns a SonarQube code-quality "
            "dashboard and is externally reachable. Public exposure can leak "
            "internal project structure, code-quality metrics, and (when anonymous "
            "browse is enabled) source-code snippets."
        ),
        recommendation=(
            "Restrict SonarQube to trusted networks, disable anonymous browse, "
            "and require authentication for all read access."
        ),
        paths=("/sonar/", "/sonarqube/"),
        body_matchers=(
            BodyMatcher("regex", r"(?i)(?:sonarqube|data-sonar-version)"),
        ),
        standards=_information_disclosure_standards(),
        order=776,
        metadata_recommendation="Restrict access to SonarQube.",
    ),
    SafePathRule(
        rule_id="external.jenkins_dashboard_exposed",
        title="Jenkins dashboard exposed",
        severity="medium",
        description=(
            "The /jenkins/ endpoint returns the Jenkins CI dashboard and is "
            "externally reachable. Public exposure (especially with anonymous "
            "read enabled) can leak build configurations, job names, "
            "environment variables, and source-code paths."
        ),
        recommendation=(
            "Restrict Jenkins to trusted networks, disable anonymous read, "
            "and require authentication for all access."
        ),
        paths=("/jenkins/", "/jenkins/login"),
        body_matchers=(
            BodyMatcher("regex", r"(?i)(?:<title>[^<]*jenkins[^<]*</title>|x-jenkins)"),
        ),
        standards=_information_disclosure_standards(),
        order=777,
        metadata_recommendation="Restrict access to Jenkins.",
    ),
    SafePathRule(
        rule_id="external.teamcity_login_exposed",
        title="TeamCity login exposed",
        severity="medium",
        description=(
            "The /login.html endpoint returns a TeamCity CI login surface and "
            "is externally reachable. Public exposure of the login surface "
            "increases enumeration and brute-force exposure against build "
            "infrastructure."
        ),
        recommendation=(
            "Restrict TeamCity to trusted networks or place its login surface "
            "behind an identity proxy."
        ),
        paths=("/login.html",),
        body_matchers=(
            BodyMatcher("regex", r"(?i)(?:teamcity|data-teamcity-version)"),
        ),
        standards=_admin_surface_standards(),
        order=778,
        metadata_recommendation="Restrict access to TeamCity.",
    ),
    SafePathRule(
        rule_id="external.gitlab_self_hosted_signin_exposed",
        title="Self-hosted GitLab sign-in exposed",
        severity="low",
        description=(
            "The /users/sign_in endpoint returns a self-hosted GitLab sign-in "
            "form and is externally reachable. Self-hosted GitLab instances "
            "host internal source code; public exposure of the sign-in surface "
            "increases enumeration and brute-force exposure against developer "
            "credentials."
        ),
        recommendation=(
            "Restrict the GitLab sign-in surface to trusted networks or "
            "place it behind an identity proxy with SSO."
        ),
        paths=("/users/sign_in",),
        body_matchers=(
            BodyMatcher("regex", r"(?i)(?:gitlab|<meta\s+content=\"GitLab)"),
        ),
        standards=_admin_surface_standards(),
        order=779,
        metadata_recommendation="Restrict access to the GitLab sign-in surface.",
    ),
    SafePathRule(
        rule_id="external.jupyter_notebook_exposed",
        title="Jupyter Notebook tree exposed",
        severity="high",
        description=(
            "The /tree endpoint returns a Jupyter Notebook file tree and is "
            "externally reachable. A reachable Jupyter tree without authentication "
            "typically allows opening notebooks and executing arbitrary code "
            "on the server."
        ),
        recommendation=(
            "Require authentication for Jupyter (set a token / password), "
            "restrict the surface to trusted networks, and never expose the "
            "/tree endpoint anonymously."
        ),
        paths=("/tree",),
        body_matchers=(
            BodyMatcher("regex", r"(?i)(?:jupyter|<title>[^<]*home page[^<]*</title>)"),
        ),
        standards=_admin_surface_standards(),
        order=780,
        metadata_recommendation="Require authentication on Jupyter and restrict /tree.",
    ),
    # ------------------------------------------------------------------
    # Batch-3: Orchestration / service-discovery UIs.
    # ------------------------------------------------------------------
    SafePathRule(
        rule_id="external.consul_ui_exposed",
        title="Consul agent self-info exposed",
        severity="high",
        description=(
            "The /v1/agent/self endpoint returns Consul agent configuration "
            "JSON and is externally reachable. Public exposure typically "
            "indicates that the Consul HTTP API is reachable without ACLs, "
            "which can leak service catalog data and configuration."
        ),
        recommendation=(
            "Enable Consul ACLs, restrict the HTTP API to trusted networks, "
            "and require authentication for all /v1/ endpoints."
        ),
        paths=("/v1/agent/self",),
        body_matchers=(
            BodyMatcher("regex", r"(?i)\"Config\"\s*:\s*\{[^}]*\"Server\""),
        ),
        standards=_information_disclosure_standards(),
        order=781,
        metadata_recommendation="Enable ACLs and restrict the Consul HTTP API.",
    ),
    SafePathRule(
        rule_id="external.vault_ui_exposed",
        title="Vault sys/health endpoint exposed",
        severity="high",
        description=(
            "The /v1/sys/health endpoint returns HashiCorp Vault status JSON "
            "and is externally reachable. Public exposure of the Vault API "
            "indicates the secret-store control plane is reachable from the "
            "internet, which dramatically increases the attack surface against "
            "the credentials it protects."
        ),
        recommendation=(
            "Restrict Vault to trusted networks, place its API behind a "
            "mutual-TLS gateway, and never expose the HTTP API publicly."
        ),
        paths=("/v1/sys/health",),
        body_matchers=(
            BodyMatcher("regex", r"(?i)\"(?:initialized|sealed|version)\"\s*:"),
        ),
        standards=_information_disclosure_standards(),
        order=782,
        metadata_recommendation="Restrict Vault to trusted networks.",
    ),
    SafePathRule(
        rule_id="external.nomad_ui_exposed",
        title="Nomad agent health endpoint exposed",
        severity="high",
        description=(
            "The /v1/agent/health endpoint returns HashiCorp Nomad agent "
            "status JSON and is externally reachable. Public exposure typically "
            "indicates the Nomad HTTP API is reachable without ACLs, which can "
            "allow workload introspection and (when write ACLs are disabled) "
            "job submission."
        ),
        recommendation=(
            "Enable Nomad ACLs, restrict the HTTP API to trusted networks, "
            "and require authentication for all /v1/ endpoints."
        ),
        paths=("/v1/agent/health",),
        body_matchers=(
            BodyMatcher("regex", r"(?i)\"(?:server|client)\"\s*:\s*\{\s*\"ok\""),
        ),
        standards=_information_disclosure_standards(),
        order=783,
        metadata_recommendation="Enable ACLs and restrict the Nomad HTTP API.",
    ),
    SafePathRule(
        rule_id="external.etcd_v2_keys_exposed",
        title="etcd v2 keys API exposed",
        severity="high",
        description=(
            "The /v2/keys/ endpoint returns the etcd v2 key-value listing JSON "
            "and is externally reachable. Public exposure of the etcd API "
            "without authentication grants unauthenticated read access (and "
            "frequently write access) to the cluster's coordination state."
        ),
        recommendation=(
            "Enable client-cert authentication on etcd, restrict the API to "
            "trusted networks, and migrate from the v2 API to v3 where "
            "supported."
        ),
        paths=("/v2/keys/",),
        body_matchers=(
            BodyMatcher("regex", r"\"action\"\s*:\s*\"get\""),
        ),
        standards=_information_disclosure_standards(),
        order=784,
        metadata_recommendation="Enable etcd authentication and restrict the API.",
    ),
    # ------------------------------------------------------------------
    # Batch-3: Spring Actuator complements + dataops UIs.
    # ------------------------------------------------------------------
    SafePathRule(
        rule_id="external.spring_actuator_info_exposed",
        title="Spring Boot actuator /info exposed",
        severity="low",
        description=(
            "The /actuator/info endpoint is externally reachable and returns a "
            "Spring Boot actuator info JSON document. The endpoint typically "
            "leaks build metadata (Git commit, version, project name) that aid "
            "reconnaissance."
        ),
        recommendation=(
            "Restrict /actuator/* endpoints to trusted scrape sources or "
            "require authentication via the actuator security configuration."
        ),
        paths=("/actuator/info",),
        body_matchers=(
            # Require an actuator-info-shaped top-level key. ``content_type_matchers``
            # is intentionally NOT added here: the runner OR-combines body and
            # content-type matchers, so adding ``application/json`` would fire
            # the rule on every JSON 200 response on /actuator/info, defeating
            # the body-matcher precision.
            BodyMatcher(
                "regex",
                r"(?is)\"(?:build|git|app|java|os)\"\s*:\s*\{",
            ),
        ),
        standards=_information_disclosure_standards(),
        order=785,
        metadata_recommendation="Restrict access to Spring actuator endpoints.",
    ),
    SafePathRule(
        rule_id="external.spring_actuator_metrics_exposed",
        title="Spring Boot actuator /metrics exposed",
        severity="medium",
        description=(
            "The /actuator/metrics endpoint is externally reachable and returns "
            "the Spring Boot actuator metrics inventory. Public access enables "
            "detailed reconnaissance against the application and its database / "
            "HTTP-client behaviour."
        ),
        recommendation=(
            "Restrict /actuator/* endpoints to trusted scrape sources or "
            "require authentication via the actuator security configuration."
        ),
        paths=("/actuator/metrics",),
        body_matchers=(
            BodyMatcher("regex", r"\"names\"\s*:\s*\["),
        ),
        standards=_information_disclosure_standards(),
        order=786,
        metadata_recommendation="Restrict access to Spring actuator endpoints.",
    ),
    SafePathRule(
        rule_id="external.airflow_home_exposed",
        title="Apache Airflow home page exposed",
        severity="high",
        description=(
            "The /home endpoint returns an Apache Airflow web UI and is "
            "externally reachable. Public exposure of the Airflow UI without "
            "authentication can allow viewing or triggering DAGs, which often "
            "translates to arbitrary code execution on workers."
        ),
        recommendation=(
            "Enable Airflow's authentication backend, restrict the UI to "
            "trusted networks, and never expose /home anonymously."
        ),
        paths=("/home",),
        body_matchers=(
            BodyMatcher("regex", r"(?i)(?:airflow|<title>[^<]*airflow[^<]*</title>)"),
        ),
        standards=_admin_surface_standards(),
        order=787,
        metadata_recommendation="Require authentication on the Airflow UI.",
    ),
    SafePathRule(
        rule_id="external.kubernetes_dashboard_exposed",
        title="Kubernetes Dashboard exposed",
        severity="high",
        description=(
            "The root endpoint returns the Kubernetes Dashboard UI and is "
            "externally reachable. Public exposure of the Dashboard, especially "
            "with cluster-admin bindings, can grant cluster-wide control without "
            "authentication."
        ),
        recommendation=(
            "Restrict the Kubernetes Dashboard to trusted networks, require "
            "token authentication, and never expose it to the public internet."
        ),
        paths=("/",),
        body_matchers=(
            BodyMatcher("regex", r"(?i)(?:kubernetes[\s-]+dashboard|<title>[^<]*kubernetes\s+dashboard[^<]*</title>)"),
        ),
        standards=_admin_surface_standards(),
        order=788,
        metadata_recommendation="Restrict access to the Kubernetes Dashboard.",
    ),
    SafePathRule(
        rule_id="external.rancher_dashboard_exposed",
        title="Rancher API root exposed",
        severity="high",
        description=(
            "The /v3 endpoint returns the Rancher management API root JSON and "
            "is externally reachable. Public exposure of the Rancher management "
            "plane increases the risk of cluster takeover, especially when "
            "authentication is misconfigured or token-less default credentials "
            "remain."
        ),
        recommendation=(
            "Restrict the Rancher management plane to trusted networks and "
            "require strong authentication for all /v3 access."
        ),
        paths=("/v3",),
        body_matchers=(
            # Require both the Rancher collection envelope AND a
            # Rancher-specific neighbour field. ``"type":"collection"``
            # alone is also used by some other resource-style APIs.
            BodyMatcher(
                "regex",
                r"(?is)\"type\"\s*:\s*\"collection\".*\"(?:resourceType|links|schemas)\"\s*:",
            ),
        ),
        standards=_information_disclosure_standards(),
        order=789,
        metadata_recommendation="Restrict access to the Rancher management API.",
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
