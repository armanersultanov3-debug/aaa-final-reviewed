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
            "/db.sql",
            "/dump.sql",
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
