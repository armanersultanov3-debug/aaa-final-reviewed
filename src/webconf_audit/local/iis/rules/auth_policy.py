from __future__ import annotations

from webconf_audit.local.iis.effective import IISEffectiveConfig, IISEffectiveSection
from webconf_audit.local.iis.parser import IISChildElement, IISConfigDocument, IISSection
from webconf_audit.local.iis.rules.rule_utils import (
    effective_location,
    is_pure_inheritance,
    location_context,
    raw_location,
    ssl_flag_tokens,
)
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

AUTHORIZATION_RULE_ID = "iis.authorization_allows_anonymous_users"
BASIC_SSL_RULE_ID = "iis.basic_auth_without_ssl"


@rule(
    rule_id=AUTHORIZATION_RULE_ID,
    title="Authorization allows anonymous users",
    severity="medium",
    description="Authorization rules explicitly allow anonymous or all users.",
    recommendation="Deny anonymous users or restrict allow rules to the intended authenticated users and roles.",
    category="local",
    server_type="iis",
    input_kind="effective",
    order=520,
)
def find_authorization_allows_anonymous_users(
    doc: IISConfigDocument, *, effective_config: IISEffectiveConfig | None = None,
) -> list[Finding]:
    if effective_config is not None:
        return _effective_authorization_findings(effective_config)
    return _raw_authorization_findings(doc)


@rule(
    rule_id=BASIC_SSL_RULE_ID,
    title="Basic authentication enabled without required SSL",
    severity="medium",
    description="Basic authentication is enabled without an SSL requirement.",
    recommendation='Require SSL for Basic authentication by setting access sslFlags to include "Ssl".',
    category="local",
    server_type="iis",
    tags=("tls",),
    input_kind="effective",
    order=521,
)
def find_basic_auth_without_ssl(
    doc: IISConfigDocument, *, effective_config: IISEffectiveConfig | None = None,
) -> list[Finding]:
    if effective_config is not None:
        return _effective_basic_ssl_findings(effective_config)
    return _raw_basic_ssl_findings(doc)


def _effective_authorization_findings(
    effective_config: IISEffectiveConfig,
) -> list[Finding]:
    findings: list[Finding] = []
    for section in effective_config.all_sections:
        if section.section_path_suffix != "/authorization":
            continue
        if is_pure_inheritance(section):
            continue
        users = _anonymous_allow_users(section.children)
        if users:
            findings.append(_effective_authorization_finding(section, users))
    return findings


def _raw_authorization_findings(doc: IISConfigDocument) -> list[Finding]:
    findings: list[Finding] = []
    for section in doc.sections:
        if section.tag != "authorization":
            continue
        users = _anonymous_allow_users(section.children)
        if users:
            findings.append(_raw_authorization_finding(section, users))
    return findings


def _anonymous_allow_users(children: list[IISChildElement]) -> list[str]:
    users: list[str] = []
    anonymous_denied = False
    for child in children:
        if child.tag.lower() != "add":
            continue
        access_type = child.attributes.get("accessType", "").lower()
        raw_users = child.attributes.get("users", "")
        if access_type == "deny" and _contains_anonymous_token(raw_users):
            anonymous_denied = True
            continue
        if access_type != "allow":
            continue
        if _allows_anonymous_user(raw_users, anonymous_denied=anonymous_denied):
            users.append(raw_users)
    return users


def _allows_anonymous_user(value: str, *, anonymous_denied: bool) -> bool:
    tokens = _user_tokens(value)
    if anonymous_denied:
        return False
    return "?" in tokens or "*" in tokens


def _contains_anonymous_token(value: str) -> bool:
    tokens = _user_tokens(value)
    return "?" in tokens or "*" in tokens


def _user_tokens(value: str) -> set[str]:
    return {
        token.strip()
        for token in value.replace(";", ",").replace(" ", ",").split(",")
        if token.strip()
    }


def _effective_authorization_finding(
    section: IISEffectiveSection,
    users: list[str],
) -> Finding:
    ctx = location_context(section)
    user_values = ", ".join(users)
    return Finding(
        rule_id=AUTHORIZATION_RULE_ID,
        title="Authorization allows anonymous users",
        severity="medium",
        description=(
            f"IIS authorization explicitly allows anonymous or all users{ctx} "
            f"(users: {user_values}). This can grant public access to content "
            "that should require authenticated authorization."
        ),
        recommendation="Replace wildcard or anonymous allow rules with explicit authenticated users or roles, or add a deny rule for anonymous users.",
        location=effective_location(section),
    )


def _raw_authorization_finding(section: IISSection, users: list[str]) -> Finding:
    user_values = ", ".join(users)
    return Finding(
        rule_id=AUTHORIZATION_RULE_ID,
        title="Authorization allows anonymous users",
        severity="medium",
        description=(
            "IIS authorization explicitly allows anonymous or all users "
            f"(users: {user_values}). This can grant public access to content "
            "that should require authenticated authorization."
        ),
        recommendation="Replace wildcard or anonymous allow rules with explicit authenticated users or roles, or add a deny rule for anonymous users.",
        location=raw_location(section),
    )


def _effective_basic_ssl_findings(
    effective_config: IISEffectiveConfig,
) -> list[Finding]:
    findings: list[Finding] = []
    for section in effective_config.all_sections:
        if section.section_path_suffix != "/basicAuthentication":
            continue
        if section.attributes.get("enabled", "").lower() != "true":
            continue
        access = effective_config.get_effective_section(
            "/access",
            location_path=section.location_path,
        )
        if _is_pure_inherited_basic_with_no_local_access(section, access):
            continue
        if _requires_ssl(access):
            continue
        findings.append(_effective_basic_ssl_finding(section))
    return findings


def _raw_basic_ssl_findings(doc: IISConfigDocument) -> list[Finding]:
    findings: list[Finding] = []
    for group in _sections_by_location(doc.sections).values():
        finding = _raw_basic_ssl_group_finding(group)
        if finding is not None:
            findings.append(finding)
    return findings


def _sections_by_location(
    sections: list[IISSection],
) -> dict[str | None, list[IISSection]]:
    by_location: dict[str | None, list[IISSection]] = {}
    for section in sections:
        by_location.setdefault(section.location_path, []).append(section)
    return by_location


def _raw_basic_ssl_group_finding(group: list[IISSection]) -> Finding | None:
    basic = _raw_section(group, "basicAuthentication")
    if basic is None or basic.attributes.get("enabled", "").lower() != "true":
        return None
    access = _raw_section(group, "access")
    if _requires_ssl(access):
        return None
    return Finding(
        rule_id=BASIC_SSL_RULE_ID,
        title="Basic authentication enabled without required SSL",
        severity="medium",
        description=(
            "IIS Basic authentication is enabled, but SSL is not required. "
            "Basic authentication transmits reusable credentials in a form "
            "that depends on TLS for confidentiality."
        ),
        recommendation='Set access sslFlags to include "Ssl" whenever Basic authentication is enabled.',
        location=raw_location(basic),
    )


def _raw_section(sections: list[IISSection], tag_name: str) -> IISSection | None:
    for section in sections:
        if section.tag == tag_name:
            return section
    return None


def _requires_ssl(section: IISEffectiveSection | IISSection | None) -> bool:
    if section is None:
        return False
    return "ssl" in ssl_flag_tokens(section.attributes.get("sslFlags"))


def _is_pure_inherited_basic_with_no_local_access(
    section: IISEffectiveSection,
    access: IISEffectiveSection | None,
) -> bool:
    if not is_pure_inheritance(section):
        return False
    return access is None or is_pure_inheritance(access)


def _effective_basic_ssl_finding(section: IISEffectiveSection) -> Finding:
    ctx = location_context(section)
    return Finding(
        rule_id=BASIC_SSL_RULE_ID,
        title="Basic authentication enabled without required SSL",
        severity="medium",
        description=(
            f"IIS Basic authentication is enabled without required SSL{ctx}. "
            "Basic authentication transmits reusable credentials in a form "
            "that depends on TLS for confidentiality."
        ),
        recommendation='Set access sslFlags to include "Ssl" whenever Basic authentication is enabled.',
        location=effective_location(section),
    )
