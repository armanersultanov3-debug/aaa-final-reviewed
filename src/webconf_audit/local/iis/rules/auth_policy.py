from __future__ import annotations

from webconf_audit.local.iis.effective import IISEffectiveConfig, IISEffectiveSection
from webconf_audit.local.iis.parser import IISChildElement, IISConfigDocument, IISSection
from webconf_audit.local.iis.rules.rule_utils import (
    effective_location,
    is_pure_inheritance,
    location_applies_to_scope,
    location_context,
    location_inheritance_chain,
    normalize_location_path,
    raw_location,
    ssl_flag_tokens,
)
from webconf_audit.models import Finding
from webconf_audit.rule_registry import StandardReference, rule

AUTHORIZATION_RULE_ID = "iis.authorization_allows_anonymous_users"
AUTHORIZATION_POLICY_MISSING_RULE_ID = "iis.authorization_policy_missing"
BASIC_SSL_RULE_ID = "iis.basic_auth_without_ssl"
ANONYMOUS_USER_IDENTITY_RULE_ID = "iis.anonymous_auth_uses_specific_user"


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
    rule_id=AUTHORIZATION_POLICY_MISSING_RULE_ID,
    title="IIS URL authorization policy is not explicit",
    severity="low",
    description="IIS URL authorization does not define explicit allow or deny rules.",
    recommendation="Add explicit URL authorization allow/deny rules for protected applications.",
    category="local",
    server_type="iis",
    input_kind="effective",
    order=543,
)
def find_authorization_policy_missing(
    doc: IISConfigDocument, *, effective_config: IISEffectiveConfig | None = None,
) -> list[Finding]:
    if effective_config is not None:
        return _effective_authorization_policy_missing_findings(doc, effective_config)
    return _raw_authorization_policy_missing_findings(doc)


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


@rule(
    rule_id=ANONYMOUS_USER_IDENTITY_RULE_ID,
    title="Anonymous authentication uses a specific user",
    severity="medium",
    description=(
        "IIS anonymous authentication is configured with a specific user "
        "instead of the application pool identity."
    ),
    recommendation=(
        'Set anonymousAuthentication userName="" and clear the password so '
        "anonymous requests run as the application pool identity."
    ),
    category="local",
    server_type="iis",
    input_kind="effective",
    standards=(
        StandardReference(
            standard="CIS",
            reference="Microsoft IIS 10 v1.2.1 section 1.6",
            url="https://www.cisecurity.org/benchmark/microsoft_iis",
            coverage="partial",
            note=(
                "Detects explicit non-empty anonymousAuthentication "
                "userName values, and password values only when userName is "
                "not explicitly blank; inherited platform defaults without "
                "source evidence remain unknown."
            ),
        ),
    ),
    order=540,
)
def find_anonymous_auth_uses_specific_user(
    doc: IISConfigDocument, *, effective_config: IISEffectiveConfig | None = None,
) -> list[Finding]:
    if effective_config is not None:
        return _effective_anonymous_user_identity_findings(effective_config)
    return _raw_anonymous_user_identity_findings(doc)


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


def _effective_authorization_policy_missing_findings(
    doc: IISConfigDocument,
    effective_config: IISEffectiveConfig,
) -> list[Finding]:
    findings: list[Finding] = []
    empty_section_keys: set[tuple[str | None, str | None, str | None]] = set()
    raw_sections_by_location = _url_authorization_sections_by_location(doc.sections)
    for scope in _effective_system_webserver_scopes(effective_config):
        authorization = _nearest_effective_iis_url_authorization_section(
            effective_config,
            scope.location_path,
        )
        if authorization is not None and _has_explicit_authorization_rules(
            authorization.children,
        ):
            continue
        raw_sections = _nearest_authorization_sections(
            raw_sections_by_location,
            scope.location_path,
        )
        if raw_sections:
            if _raw_authorization_chain_has_explicit_rules(
                raw_sections_by_location,
                scope.location_path,
            ):
                continue
            if authorization is not None:
                findings.append(
                    _effective_authorization_policy_empty_finding(
                        authorization,
                        affected_location_path=scope.location_path,
                    ),
                )
                continue
            findings.extend(
                _raw_authorization_policy_empty_finding(section)
                for section in raw_sections
                if not _has_explicit_authorization_rules(section.children)
                if _remember_raw_section(empty_section_keys, section)
            )
            continue

        if authorization is None:
            findings.append(_effective_authorization_policy_absent_finding(scope))
            continue
        findings.append(
            _effective_authorization_policy_empty_finding(
                authorization,
                affected_location_path=scope.location_path,
            ),
        )
    return findings


def _raw_authorization_policy_missing_findings(
    doc: IISConfigDocument,
) -> list[Finding]:
    findings: list[Finding] = []
    empty_section_keys: set[tuple[str | None, str | None, str | None]] = set()
    sections_by_location = _url_authorization_sections_by_location(doc.sections)
    for scope in _raw_system_webserver_scopes(doc):
        sections = _nearest_authorization_sections(
            sections_by_location,
            scope.location_path,
        )
        if not sections:
            findings.append(_raw_authorization_policy_absent_finding(scope))
            continue
        if _raw_authorization_chain_has_explicit_rules(
            sections_by_location,
            scope.location_path,
        ):
            continue
        findings.extend(
            _raw_authorization_policy_empty_finding(section)
            for section in sections
            if not _has_explicit_authorization_rules(section.children)
            if _remember_raw_section(empty_section_keys, section)
        )
    return findings


def _effective_system_webserver_scopes(
    effective_config: IISEffectiveConfig,
) -> list[IISEffectiveSection]:
    return [
        section
        for section in effective_config.all_sections
        if section.section_path_suffix == "/system.webServer"
        and not is_pure_inheritance(section)
    ]


def _raw_system_webserver_scopes(doc: IISConfigDocument) -> list[IISSection]:
    return [
        section
        for section in doc.sections
        if section.tag == "system.webServer"
    ]


def _nearest_effective_iis_url_authorization_section(
    effective_config: IISEffectiveConfig,
    scope_location: str | None,
) -> IISEffectiveSection | None:
    for location in location_inheritance_chain(scope_location):
        for section in reversed(effective_config.all_sections):
            if section.section_path_suffix != "/authorization":
                continue
            if not location_applies_to_scope(section.location_path, location):
                continue
            if _effective_section_has_iis_url_authorization_origin(section):
                return section
    return None


def _effective_section_has_iis_url_authorization_origin(
    section: IISEffectiveSection,
) -> bool:
    return any(
        _is_iis_url_authorization_path(origin.xml_path)
        for origin in section.origin_chain
    )


def _url_authorization_sections_by_location(
    sections: list[IISSection],
) -> dict[str | None, list[IISSection]]:
    by_location: dict[str | None, list[IISSection]] = {}
    for section in sections:
        if section.tag != "authorization":
            continue
        if not _is_iis_url_authorization_path(section.xml_path):
            continue
        by_location.setdefault(normalize_location_path(section.location_path), []).append(
            section,
        )
    return by_location


def _nearest_authorization_sections(
    sections_by_location: dict[str | None, list[IISSection]],
    scope_location: str | None,
) -> list[IISSection]:
    for location in location_inheritance_chain(scope_location):
        sections = sections_by_location.get(location)
        if sections:
            return sections
    return []


def _raw_authorization_chain_has_explicit_rules(
    sections_by_location: dict[str | None, list[IISSection]],
    scope_location: str | None,
) -> bool:
    children: list[IISChildElement] = []
    for location in reversed(location_inheritance_chain(scope_location)):
        for section in sections_by_location.get(location, []):
            children = _merge_authorization_children(children, section.children)
    return _has_explicit_authorization_rules(children)


def _merge_authorization_children(
    base: list[IISChildElement],
    incoming: list[IISChildElement],
) -> list[IISChildElement]:
    result = list(base)
    for child in incoming:
        tag = child.tag.lower()
        if tag == "clear":
            result.clear()
            continue
        if tag == "remove":
            result = [
                candidate
                for candidate in result
                if not _authorization_remove_matches(candidate, child)
            ]
            continue
        result.append(child)
    return result


def _authorization_remove_matches(
    candidate: IISChildElement,
    remove_child: IISChildElement,
) -> bool:
    if candidate.tag.lower() != "add" or not remove_child.attributes:
        return False
    return all(
        candidate.attributes.get(name) == value
        for name, value in remove_child.attributes.items()
    )


def _remember_raw_section(
    seen: set[tuple[str | None, str | None, str | None]],
    section: IISSection,
) -> bool:
    key = (section.source.file_path, section.source.xml_path, section.location_path)
    if key in seen:
        return False
    seen.add(key)
    return True


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


def _has_explicit_authorization_rules(children: list[IISChildElement]) -> bool:
    return any(
        child.tag.lower() == "add"
        and child.attributes.get("accessType", "").strip().lower() in {"allow", "deny"}
        for child in children
    )


def _is_iis_url_authorization_path(xml_path: str | None) -> bool:
    return (xml_path or "").lower().endswith(
        "/system.webserver/security/authorization",
    )


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


def _effective_authorization_policy_absent_finding(
    section: IISEffectiveSection,
) -> Finding:
    ctx = location_context(section)
    return Finding(
        rule_id=AUTHORIZATION_POLICY_MISSING_RULE_ID,
        title="IIS URL authorization policy is not explicit",
        severity="low",
        description=(
            f"The configuration contains system.webServer settings but no IIS URL "
            f"authorization policy{ctx}. IIS defaults can allow broad access "
            "unless authorization is constrained at a higher configuration level."
        ),
        recommendation="Add an explicit system.webServer/security/authorization policy for protected applications, or document that this application is intentionally public.",
        location=effective_location(section),
    )


def _raw_authorization_policy_absent_finding(section: IISSection) -> Finding:
    return Finding(
        rule_id=AUTHORIZATION_POLICY_MISSING_RULE_ID,
        title="IIS URL authorization policy is not explicit",
        severity="low",
        description=(
            "The configuration contains system.webServer settings but no IIS URL "
            "authorization policy. IIS defaults can allow broad access unless "
            "authorization is constrained at a higher configuration level."
        ),
        recommendation="Add an explicit system.webServer/security/authorization policy for protected applications, or document that this application is intentionally public.",
        location=raw_location(section),
    )


def _effective_authorization_policy_empty_finding(
    section: IISEffectiveSection,
    *,
    affected_location_path: str | None = None,
) -> Finding:
    ctx = _location_path_context(affected_location_path or section.location_path)
    return Finding(
        rule_id=AUTHORIZATION_POLICY_MISSING_RULE_ID,
        title="IIS URL authorization policy is not explicit",
        severity="low",
        description=(
            f"IIS URL authorization defines no effective allow or deny rules{ctx}. "
            "An empty policy can fall back to permissive defaults or parent "
            "configuration that is not visible in this file."
        ),
        recommendation="Add explicit URL authorization allow/deny rules for protected applications.",
        location=effective_location(section),
    )


def _location_path_context(location_path: str | None) -> str:
    location_path = normalize_location_path(location_path)
    if location_path:
        return f' (at location path "{location_path}")'
    return ""


def _raw_authorization_policy_empty_finding(section: IISSection) -> Finding:
    return Finding(
        rule_id=AUTHORIZATION_POLICY_MISSING_RULE_ID,
        title="IIS URL authorization policy is not explicit",
        severity="low",
        description=(
            "IIS URL authorization defines no effective allow or deny rules. "
            "An empty policy can fall back to permissive defaults or parent "
            "configuration that is not visible in this file."
        ),
        recommendation="Add explicit URL authorization allow/deny rules for protected applications.",
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


def _effective_anonymous_user_identity_findings(
    effective_config: IISEffectiveConfig,
) -> list[Finding]:
    findings: list[Finding] = []
    for section in effective_config.all_sections:
        if section.section_path_suffix != "/anonymousAuthentication":
            continue
        if is_pure_inheritance(section):
            continue
        account = _specific_anonymous_user(section.attributes)
        if account is None:
            continue
        findings.append(_effective_anonymous_user_identity_finding(section, account))
    return findings


def _raw_anonymous_user_identity_findings(doc: IISConfigDocument) -> list[Finding]:
    findings: list[Finding] = []
    for group in _sections_by_location(doc.sections).values():
        section = _raw_section(group, "anonymousAuthentication")
        if section is None:
            continue
        account = _specific_anonymous_user(section.attributes)
        if account is None:
            continue
        findings.append(_raw_anonymous_user_identity_finding(section, account))
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


def _specific_anonymous_user(attributes: dict[str, str]) -> str | None:
    if attributes.get("enabled", "").strip().lower() == "false":
        return None

    user_name = attributes.get("userName")
    if user_name is not None and user_name.strip():
        return user_name.strip()
    if user_name is not None:
        return None

    password = attributes.get("password")
    if password is not None and password.strip():
        return "<password set with blank userName>"

    return None


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


def _effective_anonymous_user_identity_finding(
    section: IISEffectiveSection,
    account: str,
) -> Finding:
    ctx = location_context(section)
    return Finding(
        rule_id=ANONYMOUS_USER_IDENTITY_RULE_ID,
        title="Anonymous authentication uses a specific user",
        severity="medium",
        description=(
            f'IIS anonymous authentication uses "{account}" as the anonymous '
            f"user identity{ctx}. Anonymous requests should use the "
            "application pool identity so site isolation follows the "
            "application pool boundary."
        ),
        recommendation=(
            'Set anonymousAuthentication userName="" and clear the password '
            "for this scope, or document why a specific anonymous account is required."
        ),
        location=effective_location(section),
        metadata={"anonymous_user": account},
    )


def _raw_anonymous_user_identity_finding(
    section: IISSection,
    account: str,
) -> Finding:
    return Finding(
        rule_id=ANONYMOUS_USER_IDENTITY_RULE_ID,
        title="Anonymous authentication uses a specific user",
        severity="medium",
        description=(
            f'IIS anonymous authentication uses "{account}" as the anonymous '
            "user identity. Anonymous requests should use the application "
            "pool identity so site isolation follows the application pool boundary."
        ),
        recommendation=(
            'Set anonymousAuthentication userName="" and clear the password '
            "for this scope, or document why a specific anonymous account is required."
        ),
        location=raw_location(section),
        metadata={"anonymous_user": account},
    )
