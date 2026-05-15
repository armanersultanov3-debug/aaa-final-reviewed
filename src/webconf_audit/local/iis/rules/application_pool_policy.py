"""Implements rules: ``iis.application_pool_identity_not_application_pool_identity``, ``iis.sites_share_application_pool``.

Location: ``src/webconf_audit/local/iis/rules/application_pool_policy.py``.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from webconf_audit.local.iis.iis_defaults import load_defaults
from webconf_audit.local.iis.effective import IISEffectiveConfig
from webconf_audit.local.iis.parser import (
    IISChildElement,
    IISConfigDocument,
    IISSection,
    IISSourceRef,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import StandardReference, rule

APP_POOL_IDENTITY_RULE_ID = (
    "iis.application_pool_identity_not_application_pool_identity"
)
SHARED_APP_POOL_RULE_ID = "iis.sites_share_application_pool"

_APPLICATION_POOL_IDENTITY_VALUES = frozenset({"applicationpoolidentity", "4"})
_DEFAULT_APP_POOL = "DefaultAppPool"
_SITE_XML_PATH = "configuration/system.applicationHost/sites/site"
_APPLICATION_POOLS_XML_PATH = "configuration/system.applicationHost/applicationPools"
_DEFAULT_PROCESS_MODEL_PATH = (
    "system.applicationHost/applicationPools/applicationPoolDefaults/processModel"
)

_IDENTITY_LABELS = {
    "0": "LocalSystem",
    "1": "LocalService",
    "2": "NetworkService",
    "3": "SpecificUser",
    "4": "ApplicationPoolIdentity",
}


@dataclass(frozen=True, slots=True)
class _DefaultProcessModel:
    identity_type: str
    source: IISSourceRef


@dataclass(frozen=True, slots=True)
class _PoolIdentity:
    pool_name: str
    identity_type: str
    source: IISSourceRef
    inherited_from_defaults: bool


@dataclass(frozen=True, slots=True)
class _SiteApplication:
    site_name: str
    app_path: str
    application_pool: str
    source: IISSourceRef


@rule(
    rule_id=APP_POOL_IDENTITY_RULE_ID,
    title="Application pool does not use ApplicationPoolIdentity",
    severity="medium",
    description="An IIS application pool runs under a non-ApplicationPoolIdentity account.",
    recommendation=(
        "Set each application pool processModel identityType to "
        "ApplicationPoolIdentity unless a documented service account is "
        "strictly required."
    ),
    category="local",
    server_type="iis",
    input_kind="ast",
    standards=(
        StandardReference(
            standard="CIS",
            reference="Microsoft IIS 10 v1.2.1 section 1.4",
            url="https://www.cisecurity.org/benchmark/microsoft_iis",
            coverage="partial",
            note=(
                "Detects explicit app-pool processModel identities and "
                "applicationPoolDefaults identities that are not "
                "ApplicationPoolIdentity; absent applicationPoolDefaults "
                "inherit the embedded IIS schema default."
            ),
        ),
    ),
    order=538,
)
def find_application_pool_identity_not_application_pool_identity(
    doc: IISConfigDocument, *, effective_config: IISEffectiveConfig | None = None,
) -> list[Finding]:
    del effective_config
    default_process_model = _application_pool_default_process_model(doc)
    findings: list[Finding] = []

    for pool_identity in _application_pool_identities(doc, default_process_model):
        if _is_application_pool_identity(pool_identity.identity_type):
            continue
        findings.append(_pool_identity_finding(pool_identity))

    return findings


@rule(
    rule_id=SHARED_APP_POOL_RULE_ID,
    title="Application pool is shared across sites",
    severity="medium",
    description="Multiple IIS sites or applications use the same application pool.",
    recommendation=(
        "Assign separate application pools to separate sites so each site runs "
        "with its own worker-process identity and isolation boundary."
    ),
    category="local",
    server_type="iis",
    input_kind="ast",
    standards=(
        StandardReference(
            standard="CIS",
            reference="Microsoft IIS 10 v1.2.1 section 1.5",
            url="https://www.cisecurity.org/benchmark/microsoft_iis",
            coverage="partial",
            note=(
                "Detects application pools assigned to applications under "
                "more than one site; intentional shared-hosting exceptions "
                "remain operator-specific."
            ),
        ),
    ),
    order=539,
)
def find_sites_share_application_pool(
    doc: IISConfigDocument, *, effective_config: IISEffectiveConfig | None = None,
) -> list[Finding]:
    del effective_config
    findings: list[Finding] = []
    applications_by_pool: dict[str, list[_SiteApplication]] = {}

    for application in _site_applications(doc):
        pool_key = application.application_pool.strip().casefold()
        applications_by_pool.setdefault(pool_key, []).append(application)

    for applications in applications_by_pool.values():
        site_names = _unique_names(app.site_name for app in applications)
        if len(site_names) <= 1:
            continue
        findings.append(_shared_app_pool_finding(applications, site_names))

    return findings


def _application_pool_default_process_model(
    doc: IISConfigDocument,
) -> _DefaultProcessModel | None:
    default_process_model: _DefaultProcessModel | None = None
    fallback_source: IISSourceRef | None = None
    for section in doc.sections:
        if section.xml_path == _APPLICATION_POOLS_XML_PATH:
            fallback_source = section.source
        if section.tag != "processModel":
            continue
        if not section.xml_path.endswith("/applicationPoolDefaults/processModel"):
            continue
        identity_type = section.attributes.get("identityType")
        if identity_type is not None:
            default_process_model = _DefaultProcessModel(
                identity_type=identity_type,
                source=section.source,
            )
            continue

        schema_identity = load_defaults().get_element_default(
            _DEFAULT_PROCESS_MODEL_PATH,
        ).get("identityType")
        if schema_identity is None:
            continue
        default_process_model = _DefaultProcessModel(
            identity_type=schema_identity,
            source=section.source,
        )
    if default_process_model is not None:
        return default_process_model

    schema_identity = load_defaults().get_element_default(
        _DEFAULT_PROCESS_MODEL_PATH,
    ).get("identityType")
    if schema_identity is None:
        return None
    return _DefaultProcessModel(
        identity_type=schema_identity,
        source=fallback_source
        or IISSourceRef(
            file_path=doc.file_path,
            xml_path="configuration/system.applicationHost/applicationPools",
        ),
    )


def _application_pool_identities(
    doc: IISConfigDocument,
    default_process_model: _DefaultProcessModel | None,
) -> list[_PoolIdentity]:
    pool_identities: list[_PoolIdentity] = []
    for section in doc.sections:
        if section.tag != "applicationPools":
            continue
        for child in section.children:
            if child.tag.lower() != "add":
                continue
            pool_identity = _application_pool_identity(child, default_process_model)
            if pool_identity is not None:
                pool_identities.append(pool_identity)
    return pool_identities


def _application_pool_identity(
    pool: IISChildElement,
    default_process_model: _DefaultProcessModel | None,
) -> _PoolIdentity | None:
    pool_name = pool.attributes.get("name", "<unnamed application pool>")
    process_model = _first_child(pool, "processModel")
    if process_model is not None and "identityType" in process_model.attributes:
        return _PoolIdentity(
            pool_name=pool_name,
            identity_type=process_model.attributes.get("identityType", ""),
            source=process_model.source,
            inherited_from_defaults=False,
        )
    if default_process_model is None:
        return None
    return _PoolIdentity(
        pool_name=pool_name,
        identity_type=default_process_model.identity_type,
        source=default_process_model.source,
        inherited_from_defaults=True,
    )


def _first_child(parent: IISChildElement, tag_name: str) -> IISChildElement | None:
    tag_lower = tag_name.lower()
    for child in parent.children:
        if child.tag.lower() == tag_lower:
            return child
    return None


def _is_application_pool_identity(identity_type: str) -> bool:
    return _identity_key(identity_type) in _APPLICATION_POOL_IDENTITY_VALUES


def _identity_key(identity_type: str) -> str:
    return identity_type.strip().lower()


def _identity_label(identity_type: str) -> str:
    stripped = identity_type.strip()
    if not stripped:
        return "<empty>"
    return _IDENTITY_LABELS.get(stripped, stripped)


def _pool_identity_finding(pool_identity: _PoolIdentity) -> Finding:
    identity_label = _identity_label(pool_identity.identity_type)
    inherited = (
        " through applicationPoolDefaults"
        if pool_identity.inherited_from_defaults
        else ""
    )
    return Finding(
        rule_id=APP_POOL_IDENTITY_RULE_ID,
        title="Application pool does not use ApplicationPoolIdentity",
        severity="medium",
        description=(
            f'IIS application pool "{pool_identity.pool_name}" runs as '
            f"{identity_label}{inherited}, not ApplicationPoolIdentity. "
            "This weakens site isolation and may grant the worker process "
            "broader local or network privileges than needed."
        ),
        recommendation=(
            f'Set processModel identityType="ApplicationPoolIdentity" for '
            f'application pool "{pool_identity.pool_name}", or document the '
            "exception if a dedicated service account is required."
        ),
        location=_source_location(pool_identity.source),
        metadata={
            "application_pool": pool_identity.pool_name,
            "identity_type": pool_identity.identity_type,
            "inherited_from_defaults": pool_identity.inherited_from_defaults,
        },
    )


def _site_applications(doc: IISConfigDocument) -> list[_SiteApplication]:
    applications: list[_SiteApplication] = []
    current_site: IISSection | None = None

    for section in doc.sections:
        if section.tag == "site" and section.xml_path == _SITE_XML_PATH:
            current_site = section
            continue

        if current_site is None:
            continue

        if not section.xml_path.startswith(_SITE_XML_PATH + "/"):
            current_site = None
            continue

        if section.tag != "application":
            continue

        applications.append(
            _SiteApplication(
                site_name=current_site.attributes.get("name", "<unnamed site>"),
                app_path=section.attributes.get("path", "/"),
                application_pool=section.attributes.get(
                    "applicationPool",
                    _DEFAULT_APP_POOL,
                ),
                source=section.source,
            )
        )

    return applications


def _unique_names(values: Iterable[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value)
        key = text.casefold()
        if key in seen:
            continue
        seen.add(key)
        result.append(text)
    return result


def _shared_app_pool_finding(
    applications: list[_SiteApplication],
    site_names: list[str],
) -> Finding:
    pool_name = applications[0].application_pool
    site_list = ", ".join(site_names)
    app_list = ", ".join(
        f'{app.site_name}:{app.app_path or "/"}' for app in applications
    )
    return Finding(
        rule_id=SHARED_APP_POOL_RULE_ID,
        title="Application pool is shared across sites",
        severity="medium",
        description=(
            f'IIS application pool "{pool_name}" is assigned to multiple '
            f"sites ({site_list}). Shared pools reduce isolation because "
            "those sites can execute under the same worker-process identity."
        ),
        recommendation=(
            f'Create distinct application pools instead of sharing "{pool_name}" '
            "across sites, then assign each site/application to its own pool."
        ),
        location=_source_location(applications[0].source),
        metadata={
            "application_pool": pool_name,
            "sites": site_names,
            "applications": app_list,
        },
    )


def _source_location(source: IISSourceRef) -> SourceLocation:
    return SourceLocation(
        mode="local",
        kind="xml",
        file_path=source.file_path,
        xml_path=source.xml_path,
    )
