from __future__ import annotations

import re

from webconf_audit.local.apache.parser import (
    ApacheBlockNode,
    ApacheConfigAst,
    ApacheDirectiveNode,
)
from webconf_audit.local.apache.rules._policy_semantics_utils import (
    explicit_module_inventory,
    iter_enabled_scoped_directives,
    module_explicitly_loaded,
)
from webconf_audit.local.apache.rules.server_directive_utils import default_location
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "apache.request_read_timeout_semantics"
TITLE = "RequestReadTimeout module semantics are incomplete"
DESCRIPTION = (
    "Apache enables mod_reqtimeout or RequestReadTimeout syntax without a "
    "complete, explicit header/body policy."
)
RECOMMENDATION = (
    "Load mod_reqtimeout explicitly and configure RequestReadTimeout with "
    "both header and body sections, using positive timeout windows and minrate "
    "values."
)
_REQUIRED_SECTIONS = frozenset({"header", "body"})


@rule(
    rule_id=RULE_ID,
    title=TITLE,
    severity="low",
    description=DESCRIPTION,
    recommendation=RECOMMENDATION,
    category="local",
    server_type="apache",
    order=374,
)
def find_request_read_timeout_semantics(config_ast: ApacheConfigAst) -> list[Finding]:
    modules = explicit_module_inventory(config_ast)
    reqtimeout_loaded = module_explicitly_loaded(modules, "reqtimeout_module")
    findings: list[Finding] = []

    directive = _effective_request_read_timeout_directive(config_ast.nodes, modules)
    if directive is None:
        if reqtimeout_loaded:
            findings.append(
                Finding(
                    rule_id=RULE_ID,
                    title=TITLE,
                    severity="low",
                    description=(
                        "Apache loads mod_reqtimeout but does not define "
                        "RequestReadTimeout."
                    ),
                    recommendation=RECOMMENDATION,
                    location=default_location(config_ast),
                )
            )
        return findings

    if not reqtimeout_loaded:
        findings.append(
            Finding(
                rule_id=RULE_ID,
                title=TITLE,
                severity="low",
                description=(
                    "Apache defines RequestReadTimeout without loading "
                    "mod_reqtimeout, so the policy is ineffective."
                ),
                recommendation=RECOMMENDATION,
                location=_directive_location(directive),
            )
        )
        return findings

    sections = _parse_request_read_timeout_sections(directive.args)
    missing_sections = sorted(_REQUIRED_SECTIONS - set(sections))
    invalid_sections = [
        section
        for section, raw_value in sections.items()
        if not _request_timeout_value_is_valid(raw_value)
    ]
    if missing_sections or invalid_sections:
        details: list[str] = []
        if missing_sections:
            details.append("missing sections: " + ", ".join(missing_sections))
        if invalid_sections:
            details.append("invalid sections: " + ", ".join(sorted(invalid_sections)))
        joined_args = " ".join(directive.args)

        findings.append(
            Finding(
                rule_id=RULE_ID,
                title=TITLE,
                severity="low",
                description=(
                    "Apache sets effective RequestReadTimeout to "
                    f"'{joined_args}' ({'; '.join(details)})."
                ),
                recommendation=RECOMMENDATION,
                location=_directive_location(directive),
            )
        )

    return findings


def _effective_request_read_timeout_directive(
    nodes: list[ApacheDirectiveNode | ApacheBlockNode],
    modules: frozenset[str],
) -> ApacheDirectiveNode | None:
    directive: ApacheDirectiveNode | None = None
    for candidate in iter_enabled_scoped_directives(nodes, modules):
        if candidate.name.lower() == "requestreadtimeout":
            directive = candidate
    return directive


def _parse_request_read_timeout_sections(args: list[str]) -> dict[str, str]:
    rendered = " ".join(args)
    sections: dict[str, str] = {}
    for match in re.finditer(
        r"\b(header|body)\s*=\s*([^=]+?)(?=\s+\b(?:header|body)\s*=|$)",
        rendered,
        flags=re.IGNORECASE,
    ):
        sections[match.group(1).lower()] = match.group(2).strip().rstrip(",")
    return sections


def _request_timeout_value_is_valid(raw_value: str) -> bool:
    value = raw_value.strip().rstrip(",")
    if not value:
        return False

    window = value.split(",", 1)[0].strip()
    if "-" in window:
        start, end = window.split("-", 1)
        if not (start.isdigit() and end.isdigit()):
            return False
        return int(start) > 0 and int(end) >= int(start)

    return window.isdigit() and int(window) > 0


def _directive_location(directive: ApacheDirectiveNode) -> SourceLocation:
    return SourceLocation(
        mode="local",
        kind="file",
        file_path=directive.source.file_path,
        line=directive.source.line,
    )


__all__ = ["find_request_read_timeout_semantics"]
