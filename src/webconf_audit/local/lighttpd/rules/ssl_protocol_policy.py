from __future__ import annotations

import re

from webconf_audit.finding_factory import finding_from_rule
from webconf_audit.local.lighttpd.conditions import LighttpdRequestContext
from webconf_audit.local.lighttpd.effective import (
    LighttpdConditionalScope,
    LighttpdEffectiveConfig,
    LighttpdEffectiveDirective,
    build_effective_config,
)
from webconf_audit.local.lighttpd.parser import LighttpdConfigAst
from webconf_audit.local.lighttpd.rules.rule_utils import (
    effective_directive_for_scope,
    normalize_value,
    unquote,
)
from webconf_audit.local.lighttpd.rules.ssl_conf_cmd_utils import (
    ssl_conf_cmd_entries,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule
from webconf_audit.standards import asvs_5, cwe, owasp_top10_2021, rfc

RULE_ID = "lighttpd.ssl_protocol_policy_missing_or_weak"
LEGACY_RULE_ID = "lighttpd.tls_legacy_versions_explicitly_enabled"

_SSL_CONF_CMD = "ssl.openssl.ssl-conf-cmd"
_LEGACY_PROTOCOL_FLAGS = {
    "ssl.use-sslv2": "SSLv2",
    "ssl.use-sslv3": "SSLv3",
}
_POLICY_DIRECTIVES = frozenset({_SSL_CONF_CMD, *_LEGACY_PROTOCOL_FLAGS})
_WEAK_PROTOCOLS = frozenset({"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"})
_DEFAULT_ALL_WEAK = _WEAK_PROTOCOLS
_PROTOCOL_RANK = {
    "SSLv2": 0,
    "SSLv3": 1,
    "TLSv1": 2,
    "TLSv1.1": 3,
    "TLSv1.2": 4,
    "TLSv1.3": 5,
}
_TOKEN_SPLIT_RE = re.compile(r"[\s,:]+")


@rule(
    rule_id=RULE_ID,
    title="Lighttpd TLS protocol policy is missing or weak",
    severity="medium",
    description=(
        "Lighttpd enables TLS without an explicit modern protocol policy, or "
        "enables legacy SSL/TLS protocol versions."
    ),
    recommendation=(
        "Set ssl.openssl.ssl-conf-cmd MinProtocol to TLSv1.2 or TLSv1.3 and "
        "do not enable legacy ssl.use-sslv2/ssl.use-sslv3 flags."
    ),
    category="local",
    server_type="lighttpd",
    input_kind="effective",
    tags=("tls",),
    standards=(
        cwe(327),
        owasp_top10_2021("A02:2021"),
        asvs_5("12.1.1", coverage="partial", note="Missing policy and legacy-version checks."),
    ),
    order=415,
)
def find_ssl_protocol_policy_missing_or_weak(
    config_ast: LighttpdConfigAst,
    *,
    effective_config: LighttpdEffectiveConfig | None = None,
    merged_directives: dict[str, LighttpdEffectiveDirective] | None = None,
    request_context: LighttpdRequestContext | None = None,
) -> list[Finding]:
    if merged_directives is not None and request_context is not None:
        return _find_from_merged(merged_directives)

    if effective_config is not None:
        return _find_from_effective(effective_config)

    return _find_from_effective(build_effective_config(config_ast))


@rule(
    rule_id=LEGACY_RULE_ID,
    title="Lighttpd explicitly enables legacy TLS versions",
    severity="medium",
    description="Lighttpd explicitly enables legacy TLS protocol versions.",
    recommendation=(
        "Set MinProtocol to TLSv1.2 or TLSv1.3 and remove explicit legacy "
        "Protocol tokens or ssl.use-sslv3 flags."
    ),
    category="local",
    server_type="lighttpd",
    input_kind="effective",
    tags=("tls",),
    standards=(
        cwe(327),
        owasp_top10_2021("A02:2021"),
        asvs_5("12.1.1"),
        rfc(
            8996,
            coverage="partial",
            note="Directly covers TLS 1.0 / 1.1 deprecation and also flags adjacent SSLv3 enablement.",
        ),
    ),
    order=415,
)
def find_tls_legacy_versions_explicitly_enabled(
    config_ast: LighttpdConfigAst,
    *,
    effective_config: LighttpdEffectiveConfig | None = None,
    merged_directives: dict[str, LighttpdEffectiveDirective] | None = None,
    request_context: LighttpdRequestContext | None = None,
) -> list[Finding]:
    if merged_directives is not None and request_context is not None:
        return _find_legacy_from_merged(merged_directives)

    if effective_config is not None:
        return _find_legacy_from_effective(effective_config)

    return _find_legacy_from_effective(build_effective_config(config_ast))


def _find_from_merged(
    merged_directives: dict[str, LighttpdEffectiveDirective],
) -> list[Finding]:
    ssl_engine = merged_directives.get("ssl.engine")
    if not _is_enabled(ssl_engine):
        return []
    return _evaluate_directives(merged_directives, ssl_engine, label="merged")


def _find_from_effective(
    effective_config: LighttpdEffectiveConfig,
) -> list[Finding]:
    findings: list[Finding] = []

    global_ssl_engine = effective_config.get_global("ssl.engine")
    if _is_enabled(global_ssl_engine):
        findings.extend(
            _evaluate_directives(
                effective_config.global_directives,
                global_ssl_engine,
                label="global",
            )
        )

    for scope in effective_config.conditional_scopes:
        if not _scope_has_tls_protocol_interest(scope):
            continue

        ssl_engine = effective_directive_for_scope(effective_config, scope, "ssl.engine")
        if not _is_enabled(ssl_engine):
            continue

        findings.extend(
            _evaluate_directives(
                _effective_scope_directives(effective_config, scope),
                ssl_engine,
                label=scope.header or "conditional",
            )
        )

    return findings


def _find_legacy_from_merged(
    merged_directives: dict[str, LighttpdEffectiveDirective],
) -> list[Finding]:
    ssl_engine = merged_directives.get("ssl.engine")
    if not _is_enabled(ssl_engine):
        return []
    return _evaluate_legacy_directives(merged_directives, ssl_engine, label="merged")


def _find_legacy_from_effective(
    effective_config: LighttpdEffectiveConfig,
) -> list[Finding]:
    findings: list[Finding] = []

    global_ssl_engine = effective_config.get_global("ssl.engine")
    if _is_enabled(global_ssl_engine):
        findings.extend(
            _evaluate_legacy_directives(
                effective_config.global_directives,
                global_ssl_engine,
                label="global",
            )
        )

    for scope in effective_config.conditional_scopes:
        if not _scope_has_tls_protocol_interest(scope):
            continue

        ssl_engine = effective_directive_for_scope(effective_config, scope, "ssl.engine")
        if not _is_enabled(ssl_engine):
            continue

        findings.extend(
            _evaluate_legacy_directives(
                _effective_scope_directives(effective_config, scope),
                ssl_engine,
                label=scope.header or "conditional",
            )
        )

    return findings


def _scope_has_tls_protocol_interest(scope: LighttpdConditionalScope) -> bool:
    if "ssl.engine" in scope.directives:
        return True
    return any(name in scope.directives for name in _POLICY_DIRECTIVES)


def _effective_scope_directives(
    effective_config: LighttpdEffectiveConfig,
    scope: LighttpdConditionalScope,
) -> dict[str, LighttpdEffectiveDirective]:
    names = {"ssl.engine", _SSL_CONF_CMD, *_LEGACY_PROTOCOL_FLAGS}
    return {
        name: directive
        for name in names
        if (directive := effective_directive_for_scope(effective_config, scope, name))
        is not None
    }


def _evaluate_directives(
    directives: dict[str, LighttpdEffectiveDirective],
    ssl_engine: LighttpdEffectiveDirective,
    *,
    label: str,
) -> list[Finding]:
    policy = _protocol_policy(directives)
    if policy.weak_protocols:
        return [
            _make_finding(
                policy.source or ssl_engine,
                description=(
                    f"Lighttpd TLS scope '{label}' enables weak protocols: "
                    + ", ".join(policy.weak_protocols)
                    + "."
                ),
            )
        ]
    if policy.explicit_policy:
        return []
    return [
        _make_finding(
            ssl_engine,
            description=(
                f"Lighttpd TLS scope '{label}' does not define an explicit "
                "ssl.openssl.ssl-conf-cmd protocol policy."
            ),
        )
    ]


def _evaluate_legacy_directives(
    directives: dict[str, LighttpdEffectiveDirective],
    ssl_engine: LighttpdEffectiveDirective,
    *,
    label: str,
) -> list[Finding]:
    policy = _protocol_policy(directives)
    legacy_protocols = [protocol for protocol in policy.weak_protocols if protocol != "SSLv2"]
    if not legacy_protocols:
        return []
    return [
        _make_legacy_finding(
            policy.source or ssl_engine,
            description=(
                f"Lighttpd TLS scope '{label}' explicitly enables legacy protocol "
                f"versions: {', '.join(legacy_protocols)}."
            ),
        )
    ]


class _ProtocolPolicy:
    def __init__(
        self,
        *,
        explicit_policy: bool,
        weak_protocols: list[str],
        source: LighttpdEffectiveDirective | None,
    ) -> None:
        self.explicit_policy = explicit_policy
        self.weak_protocols = weak_protocols
        self.source = source


def _protocol_policy(
    directives: dict[str, LighttpdEffectiveDirective],
) -> _ProtocolPolicy:
    explicit_policy = False
    weak_protocols: set[str] = set()
    finding_source: LighttpdEffectiveDirective | None = None

    ssl_conf_cmd = directives.get(_SSL_CONF_CMD)
    min_protocol_floor: str | None = None
    if ssl_conf_cmd is not None:
        entries = ssl_conf_cmd_entries(unquote(ssl_conf_cmd.value))
        if "minprotocol" in entries:
            min_protocol_floor = _min_protocol_floor(entries["minprotocol"])
            if min_protocol_floor is not None:
                explicit_policy = True
            weak = _weak_min_protocol(min_protocol_floor)
            if weak is not None:
                weak_protocols.add(weak)
                finding_source = ssl_conf_cmd
        if "protocol" in entries:
            protocol_value = entries["protocol"]
            if _protocol_value_is_recognized(protocol_value):
                explicit_policy = True
                protocol_weak = _filter_by_min_protocol_floor(
                    _weak_protocol_tokens(protocol_value),
                    min_protocol_floor,
                )
                if protocol_weak:
                    weak_protocols.update(protocol_weak)
                    finding_source = ssl_conf_cmd

    for directive_name, protocol in _LEGACY_PROTOCOL_FLAGS.items():
        directive = directives.get(directive_name)
        if directive is None or not _is_enabled(directive):
            continue
        if not _allowed_by_min_protocol_floor(protocol, min_protocol_floor):
            continue
        weak_protocols.add(protocol)
        finding_source = directive

    return _ProtocolPolicy(
        explicit_policy=explicit_policy,
        weak_protocols=sorted(weak_protocols),
        source=finding_source,
    )


def _min_protocol_floor(value: str) -> str | None:
    return _normalize_protocol_name(value)


def _weak_min_protocol(protocol: str | None) -> str | None:
    if protocol is None:
        return None
    if _PROTOCOL_RANK[protocol] < _PROTOCOL_RANK["TLSv1.2"]:
        return protocol
    return None


def _filter_by_min_protocol_floor(
    protocols: list[str],
    min_protocol_floor: str | None,
) -> list[str]:
    if min_protocol_floor is None:
        return protocols
    return [
        protocol
        for protocol in protocols
        if _allowed_by_min_protocol_floor(protocol, min_protocol_floor)
    ]


def _allowed_by_min_protocol_floor(
    protocol: str,
    min_protocol_floor: str | None,
) -> bool:
    if min_protocol_floor is None:
        return True
    return _PROTOCOL_RANK[protocol] > _PROTOCOL_RANK[min_protocol_floor]


def _weak_protocol_tokens(value: str) -> list[str]:
    explicit_enabled: set[str] = set()
    disabled: set[str] = set()
    all_mode = False
    has_disabling_token = False
    has_enabling_token = False

    for raw_token in _TOKEN_SPLIT_RE.split(value):
        token = raw_token.strip()
        if not token:
            continue
        action = token[0] if token[0] in "+-" else ""
        name = token[1:] if action else token
        normalized = _normalize_protocol_name(name)

        if name.lower() == "all":
            all_mode = action != "-"
            if action == "-":
                has_disabling_token = True
                explicit_enabled.clear()
                disabled.update(_DEFAULT_ALL_WEAK)
            else:
                has_enabling_token = True
            continue

        if normalized is None or normalized not in _WEAK_PROTOCOLS:
            if action != "-":
                has_enabling_token = True
            continue
        if action == "-":
            has_disabling_token = True
            disabled.add(normalized)
            explicit_enabled.discard(normalized)
        else:
            has_enabling_token = True
            explicit_enabled.add(normalized)
            disabled.discard(normalized)

    weak_protocols = set(explicit_enabled)
    if all_mode or (has_disabling_token and not has_enabling_token):
        weak_protocols.update(_DEFAULT_ALL_WEAK - disabled)
    return sorted(weak_protocols)


def _protocol_value_is_recognized(value: str) -> bool:
    has_token = False
    for raw_token in _TOKEN_SPLIT_RE.split(value):
        token = raw_token.strip()
        if not token:
            continue
        has_token = True
        action = token[0] if token[0] in "+-" else ""
        name = token[1:] if action else token
        if name.lower() == "all":
            continue
        if _normalize_protocol_name(name) is None:
            return False
    return has_token


def _normalize_protocol_name(value: str) -> str | None:
    normalized = value.strip().lower().replace("_", ".")
    aliases = {
        "sslv2": "SSLv2",
        "ssl2": "SSLv2",
        "sslv3": "SSLv3",
        "ssl3": "SSLv3",
        "tlsv1": "TLSv1",
        "tlsv1.0": "TLSv1",
        "tls1": "TLSv1",
        "tls1.0": "TLSv1",
        "tlsv1.1": "TLSv1.1",
        "tls1.1": "TLSv1.1",
        "tlsv1.2": "TLSv1.2",
        "tls1.2": "TLSv1.2",
        "tlsv1.3": "TLSv1.3",
        "tls1.3": "TLSv1.3",
    }
    return aliases.get(normalized)


def _is_enabled(directive: LighttpdEffectiveDirective | None) -> bool:
    return directive is not None and normalize_value(directive.value) in {
        "enable",
        "enabled",
        "on",
        "true",
        "1",
    }


def _source_location(directive: LighttpdEffectiveDirective) -> SourceLocation:
    return SourceLocation(
        mode="local",
        kind="file",
        file_path=directive.source.file_path,
        line=directive.source.line,
    )


def _make_finding(
    directive: LighttpdEffectiveDirective,
    *,
    description: str,
) -> Finding:
    return finding_from_rule(
        find_ssl_protocol_policy_missing_or_weak,
        description=description,
        location=_source_location(directive),
    )


def _make_legacy_finding(
    directive: LighttpdEffectiveDirective,
    *,
    description: str,
) -> Finding:
    return finding_from_rule(
        find_tls_legacy_versions_explicitly_enabled,
        description=description,
        location=_source_location(directive),
    )


__all__ = [
    "find_ssl_protocol_policy_missing_or_weak",
    "find_tls_legacy_versions_explicitly_enabled",
]
