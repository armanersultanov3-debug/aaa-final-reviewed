"""lighttpd.ssl_compression_enabled -- Lighttpd TLS compression is enabled."""

from __future__ import annotations

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
    ssl_conf_cmd_option_state,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "lighttpd.ssl_compression_enabled"

_SSL_CONF_CMD = "ssl.openssl.ssl-conf-cmd"


@rule(
    rule_id=RULE_ID,
    title="Lighttpd TLS compression is enabled",
    severity="medium",
    description=(
        "Lighttpd explicitly enables OpenSSL TLS compression through "
        "ssl.openssl.ssl-conf-cmd."
    ),
    recommendation=(
        "Remove the Compression option or set "
        'ssl.openssl.ssl-conf-cmd Options to "-Compression".'
    ),
    category="local",
    server_type="lighttpd",
    input_kind="effective",
    tags=("tls",),
    order=419,
)
def find_ssl_compression_enabled(
    config_ast: LighttpdConfigAst,
    *,
    effective_config: LighttpdEffectiveConfig | None = None,
    merged_directives: dict[str, LighttpdEffectiveDirective] | None = None,
    request_context: LighttpdRequestContext | None = None,
) -> list[Finding]:
    if merged_directives is not None and request_context is not None:
        return _find_from_merged(merged_directives)

    if effective_config is None:
        effective_config = build_effective_config(config_ast)
    return _find_from_effective(effective_config)


def _find_from_merged(
    merged_directives: dict[str, LighttpdEffectiveDirective],
) -> list[Finding]:
    ssl_engine = merged_directives.get("ssl.engine")
    if not _is_enabled(ssl_engine):
        return []
    return _evaluate(merged_directives, label="merged")


def _find_from_effective(
    effective_config: LighttpdEffectiveConfig,
) -> list[Finding]:
    findings: list[Finding] = []

    global_ssl_engine = effective_config.get_global("ssl.engine")
    if _is_enabled(global_ssl_engine):
        findings.extend(_evaluate(effective_config.global_directives, label="global"))

    for scope in effective_config.conditional_scopes:
        if not _scope_has_interest(scope):
            continue
        ssl_engine = effective_directive_for_scope(effective_config, scope, "ssl.engine")
        if not _is_enabled(ssl_engine):
            continue
        findings.extend(
            _evaluate(
                _effective_scope_directives(effective_config, scope),
                label=scope.header or "conditional",
            )
        )

    return findings


def _scope_has_interest(scope: LighttpdConditionalScope) -> bool:
    return "ssl.engine" in scope.directives or _SSL_CONF_CMD in scope.directives


def _effective_scope_directives(
    effective_config: LighttpdEffectiveConfig,
    scope: LighttpdConditionalScope,
) -> dict[str, LighttpdEffectiveDirective]:
    return {
        name: directive
        for name in ("ssl.engine", _SSL_CONF_CMD)
        if (directive := effective_directive_for_scope(effective_config, scope, name))
        is not None
    }


def _evaluate(
    directives: dict[str, LighttpdEffectiveDirective],
    *,
    label: str,
) -> list[Finding]:
    directive = directives.get(_SSL_CONF_CMD)
    if directive is None:
        return []
    option_state = ssl_conf_cmd_option_state(unquote(directive.value), "Compression")
    if option_state is not True:
        return []
    return [
        _make_finding(
            directive,
            description=(
                f"Lighttpd TLS scope '{label}' explicitly enables OpenSSL "
                "TLS compression."
            ),
        )
    ]


def _is_enabled(directive: LighttpdEffectiveDirective | None) -> bool:
    return directive is not None and normalize_value(directive.value) in {
        "enable",
        "enabled",
        "on",
        "true",
        "1",
    }


def _make_finding(
    directive: LighttpdEffectiveDirective,
    *,
    description: str,
) -> Finding:
    return finding_from_rule(
        find_ssl_compression_enabled,
        description=description,
        location=SourceLocation(
            mode="local",
            kind="file",
            file_path=directive.source.file_path,
            line=directive.source.line,
        ),
    )


__all__ = ["find_ssl_compression_enabled"]
