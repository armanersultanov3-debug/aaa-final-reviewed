from __future__ import annotations

from webconf_audit.local.iis.effective import IISEffectiveConfig
from webconf_audit.local.iis.parser import IISConfigDocument
from webconf_audit.local.iis.registry import IISRegistryTLS
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

TLS12_RULE_ID = "iis.schannel_tls12_not_enabled"
AES128_RULE_ID = "iis.schannel_aes128_enabled"
AES256_RULE_ID = "iis.schannel_aes256_not_enabled"
CIPHER_ORDER_RULE_ID = "iis.schannel_cipher_suite_order_not_preferred"

_AES128_CIPHER = "aes 128/128"
_AES256_CIPHER = "aes 256/256"

_CIS_CIPHER_SUITE_PREFIX = (
    "TLS_AES_256_GCM_SHA384",
    "TLS_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
)


@rule(
    rule_id=TLS12_RULE_ID,
    title="IIS SChannel TLS 1.2 is not enabled",
    severity="medium",
    description="Windows SChannel registry data does not show TLS 1.2 enabled for IIS.",
    recommendation="Enable TLS 1.2 for the SChannel Server protocol.",
    category="local",
    server_type="iis",
    tags=("tls",),
    input_kind="mixed",
    order=534,
)
def find_schannel_tls12_not_enabled(
    doc: IISConfigDocument,
    *,
    effective_config: IISEffectiveConfig | None = None,
    registry_tls: IISRegistryTLS | None = None,
) -> list[Finding]:
    if registry_tls is None or registry_tls.protocols_enabled is None:
        return []
    if "TLSv1.2" in registry_tls.protocols_enabled:
        return []
    protocols = ", ".join(registry_tls.protocols_enabled) or "none"
    return [
        _finding(
            registry_tls,
            rule_id=TLS12_RULE_ID,
            title="IIS SChannel TLS 1.2 is not enabled",
            description=(
                "Windows SChannel registry data does not show TLS 1.2 enabled "
                f"for IIS. Enabled server protocols: {protocols}."
            ),
            recommendation="Set the SChannel TLS 1.2 Server Enabled value to 1 and DisabledByDefault to 0.",
        )
    ]


@rule(
    rule_id=AES128_RULE_ID,
    title="IIS SChannel AES 128/128 cipher is enabled",
    severity="medium",
    description="Windows SChannel registry data shows the AES 128/128 cipher enabled.",
    recommendation="Disable the SChannel AES 128/128 cipher when client compatibility allows.",
    category="local",
    server_type="iis",
    tags=("tls",),
    input_kind="mixed",
    order=535,
)
def find_schannel_aes128_enabled(
    doc: IISConfigDocument,
    *,
    effective_config: IISEffectiveConfig | None = None,
    registry_tls: IISRegistryTLS | None = None,
) -> list[Finding]:
    if registry_tls is None or registry_tls.ciphers_enabled is None:
        return []
    if _AES128_CIPHER not in _normalized_ciphers(registry_tls):
        return []
    return [
        _finding(
            registry_tls,
            rule_id=AES128_RULE_ID,
            title="IIS SChannel AES 128/128 cipher is enabled",
            description=(
                "Windows SChannel registry data shows AES 128/128 enabled, "
                "while the CIS IIS benchmark recommends disabling it."
            ),
            recommendation="Set the SChannel Ciphers\\AES 128/128 Enabled value to 0.",
        )
    ]


@rule(
    rule_id=AES256_RULE_ID,
    title="IIS SChannel AES 256/256 cipher is not enabled",
    severity="medium",
    description="Windows SChannel registry data does not show the AES 256/256 cipher enabled.",
    recommendation="Enable the SChannel AES 256/256 cipher.",
    category="local",
    server_type="iis",
    tags=("tls",),
    input_kind="mixed",
    order=536,
)
def find_schannel_aes256_not_enabled(
    doc: IISConfigDocument,
    *,
    effective_config: IISEffectiveConfig | None = None,
    registry_tls: IISRegistryTLS | None = None,
) -> list[Finding]:
    if registry_tls is None or registry_tls.ciphers_enabled is None:
        return []
    if _AES256_CIPHER in _normalized_ciphers(registry_tls):
        return []
    ciphers = ", ".join(registry_tls.ciphers_enabled) or "none"
    return [
        _finding(
            registry_tls,
            rule_id=AES256_RULE_ID,
            title="IIS SChannel AES 256/256 cipher is not enabled",
            description=(
                "Windows SChannel registry data does not show AES 256/256 enabled. "
                f"Enabled SChannel ciphers: {ciphers}."
            ),
            recommendation="Set the SChannel Ciphers\\AES 256/256 Enabled value to 1.",
        )
    ]


@rule(
    rule_id=CIPHER_ORDER_RULE_ID,
    title="IIS SChannel cipher suite order is not CIS preferred",
    severity="medium",
    description="Windows SChannel cipher suite order does not start with the CIS IIS preferred order.",
    recommendation="Configure the SSL cipher suite Functions policy with the CIS IIS preferred order.",
    category="local",
    server_type="iis",
    tags=("tls",),
    input_kind="mixed",
    order=537,
)
def find_schannel_cipher_suite_order_not_preferred(
    doc: IISConfigDocument,
    *,
    effective_config: IISEffectiveConfig | None = None,
    registry_tls: IISRegistryTLS | None = None,
) -> list[Finding]:
    if registry_tls is None or registry_tls.cipher_suite_order is None:
        return []
    if _cipher_suite_order_has_cis_prefix(registry_tls.cipher_suite_order):
        return []
    first_suite = registry_tls.cipher_suite_order[0] if registry_tls.cipher_suite_order else "none"
    return [
        _finding(
            registry_tls,
            rule_id=CIPHER_ORDER_RULE_ID,
            title="IIS SChannel cipher suite order is not CIS preferred",
            description=(
                "Windows SChannel cipher suite order does not start with the "
                f"CIS IIS preferred order. First configured suite: {first_suite}."
            ),
            recommendation=(
                "Set HKLM\\SOFTWARE\\Policies\\Microsoft\\Cryptography\\Configuration\\SSL\\00010002:"
                "Functions to the CIS IIS preferred TLS cipher suite order."
            ),
        )
    ]


def _normalized_ciphers(registry_tls: IISRegistryTLS) -> set[str]:
    return {_normalize_cipher_name(cipher) for cipher in registry_tls.ciphers_enabled or []}


def _normalize_cipher_name(value: str) -> str:
    return " ".join(value.strip().lower().split())


def _cipher_suite_order_has_cis_prefix(cipher_suite_order: list[str]) -> bool:
    normalized = [_normalize_suite_name(suite) for suite in cipher_suite_order]
    required = [_normalize_suite_name(suite) for suite in _CIS_CIPHER_SUITE_PREFIX]
    return normalized[: len(required)] == required


def _normalize_suite_name(value: str) -> str:
    return value.strip().upper()


def _finding(
    registry_tls: IISRegistryTLS,
    *,
    rule_id: str,
    title: str,
    description: str,
    recommendation: str,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        severity="medium",
        description=description,
        recommendation=recommendation,
        location=SourceLocation(
            mode="local",
            kind="tls",
            file_path=registry_tls.source_file_path,
            details=registry_tls.source_details,
        ),
    )


__all__ = [
    "find_schannel_aes128_enabled",
    "find_schannel_aes256_not_enabled",
    "find_schannel_cipher_suite_order_not_preferred",
    "find_schannel_tls12_not_enabled",
]
