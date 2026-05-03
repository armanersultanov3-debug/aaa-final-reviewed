"""Entry point for local IIS rule modules.

Rules are discovered automatically via the global rule registry.
Each rule file in ``rules/iis/`` is decorated with ``@rule(...)``
which registers it at import time.
"""

from __future__ import annotations

from collections.abc import Callable
from functools import lru_cache
from inspect import signature

from webconf_audit.local.iis.effective import IISEffectiveConfig
from webconf_audit.local.iis.parser import IISConfigDocument
from webconf_audit.local.iis.registry import IISRegistryTLS
from webconf_audit.local.rule_runner_utils import run_rule_entry
from webconf_audit.models import AnalysisIssue, Finding
from webconf_audit.rule_registry import registry

_IIS_PKG = "webconf_audit.local.iis.rules"


def run_iis_rules(
    doc: IISConfigDocument,
    *,
    effective_config: IISEffectiveConfig | None = None,
    registry_tls: IISRegistryTLS | None = None,
    issues: list[AnalysisIssue] | None = None,
) -> list[Finding]:
    registry.ensure_loaded(_IIS_PKG)
    findings: list[Finding] = []

    for entry in registry.rules_for("local", server_type="iis"):
        findings.extend(
            run_rule_entry(
                entry,
                issues=issues,
                invoke=lambda entry=entry: _invoke_rule(
                    entry.fn,
                    doc,
                    effective_config=effective_config,
                    registry_tls=registry_tls,
                ),
            )
        )

    return findings


def _invoke_rule(
    fn: Callable[..., list[Finding]],
    doc: IISConfigDocument,
    *,
    effective_config: IISEffectiveConfig | None,
    registry_tls: IISRegistryTLS | None,
) -> list[Finding]:
    if _accepts_registry_tls(fn):
        return fn(doc, effective_config=effective_config, registry_tls=registry_tls)
    return fn(doc, effective_config=effective_config)


@lru_cache(maxsize=None)
def _accepts_registry_tls(fn: Callable[..., list[Finding]]) -> bool:
    return "registry_tls" in signature(fn).parameters


__all__ = ["run_iis_rules"]
