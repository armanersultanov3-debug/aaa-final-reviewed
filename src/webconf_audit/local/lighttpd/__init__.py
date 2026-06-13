from __future__ import annotations

import os
from pathlib import Path

from webconf_audit.audit_policy import (
    attach_audit_context,
    build_analysis_manifest,
    requested_opt_in_tags,
)
from webconf_audit.execution_manifest import RuleExecutionRecorder
from webconf_audit.local.lighttpd.conditions import LighttpdRequestContext
from webconf_audit.local.lighttpd.effective import build_effective_config, merge_conditional_scopes
from webconf_audit.local.lighttpd.include import resolve_includes
from webconf_audit.local.lighttpd.parser import LighttpdParseError, LighttpdParser
from webconf_audit.local.lighttpd.rules.redirect_scope_utils import (
    is_redirect_only_config,
)
from webconf_audit.local.lighttpd.rules_runner import run_lighttpd_rules
from webconf_audit.local.lighttpd.variables import expand_variables
from webconf_audit.local.load_context import LoadContext
from webconf_audit.local.normalizers import normalize_config
from webconf_audit.local.universal_rules import run_universal_rules
from webconf_audit.models import AnalysisIssue, AnalysisResult, SourceLocation
from webconf_audit.policy_models import ResolvedAuditPolicy
from webconf_audit.rule_registry import registry as rule_registry

_REDIRECT_ONLY_UNIVERSAL_NOISE_RULE_IDS = frozenset(
    {
        "universal.missing_content_security_policy",
        "universal.missing_referrer_policy",
        "universal.missing_x_content_type_options",
        "universal.missing_x_frame_options",
    }
)


def analyze_lighttpd_config(
    config_path: str | os.PathLike[str],
    execute_shell: bool = False,
    host: str | None = None,
    *,
    enable_policy_review: bool = False,
    policy: ResolvedAuditPolicy | None = None,
) -> AnalysisResult:
    """Run the full Lighttpd local-analysis pipeline against ``config_path``.

    Resolves ``include`` directives (and, when ``execute_shell=True``,
    ``include_shell``), expands ``var.*`` references, builds the
    effective conditional-scope view, then runs Lighttpd-specific rules
    and universal rules. ``host`` narrows conditional evaluation to a
    single request context for targeted analysis; when omitted, the
    no-host model is used and conditional-only signals are surfaced
    conservatively.

    Set ``enable_policy_review=True`` to additionally include rules
    tagged ``policy-review`` (operator-judgment items surfaced via the
    ``--enable-policy-review`` CLI flag).
    """
    config_path_str = os.fspath(config_path)
    path = Path(config_path_str)
    effective_policy_review = (
        enable_policy_review
        or "policy-review" in requested_opt_in_tags(policy)
    )

    if not path.is_file():
        return _attach_context(
            AnalysisResult(
                mode="local",
                target=config_path_str,
                server_type="lighttpd",
                issues=[
                    AnalysisIssue(
                        code="config_not_found",
                        level="error",
                        message=f"Config file not found: {config_path_str}",
                        location=SourceLocation(
                            mode="local",
                            kind="file",
                            file_path=config_path_str,
                        ),
                    )
                ],
            ),
            policy=policy,
        )

    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return _attach_context(
            AnalysisResult(
                mode="local",
                target=config_path_str,
                server_type="lighttpd",
                issues=[
                    AnalysisIssue(
                        code="lighttpd_config_read_error",
                        level="error",
                        message=f"Cannot read config file: {exc}",
                        location=SourceLocation(
                            mode="local",
                            kind="file",
                            file_path=str(path),
                        ),
                    )
                ],
            ),
            policy=policy,
        )

    try:
        ast = LighttpdParser(text, file_path=str(path)).parse()
        load_ctx = LoadContext(root_file=str(path))
        issues = resolve_includes(
            ast,
            path,
            load_context=load_ctx,
            execute_shell=execute_shell,
        )
        issues.extend(expand_variables(ast))
        effective = build_effective_config(ast)

        context = LighttpdRequestContext(host=host) if host is not None else None
        merged_directives = merge_conditional_scopes(effective, context=context)
        recorder = RuleExecutionRecorder()

        findings = run_lighttpd_rules(
            ast,
            effective_config=effective,
            merged_directives=merged_directives,
            request_context=context,
            issues=issues,
            enable_policy_review=effective_policy_review,
            execution_recorder=recorder,
        )
        normalized = normalize_config(
            "lighttpd", ast=ast, effective_config=effective,
            merged_directives=merged_directives,
        )
        universal_findings = run_universal_rules(
            normalized,
            issues=issues,
            enable_policy_review=effective_policy_review,
            execution_recorder=recorder,
        )
        if is_redirect_only_config(ast):
            universal_findings = [
                finding
                for finding in universal_findings
                if finding.rule_id not in _REDIRECT_ONLY_UNIVERSAL_NOISE_RULE_IDS
            ]
        findings.extend(universal_findings)
    except LighttpdParseError as exc:
        return _attach_context(
            AnalysisResult(
                mode="local",
                target=config_path_str,
                server_type="lighttpd",
                issues=[
                    AnalysisIssue(
                        code="lighttpd_parse_error",
                        level="error",
                        message=str(exc),
                        location=SourceLocation(
                            mode="local",
                            kind="file",
                            file_path=exc.file_path or str(path),
                            line=exc.line,
                        ),
                    )
                ],
            ),
            policy=policy,
        )

    return _attach_context(
        AnalysisResult(
            mode="local",
            target=config_path_str,
            server_type="lighttpd",
            findings=findings,
            issues=issues,
            metadata={
                "load_context": load_ctx.to_dict(),
                "host_filter": host,
            },
        ),
        policy=policy,
        recorder=recorder,
    )


def _attach_context(
    result: AnalysisResult,
    *,
    policy: ResolvedAuditPolicy | None,
    recorder: RuleExecutionRecorder | None = None,
) -> AnalysisResult:
    rule_registry.ensure_loaded("webconf_audit.local.lighttpd.rules")
    rule_registry.ensure_loaded("webconf_audit.local.rules.universal")
    manifest = build_analysis_manifest(
        recorder=recorder or RuleExecutionRecorder(),
        policy=policy,
        mode="local",
        server_type="lighttpd",
        registry=rule_registry,
    )
    return attach_audit_context(result, policy, manifest)


__all__ = ["analyze_lighttpd_config"]
