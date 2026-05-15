from pathlib import Path

from webconf_audit.local.load_context import LoadContext
from webconf_audit.local.nginx.include import resolve_includes
from webconf_audit.local.nginx.parser.parser import NginxParseError, NginxParser, NginxTokenizer
from webconf_audit.local.normalized import NormalizedConfig
from webconf_audit.local.nginx.rules_runner import run_nginx_rules
from webconf_audit.local.normalizers import normalize_config
from webconf_audit.local.universal_rules import run_universal_rules
from webconf_audit.models import AnalysisIssue, AnalysisResult, Finding, SourceLocation

_NGINX_SPECIFIC_UNIVERSAL_REPLACEMENTS = frozenset(
    {
        "universal.missing_x_frame_options",
        "universal.permissions_policy_unsafe",
        "universal.referrer_policy_unsafe",
        "universal.weak_tls_ciphers",
    }
)


def analyze_nginx_config(
    config_path: str,
    *,
    enable_policy_review: bool = False,
) -> AnalysisResult:
    path = Path(config_path)

    if not path.is_file():
        return AnalysisResult(
            mode="local",
            target=config_path,
            server_type="nginx",
            issues=[
                AnalysisIssue(
                    code="config_not_found",
                    level="error",
                    message=f"Config file not found: {config_path}",
                    location=SourceLocation(
                        mode="local",
                        kind="file",
                        file_path=config_path,
                    ),
                )
            ],
        )

    try:
        text = read_text_file(config_path)
    except (OSError, UnicodeDecodeError) as exc:
        return AnalysisResult(
            mode="local",
            target=config_path,
            server_type="nginx",
            issues=[
                AnalysisIssue(
                    code="nginx_config_read_error",
                    level="error",
                    message=f"Cannot read config file: {exc}",
                    location=SourceLocation(
                        mode="local",
                        kind="file",
                        file_path=str(path),
                    ),
                )
            ],
        )

    try:
        tokens = NginxTokenizer(text, file_path=str(path)).tokenize()
        ast = NginxParser(tokens).parse()
    except NginxParseError as exc:
        error_path = getattr(exc, "file_path", str(path))
        return AnalysisResult(
            mode="local",
            target=config_path,
            server_type="nginx",
            issues=[
                AnalysisIssue(
                    code="nginx_parse_error",
                    level="error",
                    message=str(exc),
                    location=SourceLocation(
                        mode="local",
                        kind="file",
                        file_path=error_path,
                        line=getattr(exc, "line", None),
                    ),
                )
            ],
        )

    load_ctx = LoadContext(root_file=str(path))
    issues = resolve_includes(ast, path, load_context=load_ctx)
    findings = run_nginx_rules(
        ast, issues=issues, enable_policy_review=enable_policy_review,
    )
    normalized = normalize_config("nginx", ast=ast)
    findings.extend(
        _universal_nginx_findings(
            normalized, issues, enable_policy_review=enable_policy_review,
        )
    )

    return AnalysisResult(
        mode="local",
        target=config_path,
        server_type="nginx",
        findings=findings,
        issues=issues,
        metadata={"load_context": load_ctx.to_dict()},
    )


def read_text_file(path: str) -> str:
    file_path = Path(path)
    return file_path.read_text(encoding="utf-8")


def _universal_nginx_findings(
    normalized: NormalizedConfig,
    issues: list[AnalysisIssue],
    *,
    enable_policy_review: bool = False,
) -> list[Finding]:
    return [
        finding
        for finding in run_universal_rules(
            normalized,
            issues=issues,
            enable_policy_review=enable_policy_review,
        )
        if finding.rule_id not in _NGINX_SPECIFIC_UNIVERSAL_REPLACEMENTS
    ]
