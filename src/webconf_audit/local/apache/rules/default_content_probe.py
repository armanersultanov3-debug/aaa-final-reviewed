from __future__ import annotations

from pathlib import Path

from webconf_audit.local.apache.effective import (
    ApacheVirtualHostContext,
    extract_document_root,
    extract_virtualhost_contexts,
)
from webconf_audit.local.apache.parser import ApacheConfigAst
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "apache.default_content_probe"
TITLE = "Default HTML or CGI sample content is exposed"
DESCRIPTION = (
    "Apache serves or stores stock HTML / CGI sample content under the active "
    "DocumentRoot."
)
RECOMMENDATION = (
    "Remove default Apache sample pages and CGI demos from the DocumentRoot "
    "or replace them with application content."
)
_SAMPLE_PATH_MARKERS: dict[str, tuple[str, ...]] = {
    "index.html": (
        "apache2 default page",
        "apache default page",
        "it works!",
        "default web page",
        "this is the default web page",
    ),
    "index.htm": (
        "apache2 default page",
        "apache default page",
        "it works!",
        "default web page",
    ),
    "cgi-bin/test-cgi": (
        "cgi test script",
        "cgi test",
        "printenv",
        "server software",
    ),
    "cgi-bin/printenv": (
        "cgi test script",
        "printenv",
        "server software",
    ),
}


@rule(
    rule_id=RULE_ID,
    title=TITLE,
    severity="medium",
    description=DESCRIPTION,
    recommendation=RECOMMENDATION,
    category="local",
    server_type="apache",
    order=373,
)
def find_default_content_probe(config_ast: ApacheConfigAst) -> list[Finding]:
    findings: list[Finding] = []
    config_dir = _config_dir(config_ast)
    contexts = [None, *extract_virtualhost_contexts(config_ast)]

    seen_files: set[str] = set()
    for context in contexts:
        document_root = extract_document_root(
            config_ast,
            virtualhost_context=context,
            config_dir=config_dir,
        )
        if document_root is None:
            continue

        for relative_path, markers in _SAMPLE_PATH_MARKERS.items():
            sample_path = document_root / relative_path
            if str(sample_path) in seen_files:
                continue

            finding = _sample_content_finding(sample_path, markers)
            if finding is None:
                continue

            findings.append(finding)
            seen_files.add(str(sample_path))

    return findings


def _sample_content_finding(
    sample_path: Path,
    markers: tuple[str, ...],
) -> Finding | None:
    if not sample_path.is_file():
        return None

    try:
        lines = sample_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return None

    for line_number, raw_line in enumerate(lines, start=1):
        lowered = raw_line.lower()
        if not any(marker in lowered for marker in markers):
            continue

        return Finding(
            rule_id=RULE_ID,
            title=TITLE,
            severity="medium",
            description=(
                f"Apache DocumentRoot file '{sample_path}' looks like stock sample "
                "content."
            ),
            recommendation=RECOMMENDATION,
            location=SourceLocation(
                mode="local",
                kind="file",
                file_path=str(sample_path),
                line=line_number,
            ),
        )

    return None


def _config_dir(config_ast: ApacheConfigAst) -> Path | None:
    if not config_ast.nodes:
        return None
    source = config_ast.nodes[0].source
    if source.file_path is None:
        return None
    return Path(source.file_path).parent


__all__ = ["find_default_content_probe"]
