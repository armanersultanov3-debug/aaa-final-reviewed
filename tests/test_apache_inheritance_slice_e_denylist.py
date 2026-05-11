from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

import pytest

from webconf_audit.local.apache.parser import parse_apache_config
from webconf_audit.local.apache.parser.parser import ApacheConfigAst
from webconf_audit.local.apache.rules.backup_files_restricted import (
    find_backup_files_restricted,
)
from webconf_audit.local.apache.rules.generated_artifacts_restricted import (
    find_generated_artifacts_restricted,
)
from webconf_audit.local.apache.rules.ht_files_restricted import find_ht_files_restricted
from webconf_audit.local.apache.rules.sensitive_config_files_restricted import (
    find_sensitive_config_files_restricted,
)
from webconf_audit.local.apache.rules.vcs_metadata_restricted import (
    find_vcs_metadata_restricted,
)
from webconf_audit.models import Finding


RuleFinder = Callable[[ApacheConfigAst], list[Finding]]


@dataclass(frozen=True, slots=True)
class DenyListRuleCase:
    name: str
    finder: RuleFinder
    full_restrictions: tuple[str, ...]
    partial_global_restrictions: tuple[str, ...]
    vhost_completion_restrictions: tuple[str, ...]
    expected_missing: tuple[str, ...]


RULE_CASES = (
    DenyListRuleCase(
        name="backup_files",
        finder=find_backup_files_restricted,
        full_restrictions=(
            '<FilesMatch "\\.(bak|old|backup|orig|save|swp|tmp)$">',
            "    Require all denied",
            "</FilesMatch>",
        ),
        partial_global_restrictions=(
            '<FilesMatch "\\.(bak|old|backup|orig|save|swp)$">',
            "    Require all denied",
            "</FilesMatch>",
        ),
        vhost_completion_restrictions=(
            '<FilesMatch "\\.tmp$">',
            "    Require all denied",
            "</FilesMatch>",
        ),
        expected_missing=("tmp",),
    ),
    DenyListRuleCase(
        name="ht_files",
        finder=find_ht_files_restricted,
        full_restrictions=(
            '<FilesMatch "^\\.ht">',
            "    Require all denied",
            "</FilesMatch>",
        ),
        partial_global_restrictions=(
            '<FilesMatch "^\\.html$">',
            "    Require all denied",
            "</FilesMatch>",
        ),
        vhost_completion_restrictions=(
            '<FilesMatch "^\\.ht">',
            "    Require all denied",
            "</FilesMatch>",
        ),
        expected_missing=(".ht*",),
    ),
    DenyListRuleCase(
        name="vcs_metadata",
        finder=find_vcs_metadata_restricted,
        full_restrictions=(
            '<FilesMatch "^\\.(git|svn)$">',
            "    Require all denied",
            "</FilesMatch>",
        ),
        partial_global_restrictions=(
            '<FilesMatch "^\\.git$">',
            "    Require all denied",
            "</FilesMatch>",
        ),
        vhost_completion_restrictions=(
            '<FilesMatch "^\\.svn$">',
            "    Require all denied",
            "</FilesMatch>",
        ),
        expected_missing=("svn",),
    ),
    DenyListRuleCase(
        name="vcs_metadata_locationmatch",
        finder=find_vcs_metadata_restricted,
        full_restrictions=(
            '<LocationMatch "^/\\.(git|svn)(/|$)">',
            "    Require all denied",
            "</LocationMatch>",
        ),
        partial_global_restrictions=(
            '<LocationMatch "^/\\.git(/|$)">',
            "    Require all denied",
            "</LocationMatch>",
        ),
        vhost_completion_restrictions=(
            '<LocationMatch "^/\\.svn(/|$)">',
            "    Require all denied",
            "</LocationMatch>",
        ),
        expected_missing=("svn",),
    ),
    DenyListRuleCase(
        name="generated_artifacts",
        finder=find_generated_artifacts_restricted,
        full_restrictions=(
            '<FilesMatch "(^|/)(Thumbs\\.db|composer\\.(json|lock)|package-lock\\.json|\\.DS_Store|\\.npmrc|\\.yarnrc)$">',
            "    Require all denied",
            "</FilesMatch>",
            '<DirectoryMatch "/\\.(idea|vscode)(/|$)">',
            "    Require all denied",
            "</DirectoryMatch>",
        ),
        partial_global_restrictions=(
            '<FilesMatch "(^|/)(Thumbs\\.db|composer\\.(json|lock)|package-lock\\.json|\\.DS_Store|\\.npmrc|\\.yarnrc)$">',
            "    Require all denied",
            "</FilesMatch>",
        ),
        vhost_completion_restrictions=(
            '<DirectoryMatch "/\\.(idea|vscode)(/|$)">',
            "    Require all denied",
            "</DirectoryMatch>",
        ),
        expected_missing=(".idea", ".vscode"),
    ),
    DenyListRuleCase(
        name="sensitive_config_files",
        finder=find_sensitive_config_files_restricted,
        full_restrictions=(
            '<FilesMatch "\\.(conf|env|ini|log|sql|orig|save|tmp)$">',
            "    Require all denied",
            "</FilesMatch>",
        ),
        partial_global_restrictions=(
            '<FilesMatch "\\.(conf|env|ini|log|sql|orig|save)$">',
            "    Require all denied",
            "</FilesMatch>",
        ),
        vhost_completion_restrictions=(
            '<FilesMatch "\\.tmp$">',
            "    Require all denied",
            "</FilesMatch>",
        ),
        expected_missing=("tmp",),
    ),
)


@pytest.mark.parametrize("case", RULE_CASES, ids=lambda case: case.name)
def test_top_level_filesmatch_inherited_by_all_vhosts_silent(
    case: DenyListRuleCase,
) -> None:
    ast = _parse(
        _vhost_config(
            global_lines=case.full_restrictions,
            first_vhost_lines=(),
            second_vhost_lines=(),
        )
    )

    assert case.finder(ast) == []


@pytest.mark.parametrize("case", RULE_CASES, ids=lambda case: case.name)
def test_top_level_filesmatch_with_one_vhost_overriding_finding_only_for_that_vhost(
    case: DenyListRuleCase,
) -> None:
    config = _vhost_config(
        global_lines=case.partial_global_restrictions,
        first_vhost_lines=case.vhost_completion_restrictions,
        second_vhost_lines=(),
    )
    ast = _parse(config)

    findings = case.finder(ast)

    assert _scope_names(findings) == ["missing.example.test"]
    assert findings[0].metadata["missing_extensions"] == list(case.expected_missing)
    assert findings[0].location is not None
    assert findings[0].location.line == _line_number(config, "<VirtualHost *:80>", 2)


@pytest.mark.parametrize("case", RULE_CASES, ids=lambda case: case.name)
def test_no_filesmatch_anywhere_finding_per_vhost(case: DenyListRuleCase) -> None:
    ast = _parse(
        _vhost_config(
            global_lines=(),
            first_vhost_lines=(),
            second_vhost_lines=(),
        )
    )

    findings = case.finder(ast)

    assert _scope_names(findings) == ["covered.example.test", "missing.example.test"]
    assert [finding.metadata["missing_extensions"] for finding in findings] == [
        list(case.expected_missing)
        if case.expected_missing == (".ht*",)
        else _expected_all_missing(case),
        list(case.expected_missing)
        if case.expected_missing == (".ht*",)
        else _expected_all_missing(case),
    ]


@pytest.mark.parametrize("case", RULE_CASES, ids=lambda case: case.name)
def test_redirect_only_vhost_skipped(case: DenyListRuleCase) -> None:
    ast = _parse(
        _vhost_config(
            global_lines=(),
            first_vhost_lines=(
                "Redirect permanent / https://redirect.example.test/",
            ),
            second_vhost_lines=(),
            first_document_root=False,
        )
    )

    findings = case.finder(ast)

    assert _scope_names(findings) == ["missing.example.test"]


@pytest.mark.parametrize("case", RULE_CASES, ids=lambda case: case.name)
def test_single_server_no_vhost_global_finding(case: DenyListRuleCase) -> None:
    ast = _parse(_single_server_config())

    findings = case.finder(ast)

    assert len(findings) == 1
    assert findings[0].metadata == {}


@pytest.mark.parametrize("case", RULE_CASES, ids=lambda case: case.name)
def test_document_root_directory_filesmatch_counts_for_that_vhost(
    case: DenyListRuleCase,
) -> None:
    if case.name == "vcs_metadata_locationmatch":
        pytest.skip("LocationMatch is a direct URL-path restriction, not a Directory child.")

    ast = _parse(
        _vhost_config(
            global_lines=case.partial_global_restrictions,
            first_vhost_lines=_document_root_directory(case.vhost_completion_restrictions),
            second_vhost_lines=(),
        )
    )

    findings = case.finder(ast)

    assert _scope_names(findings) == ["missing.example.test"]


def _parse(config: str) -> ApacheConfigAst:
    return parse_apache_config(config, file_path="httpd.conf")


def _vhost_config(
    *,
    global_lines: tuple[str, ...],
    first_vhost_lines: tuple[str, ...],
    second_vhost_lines: tuple[str, ...],
    first_document_root: bool = True,
) -> str:
    first_document_root_lines = (
        ('    DocumentRoot "/srv/www/covered"',) if first_document_root else ()
    )
    return "\n".join(
        [
            'DocumentRoot "/srv/www/global"',
            *global_lines,
            "<VirtualHost *:80>",
            "    ServerName covered.example.test",
            *first_document_root_lines,
            *_indent(first_vhost_lines),
            "</VirtualHost>",
            "<VirtualHost *:80>",
            "    ServerName missing.example.test",
            '    DocumentRoot "/srv/www/missing"',
            *_indent(second_vhost_lines),
            "</VirtualHost>",
        ]
    )


def _single_server_config() -> str:
    return "\n".join(
        [
            'DocumentRoot "/srv/www/global"',
            '<FilesMatch "^\\.html$">',
            "    Require all denied",
            "</FilesMatch>",
        ]
    )


def _document_root_directory(lines: tuple[str, ...]) -> tuple[str, ...]:
    return (
        '<Directory "/srv/www/covered">',
        *_indent(lines),
        "</Directory>",
    )


def _indent(lines: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(f"    {line}" for line in lines)


def _scope_names(findings: list[Finding]) -> list[str]:
    return [finding.metadata["scope_name"] for finding in findings]


def _expected_all_missing(case: DenyListRuleCase) -> list[str]:
    if case.name == "backup_files":
        return ["bak", "old", "backup", "orig", "save", "swp", "tmp"]
    if case.name.startswith("vcs_metadata"):
        return ["git", "svn"]
    if case.name == "generated_artifacts":
        return [
            ".DS_Store",
            "Thumbs.db",
            "composer manifests",
            "package-lock.json",
            ".npmrc",
            ".yarnrc",
            ".idea",
            ".vscode",
        ]
    if case.name == "sensitive_config_files":
        return ["conf", "env", "ini", "log", "sql", "orig", "save", "tmp"]
    return list(case.expected_missing)


def _line_number(text: str, needle: str, occurrence: int = 1) -> int:
    seen = 0
    for line_number, line in enumerate(text.splitlines(), start=1):
        if line == needle:
            seen += 1
            if seen == occurrence:
                return line_number
    raise AssertionError(f"Could not find occurrence {occurrence} of {needle!r}")
