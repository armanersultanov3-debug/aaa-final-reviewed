from tests.apache_helpers import (
    ALL_OVERRIDE_CATEGORIES,
    ApacheBlockNode,
    HtaccessFile,
    Path,
    analyze_apache_config,
    build_effective_config,
    discover_htaccess_files,
    extract_allowoverride,
    filter_htaccess_by_allowoverride,
    find_htaccess_weakens_security,
    parse_apache_config,
    pytest,
    _analyze_with_htaccess,
    _posix_path,
    _with_backup_files_restriction,
)

def test_htaccess_discovered_for_directory_block(tmp_path: Path) -> None:
    web_dir = tmp_path / "var" / "www"
    web_dir.mkdir(parents=True)
    (web_dir / ".htaccess").write_text("Options -Indexes\n", encoding="utf-8")

    config = parse_apache_config(
        f'<Directory "{_posix_path(web_dir)}">\n'
        "    AllowOverride All\n"
        "</Directory>\n"
    )
    result = discover_htaccess_files(config, str(tmp_path / "httpd.conf"))

    assert len(result.found) == 1
    assert Path(result.found[0].directory_path).resolve() == web_dir.resolve()
    assert Path(result.found[0].htaccess_path).resolve() == (web_dir / ".htaccess").resolve()
    assert result.found[0].source_directory_block is not None
    assert result.found[0].ast.nodes[0].name == "Options"
    assert result.issues == []


def test_htaccess_not_found_no_error(tmp_path: Path) -> None:
    web_dir = tmp_path / "var" / "www"
    web_dir.mkdir(parents=True)

    config = parse_apache_config(
        f'<Directory "{_posix_path(web_dir)}">\n'
        "    AllowOverride All\n"
        "</Directory>\n"
    )
    result = discover_htaccess_files(config, str(tmp_path / "httpd.conf"))

    assert result.found == []
    assert result.issues == []


def test_htaccess_parse_error_produces_issue(tmp_path: Path) -> None:
    web_dir = tmp_path / "var" / "www"
    web_dir.mkdir(parents=True)
    (web_dir / ".htaccess").write_text(
        "<IfModule mod_rewrite.c>\n",  # unterminated block
        encoding="utf-8",
    )

    config = parse_apache_config(
        f'<Directory "{_posix_path(web_dir)}">\n'
        "    AllowOverride All\n"
        "</Directory>\n"
    )
    result = discover_htaccess_files(config, str(tmp_path / "httpd.conf"))

    assert result.found == []
    assert len(result.issues) == 1
    assert result.issues[0].code == "htaccess_parse_error"


def test_htaccess_multiple_directories(tmp_path: Path) -> None:
    dir_a = tmp_path / "a"
    dir_b = tmp_path / "b"
    dir_a.mkdir()
    dir_b.mkdir()
    (dir_a / ".htaccess").write_text("Options -Indexes\n", encoding="utf-8")
    (dir_b / ".htaccess").write_text("Options +FollowSymLinks\n", encoding="utf-8")

    config = parse_apache_config(
        f'<Directory "{_posix_path(dir_a)}">\n'
        "    AllowOverride All\n"
        "</Directory>\n"
        f'<Directory "{_posix_path(dir_b)}">\n'
        "    AllowOverride All\n"
        "</Directory>\n"
    )
    result = discover_htaccess_files(config, str(tmp_path / "httpd.conf"))

    assert len(result.found) == 2
    resolved_paths = {Path(hf.directory_path).resolve() for hf in result.found}
    assert dir_a.resolve() in resolved_paths
    assert dir_b.resolve() in resolved_paths


def test_htaccess_custom_access_file_name(tmp_path: Path) -> None:
    web_dir = tmp_path / "www"
    web_dir.mkdir()
    (web_dir / ".override").write_text("Options -Indexes\n", encoding="utf-8")

    config = parse_apache_config(
        "AccessFileName .override\n"
        f'<Directory "{_posix_path(web_dir)}">\n'
        "    AllowOverride All\n"
        "</Directory>\n"
    )
    result = discover_htaccess_files(config, str(tmp_path / "httpd.conf"))

    assert len(result.found) == 1
    assert Path(result.found[0].htaccess_path).resolve() == (web_dir / ".override").resolve()


def test_htaccess_document_root_is_checked(tmp_path: Path) -> None:
    doc_root = tmp_path / "htdocs"
    doc_root.mkdir()
    (doc_root / ".htaccess").write_text("RewriteEngine On\n", encoding="utf-8")

    config = parse_apache_config(
        f'DocumentRoot "{_posix_path(doc_root)}"\n'
    )
    result = discover_htaccess_files(config, str(tmp_path / "httpd.conf"))

    assert len(result.found) == 1
    assert Path(result.found[0].directory_path).resolve() == doc_root.resolve()
    assert result.found[0].source_directory_block is None


def test_htaccess_document_root_in_virtualhost(tmp_path: Path) -> None:
    doc_root = tmp_path / "vhost_root"
    doc_root.mkdir()
    (doc_root / ".htaccess").write_text("Options -Indexes\n", encoding="utf-8")

    config = parse_apache_config(
        "<VirtualHost *:80>\n"
        f'    DocumentRoot "{_posix_path(doc_root)}"\n'
        "</VirtualHost>\n"
    )
    result = discover_htaccess_files(config, str(tmp_path / "httpd.conf"))

    assert len(result.found) == 1
    assert result.found[0].source_directory_block is None


def test_htaccess_deduplicates_same_directory(tmp_path: Path) -> None:
    web_dir = tmp_path / "www"
    web_dir.mkdir()
    (web_dir / ".htaccess").write_text("Options -Indexes\n", encoding="utf-8")

    config = parse_apache_config(
        f'DocumentRoot "{_posix_path(web_dir)}"\n'
        f'<Directory "{_posix_path(web_dir)}">\n'
        "    AllowOverride All\n"
        "</Directory>\n"
    )
    result = discover_htaccess_files(config, str(tmp_path / "httpd.conf"))

    assert len(result.found) == 1


def test_htaccess_regex_directory_skipped(tmp_path: Path) -> None:
    """<Directory ~ "regex"> blocks should not trigger .htaccess lookup."""
    config = parse_apache_config(
        '<Directory ~ "^/var/www/(pub|priv)">\n'
        "    AllowOverride None\n"
        "</Directory>\n"
    )
    result = discover_htaccess_files(config, str(tmp_path / "httpd.conf"))

    assert result.found == []
    assert result.issues == []


def test_htaccess_directory_without_args_skipped() -> None:
    """<Directory> with no path argument should be safely skipped."""
    config = parse_apache_config(
        "<Directory>\n"
        "    AllowOverride None\n"
        "</Directory>\n"
    )
    result = discover_htaccess_files(config, "httpd.conf")

    assert result.found == []
    assert result.issues == []


def test_htaccess_integrated_in_analyze(tmp_path: Path) -> None:
    """discover_htaccess_files is called during analyze_apache_config."""
    web_dir = tmp_path / "www"
    web_dir.mkdir()
    (web_dir / ".htaccess").write_text(
        "<IfModule broken\n",  # malformed -- no closing >
        encoding="utf-8",
    )

    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            f'<Directory "{_posix_path(web_dir)}">\n'
            "    AllowOverride All\n"
            "</Directory>\n"
            "ServerSignature Off\n"
            "ServerTokens Prod\n"
            "TraceEnable Off\n"
            "LimitRequestBody 102400\n"
            "LimitRequestFields 100\n"
            "ErrorLog logs/error_log\n"
            "CustomLog logs/access_log combined\n"
            'ErrorDocument 404 "/error/404.html"\n'
            'ErrorDocument 500 "/error/500.html"\n'
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))
    issue_codes = [i.code for i in result.issues]
    assert "htaccess_parse_error" in issue_codes


def test_htaccess_relative_directory_path(tmp_path: Path) -> None:
    """Relative <Directory> path resolved against config file's parent dir."""
    site_dir = tmp_path / "conf" / "site"
    site_dir.mkdir(parents=True)
    (site_dir / ".htaccess").write_text("Options -Indexes\n", encoding="utf-8")

    config_path = tmp_path / "conf" / "httpd.conf"
    config = parse_apache_config(
        '<Directory "site">\n'
        "    AllowOverride All\n"
        "</Directory>\n"
    )
    result = discover_htaccess_files(config, str(config_path))

    assert len(result.found) == 1
    assert Path(result.found[0].directory_path).resolve() == site_dir.resolve()


def test_htaccess_relative_document_root(tmp_path: Path) -> None:
    """Relative DocumentRoot resolved against config file's parent dir."""
    htdocs = tmp_path / "conf" / "htdocs"
    htdocs.mkdir(parents=True)
    (htdocs / ".htaccess").write_text("RewriteEngine On\n", encoding="utf-8")

    config_path = tmp_path / "conf" / "httpd.conf"
    config = parse_apache_config(
        'DocumentRoot "htdocs"\n'
    )
    result = discover_htaccess_files(config, str(config_path))

    assert len(result.found) == 1
    assert Path(result.found[0].directory_path).resolve() == htdocs.resolve()


def test_htaccess_stored_in_analysis_metadata(tmp_path: Path) -> None:
    """Discovered htaccess files are stored in AnalysisResult.metadata."""
    web_dir = tmp_path / "www"
    web_dir.mkdir()
    (web_dir / ".htaccess").write_text("Options -Indexes\n", encoding="utf-8")

    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            f'<Directory "{_posix_path(web_dir)}">\n'
            "    AllowOverride All\n"
            "</Directory>\n"
            "ServerSignature Off\n"
            "ServerTokens Prod\n"
            "TraceEnable Off\n"
            "LimitRequestBody 102400\n"
            "LimitRequestFields 100\n"
            "ErrorLog logs/error_log\n"
            "CustomLog logs/access_log combined\n"
            'ErrorDocument 404 "/error/404.html"\n'
            'ErrorDocument 500 "/error/500.html"\n'
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))
    assert "htaccess_files" in result.metadata
    htaccess_files = result.metadata["htaccess_files"]
    assert len(htaccess_files) == 1
    assert htaccess_files[0].ast.nodes[0].name == "Options"


def test_htaccess_read_error_produces_issue(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """OSError during .htaccess read produces htaccess_read_error issue."""
    web_dir = tmp_path / "www"
    web_dir.mkdir()
    htaccess = web_dir / ".htaccess"
    htaccess.write_text("Options -Indexes\n", encoding="utf-8")

    config = parse_apache_config(
        f'<Directory "{_posix_path(web_dir)}">\n'
        "    AllowOverride All\n"
        "</Directory>\n"
    )

    original_read_text = Path.read_text

    def failing_read_text(self: Path, *args: object, **kwargs: object) -> str:
        if self.name == ".htaccess":
            raise OSError("Permission denied")
        return original_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", failing_read_text)
    result = discover_htaccess_files(config, str(tmp_path / "httpd.conf"))

    assert result.found == []
    assert len(result.issues) == 1
    assert result.issues[0].code == "htaccess_read_error"


def test_htaccess_access_file_name_in_toplevel_ifmodule(tmp_path: Path) -> None:
    """AccessFileName inside top-level <IfModule> is server-scope -- found."""
    web_dir = tmp_path / "www"
    web_dir.mkdir()
    (web_dir / ".override").write_text("Options -Indexes\n", encoding="utf-8")

    config = parse_apache_config(
        "<IfModule mod_access.c>\n"
        "    AccessFileName .override\n"
        "</IfModule>\n"
        f'<Directory "{_posix_path(web_dir)}">\n'
        "    AllowOverride All\n"
        "</Directory>\n"
    )
    result = discover_htaccess_files(config, str(tmp_path / "httpd.conf"))

    assert len(result.found) == 1
    assert Path(result.found[0].htaccess_path).name == ".override"


def test_htaccess_access_file_name_in_toplevel_ifdefine(tmp_path: Path) -> None:
    """AccessFileName inside top-level <IfDefine> is also server-scope."""
    web_dir = tmp_path / "www"
    web_dir.mkdir()
    (web_dir / ".override").write_text("Options -Indexes\n", encoding="utf-8")

    config = parse_apache_config(
        "<IfDefine PROD>\n"
        "    AccessFileName .override\n"
        "</IfDefine>\n"
        f'<Directory "{_posix_path(web_dir)}">\n'
        "    AllowOverride All\n"
        "</Directory>\n"
    )
    result = discover_htaccess_files(config, str(tmp_path / "httpd.conf"))

    assert len(result.found) == 1
    assert Path(result.found[0].htaccess_path).name == ".override"


def test_htaccess_access_file_name_inside_directory_ignored(tmp_path: Path) -> None:
    """AccessFileName inside <Directory> is directory-scope -- ignored for global discovery."""
    dir_a = tmp_path / "app"
    dir_a.mkdir()
    (dir_a / ".appaccess").write_text("Options -Indexes\n", encoding="utf-8")

    dir_b = tmp_path / "site"
    dir_b.mkdir()
    (dir_b / ".htaccess").write_text("Options -Indexes\n", encoding="utf-8")

    config = parse_apache_config(
        f'<Directory "{_posix_path(dir_a)}">\n'
        "    AccessFileName .appaccess\n"
        "    AllowOverride Options\n"
        "</Directory>\n"
        f'<Directory "{_posix_path(dir_b)}">\n'
        "    AllowOverride Options\n"
        "</Directory>\n"
    )
    result = discover_htaccess_files(config, str(tmp_path / "httpd.conf"))

    # dir_b uses default .htaccess (not .appaccess from dir_a's scope)
    found_paths = {Path(f.htaccess_path).name for f in result.found}
    assert ".htaccess" in found_paths


# ---------------------------------------------------------------------------
# Phase 2.3: AllowOverride semantics
# ---------------------------------------------------------------------------


class TestExtractAllowOverride:
    def test_allowoverride_none(self) -> None:
        ast = parse_apache_config(
            '<Directory "/var/www">\n'
            "    AllowOverride None\n"
            "</Directory>\n"
        )
        block = ast.nodes[0]
        assert isinstance(block, ApacheBlockNode)
        assert extract_allowoverride(block) == frozenset()

    def test_allowoverride_all(self) -> None:
        ast = parse_apache_config(
            '<Directory "/var/www">\n'
            "    AllowOverride All\n"
            "</Directory>\n"
        )
        block = ast.nodes[0]
        assert isinstance(block, ApacheBlockNode)
        assert extract_allowoverride(block) == ALL_OVERRIDE_CATEGORIES

    def test_allowoverride_specific_categories(self) -> None:
        ast = parse_apache_config(
            '<Directory "/var/www">\n'
            "    AllowOverride FileInfo AuthConfig\n"
            "</Directory>\n"
        )
        block = ast.nodes[0]
        assert isinstance(block, ApacheBlockNode)
        result = extract_allowoverride(block)
        assert result == frozenset({"FileInfo", "AuthConfig"})

    def test_allowoverride_case_insensitive(self) -> None:
        """Apache accepts lowercase category names; we should too."""
        ast = parse_apache_config(
            '<Directory "/var/www">\n'
            "    AllowOverride fileinfo authconfig\n"
            "</Directory>\n"
        )
        block = ast.nodes[0]
        assert isinstance(block, ApacheBlockNode)
        result = extract_allowoverride(block)
        assert result == frozenset({"FileInfo", "AuthConfig"})

    def test_allowoverride_absent(self) -> None:
        ast = parse_apache_config(
            '<Directory "/var/www">\n'
            "    Options -Indexes\n"
            "</Directory>\n"
        )
        block = ast.nodes[0]
        assert isinstance(block, ApacheBlockNode)
        assert extract_allowoverride(block) is None

    def test_allowoverride_indexes_options(self) -> None:
        ast = parse_apache_config(
            '<Directory "/var/www">\n'
            "    AllowOverride Indexes Options\n"
            "</Directory>\n"
        )
        block = ast.nodes[0]
        assert isinstance(block, ApacheBlockNode)
        assert extract_allowoverride(block) == frozenset({"Indexes", "Options"})


class TestFilterHtaccessByAllowOverride:
    def test_none_filters_everything(self) -> None:
        ast = parse_apache_config(
            "Options Indexes\n"
            "RewriteEngine On\n"
            "DirectoryIndex index.php\n"
        )
        filtered = filter_htaccess_by_allowoverride(ast, frozenset())
        assert len(filtered.nodes) == 0

    def test_all_passes_everything(self) -> None:
        ast = parse_apache_config(
            "Options Indexes\n"
            "RewriteEngine On\n"
            "DirectoryIndex index.php\n"
        )
        filtered = filter_htaccess_by_allowoverride(ast, ALL_OVERRIDE_CATEGORIES)
        assert len(filtered.nodes) == 3

    def test_fileinfo_only(self) -> None:
        ast = parse_apache_config(
            "Options Indexes\n"
            "RewriteEngine On\n"
            "DirectoryIndex index.php\n"
        )
        filtered = filter_htaccess_by_allowoverride(ast, frozenset({"FileInfo"}))
        names = [n.name for n in filtered.nodes]
        assert "RewriteEngine" in names
        assert "Options" not in names
        assert "DirectoryIndex" not in names

    def test_options_only(self) -> None:
        ast = parse_apache_config(
            "Options Indexes\n"
            "RewriteEngine On\n"
        )
        filtered = filter_htaccess_by_allowoverride(ast, frozenset({"Options"}))
        names = [n.name for n in filtered.nodes]
        assert names == ["Options"]

    def test_unknown_directives_blocked(self) -> None:
        """Directives not in the category map are blocked."""
        ast = parse_apache_config(
            "CustomDirective value\n"
            "Options Indexes\n"
        )
        filtered = filter_htaccess_by_allowoverride(ast, frozenset({"Options"}))
        names = [n.name for n in filtered.nodes]
        assert "CustomDirective" not in names
        assert "Options" in names

    def test_block_filtered_by_category(self) -> None:
        """<LimitExcept> block is filtered when Limit category not allowed."""
        ast = parse_apache_config(
            "<LimitExcept GET POST>\n"
            "    Require all denied\n"
            "</LimitExcept>\n"
            "Options -Indexes\n"
        )
        filtered = filter_htaccess_by_allowoverride(ast, frozenset({"Options"}))
        assert len(filtered.nodes) == 1
        assert filtered.nodes[0].name == "Options"

    def test_authconfig_indexes_combo(self) -> None:
        ast = parse_apache_config(
            "AuthType Basic\n"
            "AuthName \"Restricted\"\n"
            "Require valid-user\n"
            "Options Indexes\n"
            "DirectoryIndex index.html\n"
            "RewriteEngine On\n"
        )
        filtered = filter_htaccess_by_allowoverride(
            ast, frozenset({"AuthConfig", "Indexes"})
        )
        names = [n.name for n in filtered.nodes]
        assert "AuthType" in names
        assert "AuthName" in names
        assert "Require" in names
        assert "DirectoryIndex" in names
        assert "Options" not in names
        assert "RewriteEngine" not in names


class TestAllowOverrideAllRule:
    def test_allowoverride_all_fires(self, tmp_path: Path) -> None:
        config_path = tmp_path / "httpd.conf"
        config_path.write_text(
            _with_backup_files_restriction(
                '<Directory "/var/www">\n'
                "    AllowOverride All\n"
                "</Directory>\n"
                "ServerSignature Off\n"
                "ServerTokens Prod\n"
                "TraceEnable Off\n"
                "LimitRequestBody 102400\n"
                "LimitRequestFields 100\n"
                "ErrorLog logs/error_log\n"
                "CustomLog logs/access_log combined\n"
                'ErrorDocument 404 "/error/404.html"\n'
                'ErrorDocument 500 "/error/500.html"\n',
                include_cis_allowoverride_root=False,
            ),
            encoding="utf-8",
        )
        result = analyze_apache_config(str(config_path))
        ids = [f.rule_id for f in result.findings]
        assert "apache.allowoverride_all_in_directory" in ids

    def test_allowoverride_absent_fires(self, tmp_path: Path) -> None:
        """Missing AllowOverride -> treated as worst-case All -> fires."""
        config_path = tmp_path / "httpd.conf"
        config_path.write_text(
            _with_backup_files_restriction(
                '<Directory "/var/www">\n'
                "    Options -Indexes\n"
                "</Directory>\n"
                "ServerSignature Off\n"
                "ServerTokens Prod\n"
                "TraceEnable Off\n"
                "LimitRequestBody 102400\n"
                "LimitRequestFields 100\n"
                "ErrorLog logs/error_log\n"
                "CustomLog logs/access_log combined\n"
                'ErrorDocument 404 "/error/404.html"\n'
                'ErrorDocument 500 "/error/500.html"\n',
                include_cis_allowoverride_root=False,
            ),
            encoding="utf-8",
        )
        result = analyze_apache_config(str(config_path))
        ids = [f.rule_id for f in result.findings]
        assert "apache.allowoverride_all_in_directory" in ids

    def test_allowoverride_none_does_not_fire(self, tmp_path: Path) -> None:
        config_path = tmp_path / "httpd.conf"
        config_path.write_text(
            _with_backup_files_restriction(
                '<Directory "/var/www">\n'
                "    AllowOverride None\n"
                "</Directory>\n"
                "ServerSignature Off\n"
                "ServerTokens Prod\n"
                "TraceEnable Off\n"
                "LimitRequestBody 102400\n"
                "LimitRequestFields 100\n"
                "ErrorLog logs/error_log\n"
                "CustomLog logs/access_log combined\n"
                'ErrorDocument 404 "/error/404.html"\n'
                'ErrorDocument 500 "/error/500.html"\n',
                include_cis_allowoverride_root=False,
            ),
            encoding="utf-8",
        )
        result = analyze_apache_config(str(config_path))
        ids = [f.rule_id for f in result.findings]
        assert "apache.allowoverride_all_in_directory" not in ids

    def test_allowoverride_specific_does_not_fire(self, tmp_path: Path) -> None:
        config_path = tmp_path / "httpd.conf"
        config_path.write_text(
            _with_backup_files_restriction(
                '<Directory "/var/www">\n'
                "    AllowOverride FileInfo\n"
                "</Directory>\n"
                "ServerSignature Off\n"
                "ServerTokens Prod\n"
                "TraceEnable Off\n"
                "LimitRequestBody 102400\n"
                "LimitRequestFields 100\n"
                "ErrorLog logs/error_log\n"
                "CustomLog logs/access_log combined\n"
                'ErrorDocument 404 "/error/404.html"\n'
                'ErrorDocument 500 "/error/500.html"\n',
                include_cis_allowoverride_root=False,
            ),
            encoding="utf-8",
        )
        result = analyze_apache_config(str(config_path))
        ids = [f.rule_id for f in result.findings]
        assert "apache.allowoverride_all_in_directory" not in ids

    def test_find_effective_allowoverride_excludes_self(self) -> None:
        from webconf_audit.local.apache.rules.allowoverride_all import (
            _find_effective_allowoverride,
            _iter_directory_blocks,
        )

        ast = parse_apache_config(
            '<Directory "/var/www/restricted">\n'
            "    AllowOverride FileInfo\n"
            "</Directory>\n",
            file_path="/etc/httpd/httpd.conf",
        )
        blocks = _iter_directory_blocks(ast.nodes)
        assert len(blocks) == 1

        effective = _find_effective_allowoverride(blocks[0], blocks)

        assert effective is None

    def test_find_effective_allowoverride_returns_parent_not_self(self) -> None:
        from webconf_audit.local.apache.rules.allowoverride_all import (
            _find_effective_allowoverride,
            _iter_directory_blocks,
        )

        ast = parse_apache_config(
            '<Directory "/var/www">\n'
            "    AllowOverride All\n"
            "</Directory>\n"
            '<Directory "/var/www/restricted">\n'
            "    AllowOverride FileInfo\n"
            "</Directory>\n",
            file_path="/etc/httpd/httpd.conf",
        )
        blocks = _iter_directory_blocks(ast.nodes)
        assert len(blocks) == 2
        child_block = next(b for b in blocks if b.args[0].endswith("restricted"))

        effective = _find_effective_allowoverride(child_block, blocks)

        assert effective == ALL_OVERRIDE_CATEGORIES

    def test_find_effective_allowoverride_skips_same_path_peer(self) -> None:
        from webconf_audit.local.apache.rules.allowoverride_all import (
            _find_effective_allowoverride,
            _iter_directory_blocks,
        )

        ast = parse_apache_config(
            '<Directory "/var/www">\n'
            "    AllowOverride None\n"
            "</Directory>\n"
            '<Directory "/var/www">\n'
            "    AllowOverride All\n"
            "</Directory>\n",
            file_path="/etc/httpd/httpd.conf",
        )
        blocks = _iter_directory_blocks(ast.nodes)
        assert len(blocks) == 2

        effective_for_first = _find_effective_allowoverride(blocks[0], blocks)
        effective_for_second = _find_effective_allowoverride(blocks[1], blocks)

        assert effective_for_first is None
        assert effective_for_second is None

    def test_find_effective_allowoverride_prefers_later_equal_parent(self) -> None:
        from webconf_audit.local.apache.rules.allowoverride_all import (
            _find_effective_allowoverride,
            _iter_directory_blocks,
        )

        ast = parse_apache_config(
            '<Directory "/var/www">\n'
            "    AllowOverride All\n"
            "</Directory>\n"
            '<Directory "/var/www">\n'
            "    AllowOverride None\n"
            "</Directory>\n"
            '<Directory "/var/www/restricted">\n'
            "    Options -Indexes\n"
            "</Directory>\n",
            file_path="/etc/httpd/httpd.conf",
        )
        blocks = _iter_directory_blocks(ast.nodes)
        assert len(blocks) == 3
        child_block = next(b for b in blocks if b.args[0].endswith("restricted"))

        effective = _find_effective_allowoverride(child_block, blocks)

        assert effective == frozenset()

    def test_allowoverride_all_then_none_at_same_path_does_not_fire(
        self, tmp_path: Path
    ) -> None:
        config_path = tmp_path / "httpd.conf"
        config_path.write_text(
            _with_backup_files_restriction(
                '<Directory "/var/www">\n'
                "    AllowOverride All\n"
                "</Directory>\n"
                '<Directory "/var/www">\n'
                "    AllowOverride None\n"
                "</Directory>\n"
                "ServerSignature Off\n"
                "ServerTokens Prod\n"
                "TraceEnable Off\n"
                "LimitRequestBody 102400\n"
                "LimitRequestFields 100\n"
                "ErrorLog logs/error_log\n"
                "CustomLog logs/access_log combined\n"
                'ErrorDocument 404 "/error/404.html"\n'
                'ErrorDocument 500 "/error/500.html"\n',
                include_cis_allowoverride_root=False,
            ),
            encoding="utf-8",
        )
        result = analyze_apache_config(str(config_path))
        ids = [f.rule_id for f in result.findings]
        assert "apache.allowoverride_all_in_directory" not in ids

    def test_allowoverride_later_parent_none_suppresses_child_inheritance(
        self, tmp_path: Path
    ) -> None:
        config_path = tmp_path / "httpd.conf"
        config_path.write_text(
            _with_backup_files_restriction(
                '<Directory "/var/www">\n'
                "    AllowOverride All\n"
                "</Directory>\n"
                '<Directory "/var/www">\n'
                "    AllowOverride None\n"
                "</Directory>\n"
                '<Directory "/var/www/restricted">\n'
                "    Options -Indexes\n"
                "</Directory>\n"
                "ServerSignature Off\n"
                "ServerTokens Prod\n"
                "TraceEnable Off\n"
                "LimitRequestBody 102400\n"
                "LimitRequestFields 100\n"
                "ErrorLog logs/error_log\n"
                "CustomLog logs/access_log combined\n"
                'ErrorDocument 404 "/error/404.html"\n'
                'ErrorDocument 500 "/error/500.html"\n',
                include_cis_allowoverride_root=False,
            ),
            encoding="utf-8",
        )
        result = analyze_apache_config(str(config_path))
        ids = [f.rule_id for f in result.findings]
        assert "apache.allowoverride_all_in_directory" not in ids

    def test_allowoverride_repeated_all_at_same_path_fires_once_at_winner(
        self, tmp_path: Path
    ) -> None:
        config_path = tmp_path / "httpd.conf"
        config_path.write_text(
            _with_backup_files_restriction(
                '<Directory "/var/www">\n'
                "    AllowOverride All\n"
                "</Directory>\n"
                '<Directory "/var/www">\n'
                "    AllowOverride All\n"
                "</Directory>\n"
                "ServerSignature Off\n"
                "ServerTokens Prod\n"
                "TraceEnable Off\n"
                "LimitRequestBody 102400\n"
                "LimitRequestFields 100\n"
                "ErrorLog logs/error_log\n"
                "CustomLog logs/access_log combined\n"
                'ErrorDocument 404 "/error/404.html"\n'
                'ErrorDocument 500 "/error/500.html"\n',
                include_cis_allowoverride_root=False,
            ),
            encoding="utf-8",
        )
        result = analyze_apache_config(str(config_path))
        ao_findings = [
            f for f in result.findings
            if f.rule_id == "apache.allowoverride_all_in_directory"
        ]
        assert len(ao_findings) == 1
        # Finding points at the later declaration whose directive wins the merge.
        assert ao_findings[0].location.line == 4

    def test_allowoverride_repeated_no_directive_at_same_path_fires_once(
        self, tmp_path: Path
    ) -> None:
        config_path = tmp_path / "httpd.conf"
        config_path.write_text(
            _with_backup_files_restriction(
                '<Directory "/var/www">\n'
                "    Options -Indexes\n"
                "</Directory>\n"
                '<Directory "/var/www">\n'
                "    Options +FollowSymLinks\n"
                "</Directory>\n"
                "ServerSignature Off\n"
                "ServerTokens Prod\n"
                "TraceEnable Off\n"
                "LimitRequestBody 102400\n"
                "LimitRequestFields 100\n"
                "ErrorLog logs/error_log\n"
                "CustomLog logs/access_log combined\n"
                'ErrorDocument 404 "/error/404.html"\n'
                'ErrorDocument 500 "/error/500.html"\n',
                include_cis_allowoverride_root=False,
            ),
            encoding="utf-8",
        )
        result = analyze_apache_config(str(config_path))
        ao_findings = [
            f for f in result.findings
            if f.rule_id == "apache.allowoverride_all_in_directory"
        ]
        assert len(ao_findings) == 1
        # Finding points at the earliest declaration at the path.
        assert ao_findings[0].location.line == 1


class TestHtaccessSecurityDirectiveRule:
    def test_options_in_htaccess_fires(self, tmp_path: Path) -> None:
        web_dir = tmp_path / "www"
        web_dir.mkdir()
        (web_dir / ".htaccess").write_text("Options Indexes\n", encoding="utf-8")

        config_path = tmp_path / "httpd.conf"
        config_path.write_text(
            _with_backup_files_restriction(
                f'<Directory "{_posix_path(web_dir)}">\n'
                "    AllowOverride All\n"
                "</Directory>\n"
                "ServerSignature Off\n"
                "ServerTokens Prod\n"
                "TraceEnable Off\n"
                "LimitRequestBody 102400\n"
                "LimitRequestFields 100\n"
                "ErrorLog logs/error_log\n"
                "CustomLog logs/access_log combined\n"
                'ErrorDocument 404 "/error/404.html"\n'
                'ErrorDocument 500 "/error/500.html"\n',
                include_cis_allowoverride_root=False,
            ),
            encoding="utf-8",
        )
        result = analyze_apache_config(str(config_path))
        ids = [f.rule_id for f in result.findings]
        assert "apache.htaccess_contains_security_directive" in ids

    def test_allowoverride_none_blocks_htaccess_rule(self, tmp_path: Path) -> None:
        """AllowOverride None -> .htaccess ignored -> no security override finding."""
        web_dir = tmp_path / "www"
        web_dir.mkdir()
        (web_dir / ".htaccess").write_text("Options Indexes\n", encoding="utf-8")

        config_path = tmp_path / "httpd.conf"
        config_path.write_text(
            _with_backup_files_restriction(
                f'<Directory "{_posix_path(web_dir)}">\n'
                "    AllowOverride None\n"
                "</Directory>\n"
                "ServerSignature Off\n"
                "ServerTokens Prod\n"
                "TraceEnable Off\n"
                "LimitRequestBody 102400\n"
                "LimitRequestFields 100\n"
                "ErrorLog logs/error_log\n"
                "CustomLog logs/access_log combined\n"
                'ErrorDocument 404 "/error/404.html"\n'
                'ErrorDocument 500 "/error/500.html"\n'
            ),
            encoding="utf-8",
        )
        result = analyze_apache_config(str(config_path))
        ids = [f.rule_id for f in result.findings]
        assert "apache.htaccess_contains_security_directive" not in ids

    def test_allowoverride_fileinfo_blocks_options(self, tmp_path: Path) -> None:
        """AllowOverride FileInfo -> Options directive in .htaccess is filtered out."""
        web_dir = tmp_path / "www"
        web_dir.mkdir()
        (web_dir / ".htaccess").write_text(
            "Options Indexes\nRewriteEngine On\n",
            encoding="utf-8",
        )

        config_path = tmp_path / "httpd.conf"
        config_path.write_text(
            _with_backup_files_restriction(
                f'<Directory "{_posix_path(web_dir)}">\n'
                "    AllowOverride FileInfo\n"
                "</Directory>\n"
                "ServerSignature Off\n"
                "ServerTokens Prod\n"
                "TraceEnable Off\n"
                "LimitRequestBody 102400\n"
                "LimitRequestFields 100\n"
                "ErrorLog logs/error_log\n"
                "CustomLog logs/access_log combined\n"
                'ErrorDocument 404 "/error/404.html"\n'
                'ErrorDocument 500 "/error/500.html"\n'
            ),
            encoding="utf-8",
        )
        result = analyze_apache_config(str(config_path))
        overrides = [
            f for f in result.findings
            if f.rule_id == "apache.htaccess_contains_security_directive"
        ]
        # Options is blocked by FileInfo-only override,
        # but Header (FileInfo) would pass -- here only RewriteEngine which is not security-sensitive
        assert len(overrides) == 0

    def test_header_in_htaccess_fires(self, tmp_path: Path) -> None:
        web_dir = tmp_path / "www"
        web_dir.mkdir()
        (web_dir / ".htaccess").write_text(
            "Header unset X-Content-Type-Options\n",
            encoding="utf-8",
        )

        config_path = tmp_path / "httpd.conf"
        config_path.write_text(
            _with_backup_files_restriction(
                f'<Directory "{_posix_path(web_dir)}">\n'
                "    AllowOverride FileInfo\n"
                "</Directory>\n"
                "ServerSignature Off\n"
                "ServerTokens Prod\n"
                "TraceEnable Off\n"
                "LimitRequestBody 102400\n"
                "LimitRequestFields 100\n"
                "ErrorLog logs/error_log\n"
                "CustomLog logs/access_log combined\n"
                'ErrorDocument 404 "/error/404.html"\n'
                'ErrorDocument 500 "/error/500.html"\n'
            ),
            encoding="utf-8",
        )
        result = analyze_apache_config(str(config_path))
        overrides = [
            f for f in result.findings
            if f.rule_id == "apache.htaccess_contains_security_directive"
        ]
        assert len(overrides) == 1
        assert "Header" in overrides[0].title

    def test_no_htaccess_no_findings(self, tmp_path: Path) -> None:
        config_path = tmp_path / "httpd.conf"
        config_path.write_text(
            _with_backup_files_restriction(
                '<Directory "/var/www">\n'
                "    AllowOverride All\n"
                "</Directory>\n"
                "ServerSignature Off\n"
                "ServerTokens Prod\n"
                "TraceEnable Off\n"
                "LimitRequestBody 102400\n"
                "LimitRequestFields 100\n"
                "ErrorLog logs/error_log\n"
                "CustomLog logs/access_log combined\n"
                'ErrorDocument 404 "/error/404.html"\n'
                'ErrorDocument 500 "/error/500.html"\n'
            ),
            encoding="utf-8",
        )
        result = analyze_apache_config(str(config_path))
        overrides = [
            f for f in result.findings
            if f.rule_id == "apache.htaccess_contains_security_directive"
        ]
        assert len(overrides) == 0

    def test_security_directive_inside_ifmodule(self, tmp_path: Path) -> None:
        """Security directives inside <IfModule> in .htaccess are detected."""
        web_dir = tmp_path / "www"
        web_dir.mkdir()
        (web_dir / ".htaccess").write_text(
            "<IfModule mod_headers.c>\n"
            "    Header unset X-Powered-By\n"
            "</IfModule>\n",
            encoding="utf-8",
        )

        config_path = tmp_path / "httpd.conf"
        config_path.write_text(
            _with_backup_files_restriction(
                f'<Directory "{_posix_path(web_dir)}">\n'
                "    AllowOverride FileInfo\n"
                "</Directory>\n"
                "ServerSignature Off\n"
                "ServerTokens Prod\n"
                "TraceEnable Off\n"
                "LimitRequestBody 102400\n"
                "LimitRequestFields 100\n"
                "ErrorLog logs/error_log\n"
                "CustomLog logs/access_log combined\n"
                'ErrorDocument 404 "/error/404.html"\n'
                'ErrorDocument 500 "/error/500.html"\n'
            ),
            encoding="utf-8",
        )
        result = analyze_apache_config(str(config_path))
        overrides = [
            f for f in result.findings
            if f.rule_id == "apache.htaccess_contains_security_directive"
        ]
        assert len(overrides) == 1
        assert "Header" in overrides[0].title


# ---------------------------------------------------------------------------
# Phase 2.3 bugfixes: AccessFileName scoping + AllowOverride inheritance
# ---------------------------------------------------------------------------


class TestAccessFileNameScoping:
    def test_nested_accessfilename_does_not_affect_siblings(self, tmp_path: Path) -> None:
        """AccessFileName inside <Directory> must not change discovery for other dirs."""
        dir_a = tmp_path / "app"
        dir_a.mkdir()
        (dir_a / ".appaccess").write_text("Options Indexes\n", encoding="utf-8")

        dir_b = tmp_path / "site"
        dir_b.mkdir()
        (dir_b / ".htaccess").write_text("Options Indexes\n", encoding="utf-8")

        config_path = tmp_path / "httpd.conf"
        config_path.write_text(
            f'<Directory "{_posix_path(dir_a)}">\n'
            "    AccessFileName .appaccess\n"
            "    AllowOverride Options\n"
            "</Directory>\n"
            f'<Directory "{_posix_path(dir_b)}">\n'
            "    AllowOverride Options\n"
            "</Directory>\n",
            encoding="utf-8",
        )
        result = discover_htaccess_files(
            parse_apache_config(config_path.read_text(encoding="utf-8")),
            str(config_path),
        )
        # dir_b should find .htaccess (default), not .appaccess
        found_paths = {Path(f.htaccess_path).name for f in result.found}
        assert ".htaccess" in found_paths

    def test_toplevel_accessfilename_applies_to_all(self, tmp_path: Path) -> None:
        """Top-level AccessFileName changes discovery for all directories."""
        dir_a = tmp_path / "www"
        dir_a.mkdir()
        (dir_a / ".override").write_text("Options Indexes\n", encoding="utf-8")

        config_path = tmp_path / "httpd.conf"
        config_path.write_text(
            "AccessFileName .override\n"
            f'<Directory "{_posix_path(dir_a)}">\n'
            "    AllowOverride Options\n"
            "</Directory>\n",
            encoding="utf-8",
        )
        result = discover_htaccess_files(
            parse_apache_config(config_path.read_text(encoding="utf-8")),
            str(config_path),
        )
        assert len(result.found) == 1
        assert Path(result.found[0].htaccess_path).name == ".override"


class TestAllowOverrideInheritance:
    def test_parent_allowoverride_none_blocks_child_docroot(self, tmp_path: Path) -> None:
        """<Directory> AllowOverride None should block .htaccess in child DocumentRoot."""
        parent_dir = tmp_path / "www"
        parent_dir.mkdir()
        child_dir = parent_dir / "site"
        child_dir.mkdir()
        (child_dir / ".htaccess").write_text("Options Indexes\n", encoding="utf-8")

        config_path = tmp_path / "httpd.conf"
        config_path.write_text(
            _with_backup_files_restriction(
                f'<Directory "{_posix_path(parent_dir)}">\n'
                "    AllowOverride None\n"
                "</Directory>\n"
                f'DocumentRoot "{_posix_path(child_dir)}"\n'
                "ServerSignature Off\n"
                "ServerTokens Prod\n"
                "TraceEnable Off\n"
                "LimitRequestBody 102400\n"
                "LimitRequestFields 100\n"
                "ErrorLog logs/error_log\n"
                "CustomLog logs/access_log combined\n"
                'ErrorDocument 404 "/error/404.html"\n'
                'ErrorDocument 500 "/error/500.html"\n'
            ),
            encoding="utf-8",
        )
        result = analyze_apache_config(str(config_path))
        security_findings = [
            f for f in result.findings
            if f.rule_id == "apache.htaccess_contains_security_directive"
        ]
        # Parent <Directory> has AllowOverride None -> child .htaccess should be blocked
        assert len(security_findings) == 0

    def test_parent_allowoverride_all_allows_child_docroot(self, tmp_path: Path) -> None:
        """<Directory> AllowOverride All allows .htaccess in child DocumentRoot."""
        parent_dir = tmp_path / "www"
        parent_dir.mkdir()
        child_dir = parent_dir / "site"
        child_dir.mkdir()
        (child_dir / ".htaccess").write_text("Options Indexes\n", encoding="utf-8")

        config_path = tmp_path / "httpd.conf"
        config_path.write_text(
            _with_backup_files_restriction(
                f'<Directory "{_posix_path(parent_dir)}">\n'
                "    AllowOverride All\n"
                "</Directory>\n"
                f'DocumentRoot "{_posix_path(child_dir)}"\n'
                "ServerSignature Off\n"
                "ServerTokens Prod\n"
                "TraceEnable Off\n"
                "LimitRequestBody 102400\n"
                "LimitRequestFields 100\n"
                "ErrorLog logs/error_log\n"
                "CustomLog logs/access_log combined\n"
                'ErrorDocument 404 "/error/404.html"\n'
                'ErrorDocument 500 "/error/500.html"\n'
            ),
            encoding="utf-8",
        )
        result = analyze_apache_config(str(config_path))
        security_findings = [
            f for f in result.findings
            if f.rule_id == "apache.htaccess_contains_security_directive"
        ]
        assert len(security_findings) == 1

    def test_parent_allowoverride_none_blocks_child_directory(self, tmp_path: Path) -> None:
        """Inherited AllowOverride None should block child Directory .htaccess too."""
        parent_dir = tmp_path / "var"
        parent_dir.mkdir()
        child_dir = parent_dir / "www"
        child_dir.mkdir()
        (child_dir / ".htaccess").write_text(
            "Header unset X-Frame-Options\n",
            encoding="utf-8",
        )

        config_path = tmp_path / "httpd.conf"
        config_path.write_text(
            _with_backup_files_restriction(
                f'<Directory "{_posix_path(parent_dir)}">\n'
                "    AllowOverride None\n"
                "</Directory>\n"
                f'<Directory "{_posix_path(child_dir)}">\n'
                "    Options -Indexes\n"
                "</Directory>\n"
                "ServerSignature Off\n"
                "ServerTokens Prod\n"
                "TraceEnable Off\n"
                "LimitRequestBody 102400\n"
                "LimitRequestFields 100\n"
                "ErrorLog logs/error_log\n"
                "CustomLog logs/access_log combined\n"
                'ErrorDocument 404 "/error/404.html"\n'
                'ErrorDocument 500 "/error/500.html"\n'
            ),
            encoding="utf-8",
        )
        result = analyze_apache_config(str(config_path))
        relevant_ids = {
            finding.rule_id
            for finding in result.findings
            if finding.rule_id in {
                "apache.allowoverride_all_in_directory",
                "apache.htaccess_contains_security_directive",
            }
        }
        assert relevant_ids == set()

    def test_sibling_dir_not_covered_by_prefix_match(self, tmp_path: Path) -> None:
        """/var/www must NOT cover /var/www2 -- path boundary check."""
        www_dir = tmp_path / "www"
        www_dir.mkdir()
        www2_dir = tmp_path / "www2"
        www2_dir.mkdir()
        site_dir = www2_dir / "site"
        site_dir.mkdir()
        (site_dir / ".htaccess").write_text("Options Indexes\n", encoding="utf-8")

        config_path = tmp_path / "httpd.conf"
        config_path.write_text(
            _with_backup_files_restriction(
                f'<Directory "{_posix_path(www_dir)}">\n'
                "    AllowOverride None\n"
                "</Directory>\n"
                f'DocumentRoot "{_posix_path(site_dir)}"\n'
                "ServerSignature Off\n"
                "ServerTokens Prod\n"
                "TraceEnable Off\n"
                "LimitRequestBody 102400\n"
                "LimitRequestFields 100\n"
                "ErrorLog logs/error_log\n"
                "CustomLog logs/access_log combined\n"
                'ErrorDocument 404 "/error/404.html"\n'
                'ErrorDocument 500 "/error/500.html"\n',
                include_cis_allowoverride_root=False,
            ),
            encoding="utf-8",
        )
        result = analyze_apache_config(str(config_path))
        security_findings = [
            f for f in result.findings
            if f.rule_id == "apache.htaccess_contains_security_directive"
        ]
        # /var/www AllowOverride None must NOT block /var/www2/site/.htaccess
        assert len(security_findings) == 1


# ---------------------------------------------------------------------------
# Phase 2.4: Effective config reconstruction
# ---------------------------------------------------------------------------


class TestBuildEffectiveConfig:
    def test_global_directives_only(self) -> None:
        ast = parse_apache_config("ServerTokens Prod\nServerSignature Off\n")
        ec = build_effective_config(ast, "/var/www")
        assert "servertokens" in ec.directives
        assert ec.directives["servertokens"].args == ["Prod"]
        assert ec.directives["servertokens"].origin.layer == "global"

    def test_global_directives_inside_toplevel_ifmodule(self) -> None:
        ast = parse_apache_config(
            "<IfModule mod_core.c>\n"
            "    ServerSignature Off\n"
            "    ServerTokens Prod\n"
            "</IfModule>\n"
        )
        ec = build_effective_config(ast, "/var/www")
        assert ec.directives["serversignature"].args == ["Off"]
        assert ec.directives["serversignature"].origin.layer == "global"
        assert ec.directives["servertokens"].args == ["Prod"]

    def test_directory_overrides_global(self) -> None:
        ast = parse_apache_config(
            "ServerTokens Prod\n"
            '<Directory "/var/www">\n'
            "    ServerTokens Full\n"
            "</Directory>\n"
        )
        ec = build_effective_config(ast, "/var/www")
        assert ec.directives["servertokens"].args == ["Full"]
        assert ec.directives["servertokens"].origin.layer == "directory"
        # Override chain records the global value
        assert len(ec.directives["servertokens"].override_chain) == 1
        assert ec.directives["servertokens"].override_chain[0].layer == "global"

    def test_directory_sorting_shortest_first(self) -> None:
        ast = parse_apache_config(
            '<Directory "/">\n'
            "    Options -Indexes\n"
            "</Directory>\n"
            '<Directory "/var/www">\n'
            "    Options Indexes\n"
            "</Directory>\n"
        )
        ec = build_effective_config(ast, "/var/www")
        # /var/www (longer) applied last -> wins
        assert "indexes" in [a.lower() for a in ec.directives["options"].args]

    def test_options_merge_plus_minus(self) -> None:
        ast = parse_apache_config(
            "Options Indexes FollowSymLinks\n"
            '<Directory "/var/www">\n'
            "    Options -Indexes +ExecCGI\n"
            "</Directory>\n"
        )
        ec = build_effective_config(ast, "/var/www")
        opts = set(ec.directives["options"].args)
        assert "execcgi" in opts
        assert "followsymlinks" in opts
        assert "indexes" not in opts

    def test_options_replace_without_prefix(self) -> None:
        ast = parse_apache_config(
            "Options Indexes FollowSymLinks\n"
            '<Directory "/var/www">\n'
            "    Options None\n"
            "</Directory>\n"
        )
        ec = build_effective_config(ast, "/var/www")
        # Without +/- prefix -> last-wins replacement to an empty Options set.
        assert ec.directives["options"].args == []

    def test_options_none_cleared_before_relative_merge(self, tmp_path: Path) -> None:
        ast = parse_apache_config(
            "Options None\n"
            f'<Directory "{_posix_path(tmp_path)}">\n'
            "    AllowOverride Options\n"
            "</Directory>\n"
        )
        htaccess_ast = parse_apache_config("Options +Indexes\n")
        htf = HtaccessFile(
            directory_path=str(tmp_path),
            htaccess_path=str(tmp_path / ".htaccess"),
            ast=htaccess_ast,
            source_directory_block=ast.nodes[1],
        )
        ec = build_effective_config(ast, str(tmp_path), htaccess_file=htf)
        assert ec.directives["options"].args == ["indexes"]

    def test_htaccess_layer_applied(self, tmp_path: Path) -> None:
        ast = parse_apache_config(
            "Options -Indexes\n"
            f'<Directory "{_posix_path(tmp_path)}">\n'
            "    AllowOverride Options\n"
            "</Directory>\n"
        )
        htaccess_ast = parse_apache_config("Options +Indexes\n")
        htf = HtaccessFile(
            directory_path=str(tmp_path),
            htaccess_path=str(tmp_path / ".htaccess"),
            ast=htaccess_ast,
            source_directory_block=ast.nodes[1],
        )
        ec = build_effective_config(ast, str(tmp_path), htaccess_file=htf)
        opts = set(ec.directives["options"].args)
        assert "indexes" in opts

    def test_htaccess_wrapped_directive_applied(self, tmp_path: Path) -> None:
        ast = parse_apache_config(
            "Options -Indexes\n"
            f'<Directory "{_posix_path(tmp_path)}">\n'
            "    AllowOverride Options\n"
            "</Directory>\n"
        )
        htaccess_ast = parse_apache_config(
            "<IfModule mod_autoindex.c>\n"
            "    Options +Indexes\n"
            "</IfModule>\n"
        )
        htf = HtaccessFile(
            directory_path=str(tmp_path),
            htaccess_path=str(tmp_path / ".htaccess"),
            ast=htaccess_ast,
            source_directory_block=ast.nodes[1],
        )
        ec = build_effective_config(ast, str(tmp_path), htaccess_file=htf)
        opts = set(ec.directives["options"].args)
        assert "indexes" in opts

    def test_htaccess_filtered_by_allowoverride(self, tmp_path: Path) -> None:
        ast = parse_apache_config(
            "Options -Indexes\n"
            f'<Directory "{_posix_path(tmp_path)}">\n'
            "    AllowOverride FileInfo\n"
            "</Directory>\n"
        )
        htaccess_ast = parse_apache_config("Options +Indexes\n")
        htf = HtaccessFile(
            directory_path=str(tmp_path),
            htaccess_path=str(tmp_path / ".htaccess"),
            ast=htaccess_ast,
            source_directory_block=ast.nodes[1],
        )
        ec = build_effective_config(ast, str(tmp_path), htaccess_file=htf)
        # Options not in AllowOverride FileInfo -> filtered out -> no change
        opts = set(ec.directives["options"].args)
        assert "indexes" not in opts

    def test_no_directives(self) -> None:
        ast = parse_apache_config("")
        ec = build_effective_config(ast, "/var/www")
        assert ec.directives == {}

    def test_unrelated_directory_not_applied(self) -> None:
        ast = parse_apache_config(
            "ServerTokens Prod\n"
            '<Directory "/other">\n'
            "    ServerTokens Full\n"
            "</Directory>\n"
        )
        ec = build_effective_config(ast, "/var/www")
        assert ec.directives["servertokens"].args == ["Prod"]


class TestHtaccessWeakensSecurity:
    def test_htaccess_adds_indexes(self, tmp_path: Path) -> None:
        web_dir = tmp_path / "www"
        web_dir.mkdir()
        (web_dir / ".htaccess").write_text("Options +Indexes\n", encoding="utf-8")

        config_path = tmp_path / "httpd.conf"
        config_path.write_text(
            _with_backup_files_restriction(
                "Options -Indexes\n"
                f'<Directory "{_posix_path(web_dir)}">\n'
                "    AllowOverride Options\n"
                "</Directory>\n"
                "ServerSignature Off\n"
                "ServerTokens Prod\n"
                "TraceEnable Off\n"
                "LimitRequestBody 102400\n"
                "LimitRequestFields 100\n"
                "ErrorLog logs/error_log\n"
                "CustomLog logs/access_log combined\n"
                'ErrorDocument 404 "/error/404.html"\n'
                'ErrorDocument 500 "/error/500.html"\n'
            ),
            encoding="utf-8",
        )
        result = analyze_apache_config(str(config_path))
        weakens = [
            f for f in result.findings
            if f.rule_id == "apache.htaccess_weakens_security"
        ]
        assert len(weakens) == 1
        assert "indexes" in weakens[0].title.lower()

    def test_htaccess_no_weakening(self, tmp_path: Path) -> None:
        """Non-dangerous options change should not fire."""
        web_dir = tmp_path / "www"
        web_dir.mkdir()
        (web_dir / ".htaccess").write_text("Header set X-Custom value\n", encoding="utf-8")

        config_path = tmp_path / "httpd.conf"
        config_path.write_text(
            _with_backup_files_restriction(
                "Options -Indexes\n"
                f'<Directory "{_posix_path(web_dir)}">\n'
                "    AllowOverride FileInfo\n"
                "</Directory>\n"
                "ServerSignature Off\n"
                "ServerTokens Prod\n"
                "TraceEnable Off\n"
                "LimitRequestBody 102400\n"
                "LimitRequestFields 100\n"
                "ErrorLog logs/error_log\n"
                "CustomLog logs/access_log combined\n"
                'ErrorDocument 404 "/error/404.html"\n'
                'ErrorDocument 500 "/error/500.html"\n'
            ),
            encoding="utf-8",
        )
        result = analyze_apache_config(str(config_path))
        weakens = [
            f for f in result.findings
            if f.rule_id == "apache.htaccess_weakens_security"
        ]
        assert len(weakens) == 0

    def test_allowoverride_none_blocks_weakening(self, tmp_path: Path) -> None:
        web_dir = tmp_path / "www"
        web_dir.mkdir()
        (web_dir / ".htaccess").write_text("Options +Indexes\n", encoding="utf-8")

        config_path = tmp_path / "httpd.conf"
        config_path.write_text(
            _with_backup_files_restriction(
                "Options -Indexes\n"
                f'<Directory "{_posix_path(web_dir)}">\n'
                "    AllowOverride None\n"
                "</Directory>\n"
                "ServerSignature Off\n"
                "ServerTokens Prod\n"
                "TraceEnable Off\n"
                "LimitRequestBody 102400\n"
                "LimitRequestFields 100\n"
                "ErrorLog logs/error_log\n"
                "CustomLog logs/access_log combined\n"
                'ErrorDocument 404 "/error/404.html"\n'
                'ErrorDocument 500 "/error/500.html"\n'
            ),
            encoding="utf-8",
        )
        result = analyze_apache_config(str(config_path))
        weakens = [
            f for f in result.findings
            if f.rule_id == "apache.htaccess_weakens_security"
        ]
        assert len(weakens) == 0

    def test_htaccess_adds_execcgi(self, tmp_path: Path) -> None:
        web_dir = tmp_path / "www"
        web_dir.mkdir()
        (web_dir / ".htaccess").write_text("Options +ExecCGI\n", encoding="utf-8")

        config_path = tmp_path / "httpd.conf"
        config_path.write_text(
            _with_backup_files_restriction(
                f'<Directory "{_posix_path(web_dir)}">\n'
                "    AllowOverride Options\n"
                "</Directory>\n"
                "ServerSignature Off\n"
                "ServerTokens Prod\n"
                "TraceEnable Off\n"
                "LimitRequestBody 102400\n"
                "LimitRequestFields 100\n"
                "ErrorLog logs/error_log\n"
                "CustomLog logs/access_log combined\n"
                'ErrorDocument 404 "/error/404.html"\n'
                'ErrorDocument 500 "/error/500.html"\n'
            ),
            encoding="utf-8",
        )
        result = analyze_apache_config(str(config_path))
        weakens = [
            f for f in result.findings
            if f.rule_id == "apache.htaccess_weakens_security"
        ]
        assert len(weakens) == 1
        assert "execcgi" in weakens[0].title.lower()

    def test_wrapped_htaccess_directive_weakens_security(self, tmp_path: Path) -> None:
        web_dir = tmp_path / "www"
        web_dir.mkdir()
        (web_dir / ".htaccess").write_text(
            "<IfModule mod_autoindex.c>\n"
            "    Options +Indexes\n"
            "</IfModule>\n",
            encoding="utf-8",
        )

        config_path = tmp_path / "httpd.conf"
        config_path.write_text(
            _with_backup_files_restriction(
                "Options -Indexes\n"
                f'<Directory "{_posix_path(web_dir)}">\n'
                "    AllowOverride Options\n"
                "</Directory>\n"
                "ServerSignature Off\n"
                "ServerTokens Prod\n"
                "TraceEnable Off\n"
                "LimitRequestBody 102400\n"
                "LimitRequestFields 100\n"
                "ErrorLog logs/error_log\n"
                "CustomLog logs/access_log combined\n"
                'ErrorDocument 404 "/error/404.html"\n'
                'ErrorDocument 500 "/error/500.html"\n'
            ),
            encoding="utf-8",
        )
        result = analyze_apache_config(str(config_path))
        weakens = [
            f for f in result.findings
            if f.rule_id == "apache.htaccess_weakens_security"
        ]
        assert len(weakens) == 1
        assert "indexes" in weakens[0].title.lower()

    def test_toplevel_ifmodule_baseline_enables_serversignature_override_detection(
        self,
    ) -> None:
        config_ast = parse_apache_config(
            "<IfModule mod_core.c>\n"
            "    ServerSignature Off\n"
            "</IfModule>\n"
        )
        htaccess_ast = parse_apache_config("ServerSignature On\n")
        htaccess_file = HtaccessFile(
            directory_path="/var/www",
            htaccess_path="/var/www/.htaccess",
            ast=htaccess_ast,
            source_directory_block=None,
        )

        findings = find_htaccess_weakens_security(config_ast, [htaccess_file])
        assert len(findings) == 1
        assert findings[0].rule_id == "apache.htaccess_weakens_security"
        assert "serversignature" in findings[0].title.lower()

    def test_override_chain_tracked(self, tmp_path: Path) -> None:
        """Effective config records the override chain."""
        ast = parse_apache_config(
            "ServerTokens Prod\n"
            f'<Directory "{_posix_path(tmp_path)}">\n'
            "    ServerTokens Full\n"
            "    AllowOverride All\n"
            "</Directory>\n"
        )
        ec = build_effective_config(ast, str(tmp_path))
        st = ec.directives["servertokens"]
        assert st.args == ["Full"]
        assert len(st.override_chain) == 1
        assert st.override_chain[0].layer == "global"


class TestHtaccessRulePack:
    def test_htaccess_disables_security_headers(self, tmp_path: Path) -> None:
        result, _ = _analyze_with_htaccess(
            tmp_path,
            "Header unset X-Frame-Options\n",
            allowoverride="FileInfo",
        )
        findings = [
            f
            for f in result.findings
            if f.rule_id == "apache.htaccess_disables_security_headers"
        ]
        assert len(findings) == 1
        assert "x-frame-options" in findings[0].title.lower()

    def test_htaccess_disables_security_headers_blocked_by_allowoverride(
        self,
        tmp_path: Path,
    ) -> None:
        result, _ = _analyze_with_htaccess(
            tmp_path,
            "Header unset X-Frame-Options\n",
            allowoverride="Options",
        )
        findings = [
            f
            for f in result.findings
            if f.rule_id == "apache.htaccess_disables_security_headers"
        ]
        assert findings == []

    def test_htaccess_enables_cgi(self, tmp_path: Path) -> None:
        result, _ = _analyze_with_htaccess(
            tmp_path,
            "Options +ExecCGI\n",
            allowoverride="Options",
        )
        findings = [
            f for f in result.findings if f.rule_id == "apache.htaccess_enables_cgi"
        ]
        assert len(findings) == 1

    def test_htaccess_options_all_enables_cgi(self, tmp_path: Path) -> None:
        result, _ = _analyze_with_htaccess(
            tmp_path,
            "Options All\n",
            allowoverride="Options",
        )
        findings = [
            f for f in result.findings if f.rule_id == "apache.htaccess_enables_cgi"
        ]
        assert len(findings) == 1

    def test_htaccess_enables_cgi_blocked_by_allowoverride(self, tmp_path: Path) -> None:
        result, _ = _analyze_with_htaccess(
            tmp_path,
            "Options +ExecCGI\n",
            allowoverride="FileInfo",
        )
        findings = [
            f for f in result.findings if f.rule_id == "apache.htaccess_enables_cgi"
        ]
        assert findings == []

    def test_htaccess_enables_directory_listing(self, tmp_path: Path) -> None:
        result, _ = _analyze_with_htaccess(
            tmp_path,
            "Options +Indexes\n",
            allowoverride="Options",
        )
        findings = [
            f
            for f in result.findings
            if f.rule_id == "apache.htaccess_enables_directory_listing"
        ]
        assert len(findings) == 1

    def test_htaccess_options_all_enables_directory_listing(self, tmp_path: Path) -> None:
        result, _ = _analyze_with_htaccess(
            tmp_path,
            "Options All\n",
            allowoverride="Options",
        )
        findings = [
            f
            for f in result.findings
            if f.rule_id == "apache.htaccess_enables_directory_listing"
        ]
        assert len(findings) == 1

    def test_htaccess_enables_directory_listing_blocked_by_allowoverride(
        self,
        tmp_path: Path,
    ) -> None:
        result, _ = _analyze_with_htaccess(
            tmp_path,
            "Options +Indexes\n",
            allowoverride="FileInfo",
        )
        findings = [
            f
            for f in result.findings
            if f.rule_id == "apache.htaccess_enables_directory_listing"
        ]
        assert findings == []

    def test_htaccess_rewrite_without_limit(self, tmp_path: Path) -> None:
        result, _ = _analyze_with_htaccess(
            tmp_path,
            "RewriteEngine On\nRewriteRule ^foo$ /bar [R=302,L]\n",
            allowoverride="FileInfo",
        )
        findings = [
            f
            for f in result.findings
            if f.rule_id == "apache.htaccess_rewrite_without_limit"
        ]
        assert len(findings) == 1

    def test_htaccess_rewrite_with_condition_not_reported(self, tmp_path: Path) -> None:
        result, _ = _analyze_with_htaccess(
            tmp_path,
            (
                "RewriteEngine On\n"
                "RewriteCond %{REQUEST_URI} ^/foo$\n"
                "RewriteRule ^foo$ /bar [R=302,L]\n"
            ),
            allowoverride="FileInfo",
        )
        findings = [
            f
            for f in result.findings
            if f.rule_id == "apache.htaccess_rewrite_without_limit"
        ]
        assert findings == []

    def test_directory_without_allowoverride(self, tmp_path: Path) -> None:
        config_path = tmp_path / "httpd.conf"
        config_path.write_text(
            _with_backup_files_restriction(
                "\n".join(
                    [
                        "ServerSignature Off",
                        "ServerTokens Prod",
                        "TraceEnable Off",
                        "LimitRequestBody 102400",
                        "LimitRequestFields 100",
                        "ErrorLog logs/error_log",
                        "CustomLog logs/access_log combined",
                        'ErrorDocument 404 "/error/404.html"',
                        'ErrorDocument 500 "/error/500.html"',
                        f'<Directory "{_posix_path(tmp_path / "www")}">',
                        "    Options -Indexes",
                        "</Directory>",
                    ]
                ),
                include_cis_allowoverride_root=False,
            ),
            encoding="utf-8",
        )
        result = analyze_apache_config(str(config_path))
        findings = [
            f
            for f in result.findings
            if f.rule_id == "apache.directory_without_allowoverride"
        ]
        assert len(findings) == 1

    def test_directory_without_allowoverride_inherits_parent_none_reported(
        self,
        tmp_path: Path,
    ) -> None:
        config_path = tmp_path / "httpd.conf"
        parent_dir = _posix_path(tmp_path / "www")
        child_dir = _posix_path(tmp_path / "www" / "app")
        config_path.write_text(
            _with_backup_files_restriction(
                "\n".join(
                    [
                        "ServerSignature Off",
                        "ServerTokens Prod",
                        "TraceEnable Off",
                        "LimitRequestBody 102400",
                        "LimitRequestFields 100",
                        "ErrorLog logs/error_log",
                        "CustomLog logs/access_log combined",
                        'ErrorDocument 404 "/error/404.html"',
                        'ErrorDocument 500 "/error/500.html"',
                        f'<Directory "{parent_dir}">',
                        "    AllowOverride None",
                        "</Directory>",
                        f'<Directory "{child_dir}">',
                        "    Options -Indexes",
                        "</Directory>",
                    ]
                ),
                include_cis_allowoverride_root=False,
            ),
            encoding="utf-8",
        )
        result = analyze_apache_config(str(config_path))
        findings = [
            f
            for f in result.findings
            if f.rule_id == "apache.directory_without_allowoverride"
        ]
        assert len(findings) == 1
        assert findings[0].location is not None
        assert findings[0].location.line == 13

    def test_directory_with_explicit_allowoverride_not_reported(
        self,
        tmp_path: Path,
    ) -> None:
        config_path = tmp_path / "httpd.conf"
        config_path.write_text(
            _with_backup_files_restriction(
                "\n".join(
                    [
                        "ServerSignature Off",
                        "ServerTokens Prod",
                        "TraceEnable Off",
                        "LimitRequestBody 102400",
                        "LimitRequestFields 100",
                        "ErrorLog logs/error_log",
                        "CustomLog logs/access_log combined",
                        'ErrorDocument 404 "/error/404.html"',
                        'ErrorDocument 500 "/error/500.html"',
                        f'<Directory "{_posix_path(tmp_path / "www")}">',
                        "    AllowOverride None",
                        "    Options -Indexes",
                        "</Directory>",
                    ]
                )
            ),
            encoding="utf-8",
        )
        result = analyze_apache_config(str(config_path))
        findings = [
            f
            for f in result.findings
            if f.rule_id == "apache.directory_without_allowoverride"
        ]
        assert findings == []

    def test_directory_with_allowoverride_inside_ifmodule_not_reported(
        self,
        tmp_path: Path,
    ) -> None:
        config_path = tmp_path / "httpd.conf"
        config_path.write_text(
            _with_backup_files_restriction(
                "\n".join(
                    [
                        "ServerSignature Off",
                        "ServerTokens Prod",
                        "TraceEnable Off",
                        "LimitRequestBody 102400",
                        "LimitRequestFields 100",
                        "ErrorLog logs/error_log",
                        "CustomLog logs/access_log combined",
                        'ErrorDocument 404 "/error/404.html"',
                        'ErrorDocument 500 "/error/500.html"',
                        f'<Directory "{_posix_path(tmp_path / "www")}">',
                        "    <IfModule mod_authz_core.c>",
                        "        AllowOverride None",
                        "    </IfModule>",
                        "    Options -Indexes",
                        "</Directory>",
                    ]
                )
            ),
            encoding="utf-8",
        )
        result = analyze_apache_config(str(config_path))
        findings = [
            f
            for f in result.findings
            if f.rule_id == "apache.directory_without_allowoverride"
        ]
        assert findings == []

    def test_root_directory_without_allowoverride_is_not_reported_by_explicitness_rule(
        self,
        tmp_path: Path,
    ) -> None:
        config_path = tmp_path / "httpd.conf"
        config_path.write_text(
            _with_backup_files_restriction(
                "\n".join(
                    [
                        "ServerSignature Off",
                        "ServerTokens Prod",
                        "TraceEnable Off",
                        "LimitRequestBody 102400",
                        "LimitRequestFields 100",
                        "ErrorLog logs/error_log",
                        "CustomLog logs/access_log combined",
                        'ErrorDocument 404 "/error/404.html"',
                        'ErrorDocument 500 "/error/500.html"',
                        "<Directory />",
                        "    Options None",
                        "</Directory>",
                        f'<Directory "{_posix_path(tmp_path / "www")}">',
                        "    AllowOverride None",
                        "    Options -Indexes",
                        "</Directory>",
                    ]
                ),
                include_cis_allowoverride_root=False,
                include_cis_root_options=False,
            ),
            encoding="utf-8",
        )
        result = analyze_apache_config(str(config_path))
        findings = [
            f
            for f in result.findings
            if f.rule_id == "apache.directory_without_allowoverride"
        ]
        assert findings == []

    def test_htaccess_auth_without_require(self, tmp_path: Path) -> None:
        result, _ = _analyze_with_htaccess(
            tmp_path,
            'AuthType Basic\nAuthName "Restricted"\n',
            allowoverride="AuthConfig",
        )
        findings = [
            f
            for f in result.findings
            if f.rule_id == "apache.htaccess_auth_without_require"
        ]
        assert len(findings) == 1

    def test_htaccess_auth_with_require_not_reported(self, tmp_path: Path) -> None:
        result, _ = _analyze_with_htaccess(
            tmp_path,
            'AuthType Basic\nAuthName "Restricted"\nRequire valid-user\n',
            allowoverride="AuthConfig",
        )
        findings = [
            f
            for f in result.findings
            if f.rule_id == "apache.htaccess_auth_without_require"
        ]
        assert findings == []
