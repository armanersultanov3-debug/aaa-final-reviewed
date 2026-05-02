from tests.apache_helpers import (
    ALL_OVERRIDE_CATEGORIES,
    Path,
    analyze_apache_config,
    build_effective_config,
    build_server_effective_config,
    discover_htaccess_files,
    extract_allowoverride,
    extract_virtualhost_contexts,
    parse_apache_config,
    select_applicable_virtualhosts,
    _make_vh_override_config,
    _posix_path,
    _with_backup_files_restriction,
)

def test_extract_virtualhost_contexts_reads_server_names_and_aliases() -> None:
    ast = parse_apache_config(
        "<VirtualHost *:80>\n"
        "    ServerName example.test\n"
        "    ServerAlias www.example.test api.example.test\n"
        "</VirtualHost>\n"
        "<IfModule mod_ssl.c>\n"
        "    <VirtualHost *:443>\n"
        "    </VirtualHost>\n"
        "</IfModule>\n"
    )

    contexts = extract_virtualhost_contexts(ast)

    assert len(contexts) == 2
    assert contexts[0].server_name == "example.test"
    assert contexts[0].server_aliases == ["www.example.test", "api.example.test"]
    assert contexts[0].listen_address == "*:80"
    assert contexts[0].optional_ancestor_names == ()
    assert contexts[1].server_name is None
    assert contexts[1].listen_address == "*:443"
    assert contexts[1].optional_ancestor_names == ("ifmodule",)


def test_select_applicable_virtualhosts_matches_serveralias() -> None:
    ast = parse_apache_config(
        "<VirtualHost *:80>\n"
        "    ServerName example.test\n"
        "    ServerAlias www.example.test api.example.test\n"
        "</VirtualHost>\n"
        "<VirtualHost *:80>\n"
        "    ServerName admin.example.test\n"
        "</VirtualHost>\n"
    )

    contexts = extract_virtualhost_contexts(ast)
    selected = select_applicable_virtualhosts(contexts, target_host="api.example.test")

    assert len(selected) == 1
    assert selected[0].server_name == "example.test"


def test_build_server_effective_config_applies_virtualhost_override() -> None:
    ast = parse_apache_config(
        "ServerTokens Prod\n"
        "<VirtualHost *:80>\n"
        "    ServerName example.test\n"
        "    ServerTokens Full\n"
        "</VirtualHost>\n"
    )

    context = extract_virtualhost_contexts(ast)[0]
    effective = build_server_effective_config(ast, virtualhost_context=context)

    assert effective.directives["servertokens"].args == ["Full"]
    assert effective.directives["servertokens"].origin.layer == "virtualhost:example.test"


def test_build_effective_config_applies_location_after_directory() -> None:
    ast = parse_apache_config(
        "Options -Indexes\n"
        '<Directory "/var/www">\n'
        "    Options -Indexes\n"
        "</Directory>\n"
        '<Location "/admin">\n'
        "    Options +Indexes\n"
        "</Location>\n"
    )

    effective = build_effective_config(ast, "/var/www", location_path="/admin")

    assert "indexes" in set(effective.directives["options"].args)
    assert effective.directives["options"].origin.layer == "location:/admin"


def test_build_effective_config_accumulates_header_directives() -> None:
    ast = parse_apache_config(
        "Header set X-Frame-Options DENY\n"
        "<VirtualHost *:80>\n"
        "    ServerName example.test\n"
        "    Header append X-Frame-Options SAMEORIGIN\n"
        "    Header set Strict-Transport-Security max-age=31536000\n"
        "</VirtualHost>\n"
    )

    context = extract_virtualhost_contexts(ast)[0]
    effective = build_effective_config(
        ast,
        "/var/www",
        virtualhost_context=context,
    )

    header_args = effective.directives["header"].args
    assert isinstance(header_args[0], list)
    assert ["set", "X-Frame-Options", "DENY"] in header_args
    assert ["append", "X-Frame-Options", "SAMEORIGIN"] in header_args
    assert ["set", "Strict-Transport-Security", "max-age=31536000"] in header_args


def test_analyze_apache_config_reports_virtualhost_specific_server_tokens(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "\n".join(
                [
                    "ServerSignature Off",
                    "TraceEnable Off",
                    "ServerTokens Prod",
                    "LimitRequestBody 102400",
                    "LimitRequestFields 100",
                    "ErrorLog logs/error_log",
                    "CustomLog logs/access_log combined",
                    "ErrorDocument 404 /custom404.html",
                    "ErrorDocument 500 /custom500.html",
                    "<VirtualHost *:80>",
                    "    ServerName example.test",
                    "</VirtualHost>",
                    "<VirtualHost *:80>",
                    "    ServerName admin.example.test",
                    "    ServerTokens Full",
                    "</VirtualHost>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))
    findings = [
        finding
        for finding in result.findings
        if finding.rule_id == "apache.server_tokens_not_prod"
    ]

    assert result.issues == []
    assert len(findings) == 1
    assert findings[0].location is not None
    assert findings[0].location.file_path == str(config_path)
    assert findings[0].location.line == 15


def test_analyze_apache_config_describes_inherited_virtualhost_server_tokens(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "\n".join(
                [
                    "ServerSignature Off",
                    "TraceEnable Off",
                    "ServerTokens Full",
                    "LimitRequestBody 102400",
                    "LimitRequestFields 100",
                    "ErrorLog logs/error_log",
                    "CustomLog logs/access_log combined",
                    "ErrorDocument 404 /custom404.html",
                    "ErrorDocument 500 /custom500.html",
                    "<VirtualHost *:80>",
                    "    ServerName inherited.example.test",
                    "</VirtualHost>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))
    findings = [
        finding
        for finding in result.findings
        if finding.rule_id == "apache.server_tokens_not_prod"
    ]

    assert result.issues == []
    assert len(findings) == 1
    # Assert the *semantic* parts of the description (directive name,
    # offending value, scope) instead of the whole sentence -- a harmless
    # rewording of the human-readable text would otherwise break the
    # test without any actual regression in rule behaviour.
    description = findings[0].description
    assert "ServerTokens" in description
    assert "Full" in description
    assert "inherits" in description
    assert "global scope" in description


def test_analyze_apache_config_reports_options_includes_in_location_block(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "\n".join(
                [
                    "ServerSignature Off",
                    "TraceEnable Off",
                    "ServerTokens Prod",
                    "LimitRequestBody 102400",
                    "LimitRequestFields 100",
                    "ErrorLog logs/error_log",
                    "CustomLog logs/access_log combined",
                    "ErrorDocument 404 /custom404.html",
                    "ErrorDocument 500 /custom500.html",
                    '<Location "/admin">',
                    "    Options Includes",
                    "</Location>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))
    findings = [
        finding
        for finding in result.findings
        if finding.rule_id == "apache.options_includes_enabled"
    ]

    assert result.issues == []
    assert len(findings) == 1
    assert findings[0].location is not None
    assert findings[0].location.file_path == str(config_path)
    assert findings[0].location.line == 11


# --- Block 2: analysis context tests ---


def test_analysis_contexts_global_when_no_virtualhost(tmp_path: Path) -> None:
    """Config without VirtualHost produces a single global analysis context."""
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "\n".join([
                "ServerSignature Off",
                "ServerTokens Prod",
                "TraceEnable Off",
                "LimitRequestBody 102400",
                "LimitRequestFields 100",
                "ErrorLog logs/error_log",
                "CustomLog logs/access_log combined",
                "ErrorDocument 404 /custom404.html",
                "ErrorDocument 500 /custom500.html",
            ])
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))
    contexts = result.metadata.get("analysis_contexts")
    assert contexts is not None
    assert len(contexts) == 1
    assert contexts[0]["label"] == "global"
    assert contexts[0]["virtualhost"] is False


def test_analysis_contexts_per_virtualhost(tmp_path: Path) -> None:
    """Config with two VirtualHosts produces two analysis contexts."""
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "\n".join([
                "ServerSignature Off",
                "ServerTokens Prod",
                "TraceEnable Off",
                "LimitRequestBody 102400",
                "LimitRequestFields 100",
                "ErrorLog logs/error_log",
                "CustomLog logs/access_log combined",
                "ErrorDocument 404 /custom404.html",
                "ErrorDocument 500 /custom500.html",
                "<VirtualHost *:80>",
                "    ServerName alpha.test",
                f'    DocumentRoot "{_posix_path(tmp_path / "alpha")}"',
                "</VirtualHost>",
                "<VirtualHost *:80>",
                "    ServerName beta.test",
                f'    DocumentRoot "{_posix_path(tmp_path / "beta")}"',
                "</VirtualHost>",
            ])
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))
    contexts = result.metadata.get("analysis_contexts")
    assert contexts is not None
    assert len(contexts) == 2
    labels = {ctx["label"] for ctx in contexts}
    assert labels == {"alpha.test", "beta.test"}
    for ctx in contexts:
        assert ctx["virtualhost"] is True


def test_virtualhost_specific_document_root_changes_htaccess_discovery(
    tmp_path: Path,
) -> None:
    """Htaccess under VH-specific DocumentRoot is associated with that context."""
    alpha_dir = tmp_path / "alpha"
    alpha_dir.mkdir()
    (alpha_dir / ".htaccess").write_text("Options +Indexes\n", encoding="utf-8")

    beta_dir = tmp_path / "beta"
    beta_dir.mkdir()

    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "\n".join([
                "ServerSignature Off",
                "ServerTokens Prod",
                "TraceEnable Off",
                "LimitRequestBody 102400",
                "LimitRequestFields 100",
                "ErrorLog logs/error_log",
                "CustomLog logs/access_log combined",
                "ErrorDocument 404 /custom404.html",
                "ErrorDocument 500 /custom500.html",
                "<VirtualHost *:80>",
                "    ServerName alpha.test",
                f'    DocumentRoot "{_posix_path(alpha_dir)}"',
                f'    <Directory "{_posix_path(alpha_dir)}">',
                "        AllowOverride All",
                "    </Directory>",
                "</VirtualHost>",
                "<VirtualHost *:80>",
                "    ServerName beta.test",
                f'    DocumentRoot "{_posix_path(beta_dir)}"',
                "</VirtualHost>",
            ])
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))
    contexts = result.metadata["analysis_contexts"]
    alpha_ctx = next(c for c in contexts if c["label"] == "alpha.test")
    beta_ctx = next(c for c in contexts if c["label"] == "beta.test")
    assert alpha_ctx["htaccess_count"] == 1
    assert beta_ctx["htaccess_count"] == 0


def test_global_server_status_overridden_in_all_virtualhosts_no_false_positive(
    tmp_path: Path,
) -> None:
    """Global permissive Location is overridden safely in each VirtualHost."""
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "\n".join([
                "ServerSignature Off",
                "ServerTokens Prod",
                "TraceEnable Off",
                "LimitRequestBody 102400",
                "LimitRequestFields 100",
                "ErrorLog logs/error_log",
                "CustomLog logs/access_log combined",
                "ErrorDocument 404 /custom404.html",
                "ErrorDocument 500 /custom500.html",
                '<Location "/server-status">',
                "    SetHandler server-status",
                "</Location>",
                "<VirtualHost *:80>",
                "    ServerName site1.test",
                '    <Location "/server-status">',
                "        SetHandler server-status",
                "        Require ip 127.0.0.1",
                "    </Location>",
                "</VirtualHost>",
                "<VirtualHost *:80>",
                "    ServerName site2.test",
                '    <Location "/server-status">',
                "        SetHandler server-status",
                "        Require ip 10.0.0.0/8",
                "    </Location>",
                "</VirtualHost>",
            ])
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))
    server_status_findings = [
        f for f in result.findings
        if f.rule_id == "apache.server_status_exposed"
    ]
    assert server_status_findings == []


def test_options_indexes_vh_override_suppresses_finding(tmp_path: Path) -> None:
    """Global <Directory> has Options Indexes but VH overrides with -Indexes.

    The effective-config-aware rule should NOT report a finding because
    the VH override disables directory listing in the effective scope.
    """
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "\n".join([
                "ServerSignature Off",
                "TraceEnable Off",
                "ServerTokens Prod",
                "LimitRequestBody 102400",
                "LimitRequestFields 100",
                "ErrorLog logs/error_log",
                "CustomLog logs/access_log combined",
                'ErrorDocument 404 "/error/404.html"',
                'ErrorDocument 500 "/error/500.html"',
                '<Directory "/var/www/html">',
                "    Options Indexes",
                "</Directory>",
                "<VirtualHost *:80>",
                "    ServerName safe.test",
                '    <Directory "/var/www/html">',
                "        Options -Indexes",
                "    </Directory>",
                "</VirtualHost>",
            ])
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))
    index_findings = [
        f for f in result.findings if f.rule_id == "apache.options_indexes"
    ]
    assert index_findings == []


# --- Block 3/5 regression: VH effective override suppresses Options-family ---

def test_options_includes_vh_override_suppresses_finding(tmp_path: Path) -> None:
    """VH overrides global Options Includes with -Includes -> no finding."""
    config = _make_vh_override_config(
        tmp_path,
        global_options="Options Includes",
        vh_options="Options -Includes",
    )
    result = analyze_apache_config(config)
    findings = [f for f in result.findings if f.rule_id == "apache.options_includes_enabled"]
    assert findings == [], (
        "Regression: options_includes_enabled fires despite VH -Includes override."
    )


def test_options_execcgi_vh_override_suppresses_finding(tmp_path: Path) -> None:
    """VH overrides global Options ExecCGI with -ExecCGI -> no finding."""
    config = _make_vh_override_config(
        tmp_path,
        global_options="Options ExecCGI",
        vh_options="Options -ExecCGI",
    )
    result = analyze_apache_config(config)
    findings = [f for f in result.findings if f.rule_id == "apache.options_execcgi_enabled"]
    assert findings == [], (
        "Regression: options_execcgi_enabled fires despite VH -ExecCGI override."
    )


def test_options_multiviews_vh_override_suppresses_finding(tmp_path: Path) -> None:
    """VH overrides global Options MultiViews with -MultiViews -> no finding."""
    config = _make_vh_override_config(
        tmp_path,
        global_options="Options MultiViews",
        vh_options="Options -MultiViews",
    )
    result = analyze_apache_config(config)
    findings = [f for f in result.findings if f.rule_id == "apache.options_multiviews_enabled"]
    assert findings == [], (
        "Regression: options_multiviews_enabled fires despite VH -MultiViews override."
    )


def test_index_options_fancyindexing_vh_override_suppresses_finding(tmp_path: Path) -> None:
    """VH overrides global IndexOptions FancyIndexing -> no finding."""
    config = _make_vh_override_config(
        tmp_path,
        global_options="IndexOptions FancyIndexing",
        vh_options="IndexOptions -FancyIndexing",
    )
    result = analyze_apache_config(config)
    findings = [
        f for f in result.findings
        if f.rule_id == "apache.index_options_fancyindexing_enabled"
    ]
    assert findings == [], (
        "Regression: index_options_fancyindexing_enabled fires despite VH override."
    )


def test_index_options_scanhtmltitles_vh_override_suppresses_finding(tmp_path: Path) -> None:
    """VH overrides global IndexOptions ScanHTMLTitles -> no finding."""
    config = _make_vh_override_config(
        tmp_path,
        global_options="IndexOptions ScanHTMLTitles",
        vh_options="IndexOptions -ScanHTMLTitles",
    )
    result = analyze_apache_config(config)
    findings = [
        f for f in result.findings
        if f.rule_id == "apache.index_options_scanhtmltitles_enabled"
    ]
    assert findings == [], (
        "Regression: index_options_scanhtmltitles_enabled fires despite VH override."
    )


def test_htaccess_discovery_prefers_later_same_path_allowoverride_block(
    tmp_path: Path,
) -> None:
    """Later same-path Directory blocks should win for AllowOverride inheritance."""
    web_dir = tmp_path / "www"
    web_dir.mkdir()
    (web_dir / ".htaccess").write_text("Options +Indexes\n", encoding="utf-8")

    config = parse_apache_config(
        f'<Directory "{_posix_path(web_dir)}">\n'
        "    AllowOverride None\n"
        "</Directory>\n"
        f'<Directory "{_posix_path(web_dir)}">\n'
        "    AllowOverride All\n"
        "</Directory>\n"
    )
    result = discover_htaccess_files(config, str(tmp_path / "httpd.conf"))

    assert len(result.found) == 1
    source_block = result.found[0].source_directory_block
    assert source_block is not None
    assert extract_allowoverride(source_block) == ALL_OVERRIDE_CATEGORIES


def test_global_directory_findings_still_fire_when_virtualhosts_exist(tmp_path: Path) -> None:
    """Global Directory directives must still be evaluated in each VH effective view."""
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "\n".join([
                "ServerSignature Off",
                "TraceEnable Off",
                "ServerTokens Prod",
                "LimitRequestBody 102400",
                "LimitRequestFields 100",
                "ErrorLog logs/error_log",
                "CustomLog logs/access_log combined",
                'ErrorDocument 404 "/error/404.html"',
                'ErrorDocument 500 "/error/500.html"',
                '<Directory "/var/www/html">',
                "    Options Indexes Includes",
                "    IndexOptions FancyIndexing ScanHTMLTitles",
                "</Directory>",
                "<VirtualHost *:80>",
                "    ServerName demo.test",
                '    DocumentRoot "/var/www/html"',
                "</VirtualHost>",
            ])
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))
    rule_ids = {finding.rule_id for finding in result.findings}

    assert "apache.options_indexes" in rule_ids
    assert "apache.options_includes_enabled" in rule_ids
    assert "apache.index_options_fancyindexing_enabled" in rule_ids
    assert "apache.index_options_scanhtmltitles_enabled" in rule_ids


def test_options_indexes_negative_token_wins_when_mixed(tmp_path: Path) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "\n".join(
                [
                    '<Directory "/var/www/html">',
                    "    AllowOverride None",
                    "    Options Indexes -Indexes",
                    "</Directory>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert not any(f.rule_id == "apache.options_indexes" for f in result.findings)
