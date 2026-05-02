from tests.apache_helpers import (
    Path,
    analyze_apache_config,
    _with_backup_files_restriction,
)

def test_analyze_apache_config_does_not_report_options_indexes_when_disabled(tmp_path: Path) -> None:
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
                    '<Directory "/var/www/html">',
                    "    AllowOverride None",
                    "    Options -Indexes",
                    "</Directory>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert result.findings == []


def test_analyze_apache_config_reports_options_indexes_in_directory(tmp_path: Path) -> None:
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
                    '<Directory "/var/www/html">',
                    "    AllowOverride None",
                    "    Options Indexes",
                    "</Directory>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "apache.options_indexes"
    assert finding.title == "Directory indexing enabled"


def test_analyze_apache_config_reports_mixed_options_indexes_in_directory(tmp_path: Path) -> None:
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
                    '<Directory "/var/www/html">',
                    "    AllowOverride None",
                    "    Options FollowSymLinks Indexes",
                    "</Directory>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "apache.options_indexes"
    assert finding.title == "Directory indexing enabled"


def test_analyze_apache_config_reports_options_plus_execcgi_in_directory(tmp_path: Path) -> None:
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
                    '<Directory "/var/www/html/cgi-bin">',
                    "    AllowOverride None",
                    "    Options +ExecCGI",
                    "</Directory>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "apache.options_execcgi_enabled"
    assert finding.title == "ExecCGI enabled via Options"
    assert finding.location is not None
    assert finding.location.file_path == str(config_path)
    assert finding.location.line == 12


def test_analyze_apache_config_reports_options_execcgi_in_directory(tmp_path: Path) -> None:
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
                    '<Directory "/var/www/html/cgi-bin">',
                    "    AllowOverride None",
                    "    Options ExecCGI",
                    "</Directory>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "apache.options_execcgi_enabled"
    assert finding.title == "ExecCGI enabled via Options"


def test_analyze_apache_config_reports_options_execcgi_in_virtual_host(tmp_path: Path) -> None:
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
                    "    Options Indexes ExecCGI",
                    "</VirtualHost>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    execcgi_findings = [
        f for f in result.findings if f.rule_id == "apache.options_execcgi_enabled"
    ]
    assert len(execcgi_findings) == 1
    finding = execcgi_findings[0]
    assert finding.title == "ExecCGI enabled via Options"
    assert finding.location is not None
    assert finding.location.line == 11


def test_analyze_apache_config_does_not_report_options_execcgi_when_absent(tmp_path: Path) -> None:
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
                    '<Directory "/var/www/html/cgi-bin">',
                    "    AllowOverride None",
                    "    Require all granted",
                    "</Directory>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert result.findings == []


def test_analyze_apache_config_does_not_report_safe_options_without_execcgi(
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
                    "    Options FollowSymLinks SymLinksIfOwnerMatch",
                    "</VirtualHost>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    apache_findings = [f for f in result.findings if f.rule_id.startswith("apache.")]
    assert apache_findings == []


def test_analyze_apache_config_does_not_report_options_minus_execcgi_in_directory(
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
                    '<Directory "/var/www/html/cgi-bin">',
                    "    AllowOverride None",
                    "    Options -ExecCGI",
                    "</Directory>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert result.findings == []


def test_analyze_apache_config_does_not_report_options_includes_when_absent(
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
                    '<Directory "/var/www/html">',
                    "    AllowOverride None",
                    "    Options FollowSymLinks SymLinksIfOwnerMatch",
                    "</Directory>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert result.findings == []


def test_analyze_apache_config_reports_options_indexes_includes_in_directory(
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
                    '<Directory "/var/www/html">',
                    "    AllowOverride None",
                    "    Options Indexes Includes",
                    "</Directory>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    includes_findings = [
        finding
        for finding in result.findings
        if finding.rule_id == "apache.options_includes_enabled"
    ]

    assert result.issues == []
    assert len(includes_findings) == 1
    assert includes_findings[0].title == "Includes enabled via Options"


def test_analyze_apache_config_reports_options_includes_in_directory(tmp_path: Path) -> None:
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
                    '<Directory "/var/www/html">',
                    "    AllowOverride None",
                    "    Options Includes",
                    "</Directory>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "apache.options_includes_enabled"
    assert finding.title == "Includes enabled via Options"


def test_analyze_apache_config_reports_options_includes_in_virtual_host(
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
                    "    Options Includes",
                    "</VirtualHost>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    matching = [f for f in result.findings if f.rule_id == "apache.options_includes_enabled"]
    assert len(matching) == 1
    finding = matching[0]
    assert finding.rule_id == "apache.options_includes_enabled"
    assert finding.title == "Includes enabled via Options"


def test_analyze_apache_config_reports_options_includes_location(tmp_path: Path) -> None:
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
                    '<Directory "/var/www/html">',
                    "    AllowOverride None",
                    "    Options Includes",
                    "</Directory>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "apache.options_includes_enabled"
    assert finding.location is not None
    assert finding.location.file_path == str(config_path)
    assert finding.location.line == 12


def test_analyze_apache_config_does_not_report_options_multiviews_when_absent(
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
                    '<Directory "/var/www/html">',
                    "    AllowOverride None",
                    "    Options FollowSymLinks SymLinksIfOwnerMatch",
                    "</Directory>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert result.findings == []


def test_analyze_apache_config_reports_options_multiviews_in_directory(
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
                    '<Directory "/var/www/html">',
                    "    AllowOverride None",
                    "    Options MultiViews",
                    "</Directory>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "apache.options_multiviews_enabled"
    assert finding.title == "MultiViews enabled via Options"


def test_analyze_apache_config_reports_options_indexes_multiviews_in_directory(
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
                    '<Directory "/var/www/html">',
                    "    AllowOverride None",
                    "    Options Indexes MultiViews",
                    "</Directory>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    multiviews_findings = [
        finding
        for finding in result.findings
        if finding.rule_id == "apache.options_multiviews_enabled"
    ]

    assert result.issues == []
    assert len(multiviews_findings) == 1
    assert multiviews_findings[0].title == "MultiViews enabled via Options"


def test_analyze_apache_config_reports_options_multiviews_in_virtual_host(
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
                    "    Options MultiViews",
                    "</VirtualHost>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    matching = [f for f in result.findings if f.rule_id == "apache.options_multiviews_enabled"]
    assert len(matching) == 1
    finding = matching[0]
    assert finding.rule_id == "apache.options_multiviews_enabled"
    assert finding.title == "MultiViews enabled via Options"


def test_analyze_apache_config_does_not_report_options_minus_multiviews_in_directory(
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
                    '<Directory "/var/www/html">',
                    "    AllowOverride None",
                    "    Options -MultiViews",
                    "</Directory>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert result.findings == []


def test_analyze_apache_config_reports_options_multiviews_location(tmp_path: Path) -> None:
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
                    '<Directory "/var/www/html">',
                    "    AllowOverride None",
                    "    Options MultiViews",
                    "</Directory>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "apache.options_multiviews_enabled"
    assert finding.location is not None
    assert finding.location.file_path == str(config_path)
    assert finding.location.line == 12


def test_analyze_apache_config_does_not_report_index_options_risky_tokens_when_absent(
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
                    '<Directory "/var/www/html">',
                    "    AllowOverride None",
                    "    IndexOptions NameWidth=* DescriptionWidth=*",
                    "</Directory>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert result.findings == []


def test_analyze_apache_config_reports_index_options_fancyindexing_in_directory(
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
                    '<Directory "/var/www/html">',
                    "    AllowOverride None",
                    "    IndexOptions FancyIndexing",
                    "</Directory>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "apache.index_options_fancyindexing_enabled"
    assert finding.title == "FancyIndexing enabled via IndexOptions"


def test_analyze_apache_config_reports_index_options_scanhtmltitles_in_directory(
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
                    '<Directory "/var/www/html">',
                    "    AllowOverride None",
                    "    IndexOptions ScanHTMLTitles",
                    "</Directory>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "apache.index_options_scanhtmltitles_enabled"
    assert finding.title == "ScanHTMLTitles enabled via IndexOptions"


def test_analyze_apache_config_reports_index_options_fancyindexing_in_virtual_host(
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
                    "    IndexOptions FancyIndexing",
                    "</VirtualHost>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    matching = [f for f in result.findings if f.rule_id == "apache.index_options_fancyindexing_enabled"]
    assert len(matching) == 1
    finding = matching[0]
    assert finding.rule_id == "apache.index_options_fancyindexing_enabled"
    assert finding.title == "FancyIndexing enabled via IndexOptions"


def test_analyze_apache_config_reports_index_options_scanhtmltitles_in_virtual_host(
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
                    "    IndexOptions ScanHTMLTitles",
                    "</VirtualHost>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    matching = [f for f in result.findings if f.rule_id == "apache.index_options_scanhtmltitles_enabled"]
    assert len(matching) == 1
    finding = matching[0]
    assert finding.rule_id == "apache.index_options_scanhtmltitles_enabled"
    assert finding.title == "ScanHTMLTitles enabled via IndexOptions"


def test_analyze_apache_config_does_not_report_index_options_minus_fancyindexing(
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
                    '<Directory "/var/www/html">',
                    "    AllowOverride None",
                    "    IndexOptions -FancyIndexing",
                    "</Directory>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert result.findings == []


def test_analyze_apache_config_does_not_report_index_options_minus_scanhtmltitles(
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
                    '<Directory "/var/www/html">',
                    "    AllowOverride None",
                    "    IndexOptions -ScanHTMLTitles",
                    "</Directory>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert result.findings == []


def test_analyze_apache_config_reports_both_index_options_findings_with_location(
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
                    '<Directory "/var/www/html">',
                    "    AllowOverride None",
                    "    IndexOptions FancyIndexing ScanHTMLTitles",
                    "</Directory>",
                ]
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    findings_by_rule_id = {finding.rule_id: finding for finding in result.findings}

    assert result.issues == []
    assert len(result.findings) == 2
    assert set(findings_by_rule_id) == {
        "apache.index_options_fancyindexing_enabled",
        "apache.index_options_scanhtmltitles_enabled",
    }
    assert (
        findings_by_rule_id["apache.index_options_fancyindexing_enabled"].location is not None
    )
    assert (
        findings_by_rule_id["apache.index_options_scanhtmltitles_enabled"].location is not None
    )
    assert (
        findings_by_rule_id["apache.index_options_fancyindexing_enabled"].location.file_path
        == str(config_path)
    )
    assert (
        findings_by_rule_id["apache.index_options_scanhtmltitles_enabled"].location.file_path
        == str(config_path)
    )
    assert findings_by_rule_id["apache.index_options_fancyindexing_enabled"].location.line == 12
    assert findings_by_rule_id["apache.index_options_scanhtmltitles_enabled"].location.line == 12
