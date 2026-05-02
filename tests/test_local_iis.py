from tests.iis_helpers import (
    AnalysisResult,
    IISParseError,
    MINIMAL_APPLICATION_HOST_CONFIG,
    MINIMAL_WEB_CONFIG,
    Path,
    _ABSENCE_RULE_IDS,
    analyze_iis_config,
    parse_iis_config,
    pytest,
)


# --- Parser happy path ---


def test_parse_application_host_config() -> None:
    doc = parse_iis_config(
        MINIMAL_APPLICATION_HOST_CONFIG,
        file_path="C:/Windows/System32/inetsrv/config/applicationHost.config",
    )

    assert doc.root_tag == "configuration"
    assert doc.config_kind == "applicationHost"
    assert doc.file_path is not None
    assert len(doc.sections) > 0

    top_level_tags = [s.tag for s in doc.sections if s.xml_path.count("/") == 1]
    assert "system.applicationHost" in top_level_tags
    assert "system.webServer" in top_level_tags


def test_parse_web_config() -> None:
    doc = parse_iis_config(MINIMAL_WEB_CONFIG, file_path="C:/inetpub/wwwroot/web.config")

    assert doc.root_tag == "configuration"
    assert doc.config_kind == "web"
    assert len(doc.sections) > 0

    top_level_tags = [s.tag for s in doc.sections if s.xml_path.count("/") == 1]
    assert "system.webServer" in top_level_tags
    assert "system.web" in top_level_tags


def test_parse_machine_config() -> None:
    doc = parse_iis_config(
        """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <configSections />
    <system.web>
        <customErrors mode="RemoteOnly" />
    </system.web>
</configuration>
""",
        file_path="C:/Windows/Microsoft.NET/Framework64/v4.0.30319/Config/machine.config",
    )

    assert doc.root_tag == "configuration"
    assert doc.config_kind == "machine"
    assert len(doc.sections) > 0


def test_parse_preserves_xml_paths() -> None:
    doc = parse_iis_config(MINIMAL_WEB_CONFIG, file_path="web.config")

    xml_paths = [s.xml_path for s in doc.sections]
    assert "configuration/system.webServer" in xml_paths
    assert "configuration/system.webServer/httpErrors" in xml_paths
    assert "configuration/system.webServer/security" in xml_paths
    assert "configuration/system.webServer/security/requestFiltering" in xml_paths
    assert "configuration/system.webServer/security/requestFiltering/requestLimits" in xml_paths


def test_parse_preserves_attributes() -> None:
    doc = parse_iis_config(MINIMAL_WEB_CONFIG, file_path="web.config")

    http_errors = [s for s in doc.sections if s.tag == "httpErrors"]
    assert len(http_errors) == 1
    assert http_errors[0].attributes.get("errorMode") == "Custom"


def test_parse_preserves_source_ref() -> None:
    doc = parse_iis_config(MINIMAL_WEB_CONFIG, file_path="web.config")

    for section in doc.sections:
        assert section.source.file_path == "web.config"
        assert section.source.xml_path == section.xml_path


def test_parse_unknown_config_kind_for_generic_path() -> None:
    doc = parse_iis_config(
        '<?xml version="1.0"?>\n<configuration></configuration>',
        file_path="custom.config",
    )

    assert doc.config_kind == "unknown"
    assert doc.root_tag == "configuration"


def test_parse_generic_machine_like_config_detected_by_structure() -> None:
    doc = parse_iis_config(
        """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <configSections />
    <system.web>
        <trace enabled="false" />
    </system.web>
</configuration>
""",
        file_path="custom.config",
    )

    assert doc.config_kind == "machine"


# --- Parser error handling ---


def test_parse_malformed_xml_raises_parse_error() -> None:
    with pytest.raises(IISParseError) as exc_info:
        parse_iis_config("<configuration><broken>", file_path="web.config")
    assert exc_info.value.file_path == "web.config"
    assert "XML parse error" in str(exc_info.value)


def test_parse_empty_input_raises_parse_error() -> None:
    with pytest.raises(IISParseError):
        parse_iis_config("", file_path="web.config")


# --- Analyzer happy path ---


def test_analyze_valid_application_host_config(tmp_path: Path) -> None:
    config_path = tmp_path / "applicationHost.config"
    config_path.write_text(MINIMAL_APPLICATION_HOST_CONFIG, encoding="utf-8")

    result = analyze_iis_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.mode == "local"
    assert result.server_type == "iis"
    assert result.target == str(config_path)
    # Absence rules (HSTS, logging) may fire on minimal configs; no *insecure* findings.
    insecure = [f for f in result.findings if f.rule_id not in _ABSENCE_RULE_IDS]
    assert insecure == []
    assert result.issues == []
    assert result.metadata["config_kind"] == "applicationHost"
    assert result.metadata["root_tag"] == "configuration"
    assert isinstance(result.metadata["section_count"], int)
    assert result.metadata["section_count"] > 0


def test_analyze_valid_web_config(tmp_path: Path) -> None:
    config_path = tmp_path / "web.config"
    config_path.write_text(MINIMAL_WEB_CONFIG, encoding="utf-8")

    result = analyze_iis_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.mode == "local"
    assert result.server_type == "iis"
    insecure = [f for f in result.findings if f.rule_id not in _ABSENCE_RULE_IDS]
    assert insecure == []
    assert result.issues == []
    assert result.metadata["config_kind"] == "web"
    assert result.metadata["machine_config_path"] is None
    assert result.metadata["inheritance_chain"] == [str(config_path)]


def test_analyze_iis_config_accepts_utf8_bom(tmp_path: Path) -> None:
    config_path = tmp_path / "web.config"
    config_path.write_text(MINIMAL_WEB_CONFIG, encoding="utf-8-sig")

    result = analyze_iis_config(str(config_path))

    assert result.issues == []
    assert result.metadata["config_kind"] == "web"


def test_analyze_machine_config_as_single_file(tmp_path: Path) -> None:
    config_path = tmp_path / "machine.config"
    config_path.write_text(
        """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <configSections />
    <system.web>
        <customErrors mode="RemoteOnly" />
    </system.web>
</configuration>
""",
        encoding="utf-8",
    )

    result = analyze_iis_config(str(config_path))

    assert result.issues == []
    assert result.metadata["config_kind"] == "machine"
    assert result.metadata["machine_config_path"] == str(config_path)
    assert result.metadata["inheritance_chain"] == [str(config_path)]


def test_analyze_reports_top_level_sections_in_metadata(tmp_path: Path) -> None:
    config_path = tmp_path / "web.config"
    config_path.write_text(MINIMAL_WEB_CONFIG, encoding="utf-8")

    result = analyze_iis_config(str(config_path))

    top_sections = result.metadata["top_level_sections"]
    assert "system.webServer" in top_sections
    assert "system.web" in top_sections


# --- Analyzer failure handling ---


def test_analyze_missing_file_returns_issue() -> None:
    result = analyze_iis_config("/nonexistent/web.config")

    assert isinstance(result, AnalysisResult)
    assert result.mode == "local"
    assert result.server_type == "iis"
    assert result.findings == []
    assert len(result.issues) == 1
    assert result.issues[0].code == "config_not_found"
    assert result.issues[0].level == "error"
    assert result.issues[0].location is not None
    assert result.issues[0].location.kind == "file"


def test_analyze_malformed_xml_returns_issue(tmp_path: Path) -> None:
    config_path = tmp_path / "web.config"
    config_path.write_text("<configuration><broken>", encoding="utf-8")

    result = analyze_iis_config(str(config_path))

    assert isinstance(result, AnalysisResult)
    assert result.mode == "local"
    assert result.server_type == "iis"
    assert result.findings == []
    assert len(result.issues) == 1
    assert result.issues[0].code == "iis_parse_error"
    assert result.issues[0].level == "error"
    assert result.issues[0].location is not None
    assert result.issues[0].location.kind == "xml"
    assert result.issues[0].location.file_path == str(config_path)


# --- Directory discovery ---


def test_analyze_directory_with_web_config(tmp_path: Path) -> None:
    web_config = tmp_path / "web.config"
    web_config.write_text(MINIMAL_WEB_CONFIG, encoding="utf-8")

    result = analyze_iis_config(str(tmp_path))

    assert isinstance(result, AnalysisResult)
    assert result.mode == "local"
    assert result.server_type == "iis"
    assert result.issues == []
    assert result.metadata["config_kind"] == "web"


def test_analyze_directory_without_web_config_returns_issue(tmp_path: Path) -> None:
    result = analyze_iis_config(str(tmp_path))

    assert isinstance(result, AnalysisResult)
    assert result.mode == "local"
    assert result.server_type == "iis"
    assert len(result.issues) == 1
    assert result.issues[0].code == "config_not_found"


# --- IIS rules: iis.directory_browse_enabled ---


def test_directory_browse_enabled_fires(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <directoryBrowse enabled="true" />
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    rule_ids = {f.rule_id for f in result.findings}
    assert "iis.directory_browse_enabled" in rule_ids
    finding = [f for f in result.findings if f.rule_id == "iis.directory_browse_enabled"][0]
    assert finding.location is not None
    assert finding.location.kind == "xml"
    assert finding.location.xml_path is not None
    assert "directoryBrowse" in finding.location.xml_path


def test_directory_browse_enabled_does_not_fire_when_false(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <directoryBrowse enabled="false" />
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.directory_browse_enabled" not in {f.rule_id for f in result.findings}


def test_directory_browse_enabled_does_not_fire_when_section_missing(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security />
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.directory_browse_enabled" not in {f.rule_id for f in result.findings}


def test_directory_browse_enabled_case_insensitive(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <directoryBrowse enabled="True" />
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.directory_browse_enabled" in {f.rule_id for f in result.findings}


# --- IIS rules: iis.http_errors_detailed ---


def test_http_errors_detailed_fires(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <httpErrors errorMode="Detailed" />
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    rule_ids = {f.rule_id for f in result.findings}
    assert "iis.http_errors_detailed" in rule_ids
    finding = [f for f in result.findings if f.rule_id == "iis.http_errors_detailed"][0]
    assert finding.location is not None
    assert finding.location.kind == "xml"
    assert "httpErrors" in (finding.location.xml_path or "")


def test_http_errors_detailed_does_not_fire_when_custom(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <httpErrors errorMode="Custom" />
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.http_errors_detailed" not in {f.rule_id for f in result.findings}


def test_http_errors_detailed_does_not_fire_when_detailed_local_only(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <httpErrors errorMode="DetailedLocalOnly" />
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.http_errors_detailed" not in {f.rule_id for f in result.findings}


def test_http_errors_detailed_does_not_fire_when_section_missing(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security />
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.http_errors_detailed" not in {f.rule_id for f in result.findings}


# --- IIS rules: iis.custom_errors_off ---


def test_custom_errors_off_fires(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.web>
        <customErrors mode="Off" />
    </system.web>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    rule_ids = {f.rule_id for f in result.findings}
    assert "iis.custom_errors_off" in rule_ids
    finding = [f for f in result.findings if f.rule_id == "iis.custom_errors_off"][0]
    assert finding.location is not None
    assert finding.location.kind == "xml"
    assert "customErrors" in (finding.location.xml_path or "")


def test_custom_errors_off_does_not_fire_when_remote_only(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.web>
        <customErrors mode="RemoteOnly" />
    </system.web>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.custom_errors_off" not in {f.rule_id for f in result.findings}


def test_custom_errors_off_does_not_fire_when_on(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.web>
        <customErrors mode="On" />
    </system.web>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.custom_errors_off" not in {f.rule_id for f in result.findings}


def test_custom_errors_off_case_insensitive(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.web>
        <customErrors mode="off" />
    </system.web>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.custom_errors_off" in {f.rule_id for f in result.findings}


# --- IIS rules: iis.asp_script_error_sent_to_browser ---


def test_asp_script_error_sent_to_browser_fires(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <asp scriptErrorSentToBrowser="true" />
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    rule_ids = {f.rule_id for f in result.findings}
    assert "iis.asp_script_error_sent_to_browser" in rule_ids
    finding = [f for f in result.findings if f.rule_id == "iis.asp_script_error_sent_to_browser"][0]
    assert finding.location is not None
    assert finding.location.kind == "xml"
    assert "asp" in (finding.location.xml_path or "")


def test_asp_script_error_sent_to_browser_does_not_fire_when_false(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <asp scriptErrorSentToBrowser="false" />
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.asp_script_error_sent_to_browser" not in {f.rule_id for f in result.findings}


def test_asp_script_error_sent_to_browser_does_not_fire_when_section_missing(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security />
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.asp_script_error_sent_to_browser" not in {f.rule_id for f in result.findings}


# --- IIS rules: no false positives on safe baseline ---


# --- IIS rules: iis.compilation_debug_enabled ---


def test_compilation_debug_enabled_fires(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.web>
        <compilation debug="true" />
    </system.web>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    rule_ids = {f.rule_id for f in result.findings}
    assert "iis.compilation_debug_enabled" in rule_ids
    finding = [f for f in result.findings if f.rule_id == "iis.compilation_debug_enabled"][0]
    assert finding.location is not None
    assert finding.location.kind == "xml"
    assert "compilation" in (finding.location.xml_path or "")


def test_compilation_debug_enabled_does_not_fire_when_false(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.web>
        <compilation debug="false" />
    </system.web>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.compilation_debug_enabled" not in {f.rule_id for f in result.findings}


def test_compilation_debug_enabled_does_not_fire_when_missing(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.web>
        <compilation targetFramework="4.8" />
    </system.web>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.compilation_debug_enabled" not in {f.rule_id for f in result.findings}


def test_compilation_debug_enabled_handles_empty_debug_value(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.web>
        <compilation debug="" />
    </system.web>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.compilation_debug_enabled" not in {f.rule_id for f in result.findings}


# --- IIS rules: iis.trace_enabled ---


def test_trace_enabled_fires(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.web>
        <trace enabled="true" />
    </system.web>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    rule_ids = {f.rule_id for f in result.findings}
    assert "iis.trace_enabled" in rule_ids
    finding = [f for f in result.findings if f.rule_id == "iis.trace_enabled"][0]
    assert finding.location is not None
    assert finding.location.kind == "xml"
    assert "trace" in (finding.location.xml_path or "")


def test_trace_enabled_does_not_fire_when_false(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.web>
        <trace enabled="false" />
    </system.web>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.trace_enabled" not in {f.rule_id for f in result.findings}


def test_trace_enabled_does_not_fire_when_section_missing(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.web>
        <compilation debug="false" />
    </system.web>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.trace_enabled" not in {f.rule_id for f in result.findings}


# --- IIS rules: iis.http_runtime_version_header_enabled ---


def test_http_runtime_version_header_enabled_fires(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.web>
        <httpRuntime enableVersionHeader="true" />
    </system.web>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    rule_ids = {f.rule_id for f in result.findings}
    assert "iis.http_runtime_version_header_enabled" in rule_ids
    finding = [f for f in result.findings if f.rule_id == "iis.http_runtime_version_header_enabled"][0]
    assert finding.location is not None
    assert finding.location.kind == "xml"
    assert "httpRuntime" in (finding.location.xml_path or "")


def test_http_runtime_version_header_does_not_fire_when_false(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.web>
        <httpRuntime enableVersionHeader="false" />
    </system.web>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.http_runtime_version_header_enabled" not in {f.rule_id for f in result.findings}


def test_http_runtime_version_header_does_not_fire_when_absent(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.web>
        <httpRuntime targetFramework="4.8" />
    </system.web>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.http_runtime_version_header_enabled" not in {f.rule_id for f in result.findings}


# --- IIS rules: iis.request_filtering_allow_double_escaping ---


def test_request_filtering_allow_double_escaping_fires(tmp_path: Path) -> None:
    # requestFiltering at depth 2 (direct child of system.webServer)
    # so it is visible to the current 2-level parser.
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <requestFiltering allowDoubleEscaping="true" />
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    rule_ids = {f.rule_id for f in result.findings}
    assert "iis.request_filtering_allow_double_escaping" in rule_ids
    finding = [f for f in result.findings if f.rule_id == "iis.request_filtering_allow_double_escaping"][0]
    assert finding.location is not None
    assert finding.location.kind == "xml"
    assert "requestFiltering" in (finding.location.xml_path or "")


def test_request_filtering_allow_double_escaping_does_not_fire_when_false(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <requestFiltering allowDoubleEscaping="false" />
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.request_filtering_allow_double_escaping" not in {f.rule_id for f in result.findings}


def test_request_filtering_allow_double_escaping_does_not_fire_when_missing(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <requestFiltering>
            <requestLimits maxAllowedContentLength="4194304" />
        </requestFiltering>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert "iis.request_filtering_allow_double_escaping" not in {f.rule_id for f in result.findings}


def test_request_filtering_under_security_fires_for_canonical_iis_path(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <requestFiltering allowDoubleEscaping="true" />
        </security>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    rule_ids = {f.rule_id for f in result.findings}
    assert "iis.request_filtering_allow_double_escaping" in rule_ids
    finding = [f for f in result.findings if f.rule_id == "iis.request_filtering_allow_double_escaping"][0]
    assert finding.location is not None
    assert finding.location.xml_path == "configuration/system.webServer/security/requestFiltering"


# --- IIS rules: no false positives on safe baseline (all rules) ---


def test_no_iis_rule_findings_on_safe_baseline(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <directoryBrowse enabled="false" />
        <httpErrors errorMode="DetailedLocalOnly" />
        <httpLogging dontLog="false" />
        <asp scriptErrorSentToBrowser="false" />
        <requestFiltering allowDoubleEscaping="false">
            <requestLimits maxAllowedContentLength="4194304" />
        </requestFiltering>
        <httpProtocol>
            <customHeaders>
                <remove name="X-Powered-By" />
                <add name="Strict-Transport-Security"
                     value="max-age=31536000; includeSubDomains" />
            </customHeaders>
        </httpProtocol>
    </system.webServer>
    <system.web>
        <customErrors mode="RemoteOnly" />
        <compilation debug="false" />
        <trace enabled="false" />
        <httpRuntime enableVersionHeader="false" />
    </system.web>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    server_findings = [f for f in result.findings if not f.rule_id.startswith("universal.")]
    assert server_findings == []


def test_malformed_xml_still_returns_parse_error_not_rule_findings(tmp_path: Path) -> None:
    (tmp_path / "web.config").write_text("<configuration><broken>", encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    assert result.findings == []
    assert len(result.issues) == 1
    assert result.issues[0].code == "iis_parse_error"
