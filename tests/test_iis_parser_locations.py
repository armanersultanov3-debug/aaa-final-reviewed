from tests.iis_helpers import (
    Path,
    analyze_iis_config,
    parse_iis_config,
)


# ---------------------------------------------------------------------------
# Child element extraction (4.1)
# ---------------------------------------------------------------------------


def test_child_add_elements_extracted_into_section_children() -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <httpErrors errorMode="DetailedLocalOnly">
            <remove statusCode="404" />
            <error statusCode="404" path="/custom-404.htm" responseMode="File" />
        </httpErrors>
    </system.webServer>
</configuration>
"""
    doc = parse_iis_config(config, file_path="web.config")
    http_errors = [s for s in doc.sections if s.tag == "httpErrors"]
    assert len(http_errors) == 1
    section = http_errors[0]
    assert section.attributes.get("errorMode") == "DetailedLocalOnly"
    assert len(section.children) == 2
    assert section.children[0].tag == "remove"
    assert section.children[0].attributes.get("statusCode") == "404"
    assert section.children[1].tag == "error"
    assert section.children[1].attributes.get("path") == "/custom-404.htm"


def test_child_clear_element_extracted() -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <modules>
            <clear />
            <add name="MyModule" type="MyHandler" />
        </modules>
    </system.webServer>
</configuration>
"""
    doc = parse_iis_config(config, file_path="web.config")
    modules = [s for s in doc.sections if s.tag == "modules"]
    assert len(modules) == 1
    assert len(modules[0].children) == 2
    assert modules[0].children[0].tag == "clear"
    assert modules[0].children[1].tag == "add"
    assert modules[0].children[1].attributes.get("name") == "MyModule"


def test_child_deny_allow_elements_extracted() -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <ipSecurity>
                <deny ipAddress="192.168.1.100" />
                <allow ipAddress="10.0.0.0" subnetMask="255.0.0.0" />
            </ipSecurity>
        </security>
    </system.webServer>
</configuration>
"""
    doc = parse_iis_config(config, file_path="web.config")
    ip_security = [s for s in doc.sections if s.tag == "ipSecurity"]
    assert len(ip_security) == 1
    assert len(ip_security[0].children) == 2
    assert ip_security[0].children[0].tag == "deny"
    assert ip_security[0].children[1].tag == "allow"


def test_child_elements_do_not_appear_as_separate_sections() -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <httpErrors>
            <remove statusCode="500" />
            <error statusCode="500" path="/err.htm" responseMode="File" />
        </httpErrors>
    </system.webServer>
</configuration>
"""
    doc = parse_iis_config(config, file_path="web.config")
    tags = [s.tag for s in doc.sections]
    assert "remove" not in tags
    assert "error" not in tags


def test_child_elements_have_source_refs() -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <modules>
            <add name="Mod1" />
        </modules>
    </system.webServer>
</configuration>
"""
    doc = parse_iis_config(config, file_path="web.config")
    modules = [s for s in doc.sections if s.tag == "modules"]
    assert len(modules) == 1
    child = modules[0].children[0]
    assert child.source.file_path == "web.config"
    assert child.source.xml_path == "configuration/system.webServer/modules/add"


def test_non_child_leaf_sections_remain_as_sections() -> None:
    """Leaf elements that are NOT in the child-directive tag set stay as IISSection."""
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <directoryBrowse enabled="true" />
        <httpErrors errorMode="Detailed" />
    </system.webServer>
</configuration>
"""
    doc = parse_iis_config(config, file_path="web.config")
    tags = [s.tag for s in doc.sections]
    assert "directoryBrowse" in tags
    assert "httpErrors" in tags


def test_binding_elements_extracted_as_children() -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.applicationHost>
        <sites>
            <site name="Default" id="1">
                <bindings>
                    <binding protocol="http" bindingInformation="*:80:" />
                    <binding protocol="https" bindingInformation="*:443:" />
                </bindings>
            </site>
        </sites>
    </system.applicationHost>
</configuration>
"""
    doc = parse_iis_config(config, file_path="applicationHost.config")
    bindings = [s for s in doc.sections if s.tag == "bindings"]
    assert len(bindings) == 1
    assert len(bindings[0].children) == 2
    assert bindings[0].children[0].tag == "binding"
    assert bindings[0].children[0].attributes.get("protocol") == "http"
    assert bindings[0].children[1].attributes.get("protocol") == "https"


# ---------------------------------------------------------------------------
# Location path awareness (4.2)
# ---------------------------------------------------------------------------


def test_location_path_propagated_to_sections() -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <directoryBrowse enabled="false" />
    </system.webServer>
    <location path="uploads">
        <system.webServer>
            <directoryBrowse enabled="true" />
        </system.webServer>
    </location>
</configuration>
"""
    doc = parse_iis_config(config, file_path="web.config")
    dir_browse = [s for s in doc.sections if s.tag == "directoryBrowse"]
    assert len(dir_browse) == 2

    global_section = [s for s in dir_browse if s.location_path is None]
    assert len(global_section) == 1
    assert global_section[0].attributes.get("enabled") == "false"

    scoped_section = [s for s in dir_browse if s.location_path == "uploads"]
    assert len(scoped_section) == 1
    assert scoped_section[0].attributes.get("enabled") == "true"


def test_location_path_xml_path_format() -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <location path="api">
        <system.webServer>
            <httpErrors errorMode="Detailed" />
        </system.webServer>
    </location>
</configuration>
"""
    doc = parse_iis_config(config, file_path="web.config")
    http_errors = [s for s in doc.sections if s.tag == "httpErrors"]
    assert len(http_errors) == 1
    assert http_errors[0].location_path == "api"
    assert http_errors[0].xml_path == "configuration/location[@path='api']/system.webServer/httpErrors"


def test_location_path_none_for_global_sections() -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <directoryBrowse enabled="false" />
    </system.webServer>
</configuration>
"""
    doc = parse_iis_config(config, file_path="web.config")
    for section in doc.sections:
        assert section.location_path is None


def test_multiple_location_blocks() -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <location path="uploads">
        <system.webServer>
            <directoryBrowse enabled="true" />
        </system.webServer>
    </location>
    <location path="admin">
        <system.webServer>
            <directoryBrowse enabled="false" />
        </system.webServer>
    </location>
</configuration>
"""
    doc = parse_iis_config(config, file_path="web.config")
    dir_browse = [s for s in doc.sections if s.tag == "directoryBrowse"]
    assert len(dir_browse) == 2
    paths = {s.location_path for s in dir_browse}
    assert paths == {"uploads", "admin"}


def test_location_path_empty_string_becomes_none() -> None:
    """<location path=""> is treated as global (location_path=None)."""
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <location path="">
        <system.webServer>
            <directoryBrowse enabled="true" />
        </system.webServer>
    </location>
</configuration>
"""
    doc = parse_iis_config(config, file_path="web.config")
    dir_browse = [s for s in doc.sections if s.tag == "directoryBrowse"]
    assert len(dir_browse) == 1
    assert dir_browse[0].location_path is None


def test_location_path_with_child_elements() -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <location path="secure">
        <system.webServer>
            <httpErrors>
                <remove statusCode="404" />
            </httpErrors>
        </system.webServer>
    </location>
</configuration>
"""
    doc = parse_iis_config(config, file_path="web.config")
    http_errors = [s for s in doc.sections if s.tag == "httpErrors"]
    assert len(http_errors) == 1
    assert http_errors[0].location_path == "secure"
    assert len(http_errors[0].children) == 1
    assert http_errors[0].children[0].tag == "remove"


def test_location_without_path_attribute() -> None:
    """<location> without path attr → location_path is None."""
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <location>
        <system.webServer>
            <directoryBrowse enabled="true" />
        </system.webServer>
    </location>
</configuration>
"""
    doc = parse_iis_config(config, file_path="web.config")
    dir_browse = [s for s in doc.sections if s.tag == "directoryBrowse"]
    assert len(dir_browse) == 1
    assert dir_browse[0].location_path is None


def test_existing_rules_still_fire_for_location_scoped_sections(tmp_path: Path) -> None:
    """directoryBrowse inside <location> still triggers the existing rule."""
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <location path="uploads">
        <system.webServer>
            <directoryBrowse enabled="true" />
        </system.webServer>
    </location>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    rule_ids = {f.rule_id for f in result.findings}
    assert "iis.directory_browse_enabled" in rule_ids


# ---------------------------------------------------------------------------
# Location-aware finding tests (4.4)
# ---------------------------------------------------------------------------


def test_location_finding_includes_location_context_in_description(tmp_path: Path) -> None:
    """Findings from location-scoped sections mention the location path."""
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <location path="uploads">
        <system.webServer>
            <directoryBrowse enabled="true" />
        </system.webServer>
    </location>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    finding = [f for f in result.findings if f.rule_id == "iis.directory_browse_enabled"][0]
    assert "uploads" in finding.description


def test_global_safe_location_unsafe_fires(tmp_path: Path) -> None:
    """Global directoryBrowse=false, but location overrides to true → finding."""
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <directoryBrowse enabled="false" />
    </system.webServer>
    <location path="uploads">
        <system.webServer>
            <directoryBrowse enabled="true" />
        </system.webServer>
    </location>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    findings = [f for f in result.findings if f.rule_id == "iis.directory_browse_enabled"]
    # Only the location-scoped one should fire, not the global.
    assert len(findings) == 1
    assert "uploads" in findings[0].description


def test_global_unsafe_location_overrides_to_safe(tmp_path: Path) -> None:
    """Global directoryBrowse=true fires, location overrides to false → no location finding."""
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <directoryBrowse enabled="true" />
    </system.webServer>
    <location path="secure">
        <system.webServer>
            <directoryBrowse enabled="false" />
        </system.webServer>
    </location>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    findings = [f for f in result.findings if f.rule_id == "iis.directory_browse_enabled"]
    # Global fires, location does not.
    assert len(findings) == 1
    assert "secure" not in findings[0].description


def test_multiple_locations_each_produce_findings(tmp_path: Path) -> None:
    """Two unsafe locations produce two separate findings."""
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <location path="uploads">
        <system.webServer>
            <directoryBrowse enabled="true" />
        </system.webServer>
    </location>
    <location path="public">
        <system.webServer>
            <directoryBrowse enabled="true" />
        </system.webServer>
    </location>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    findings = [f for f in result.findings if f.rule_id == "iis.directory_browse_enabled"]
    assert len(findings) == 2
    descriptions = {f.description for f in findings}
    assert any("uploads" in d for d in descriptions)
    assert any("public" in d for d in descriptions)


def test_location_httpErrors_detailed_includes_context(tmp_path: Path) -> None:
    """httpErrors errorMode=Detailed at a location mentions the path."""
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <location path="api">
        <system.webServer>
            <httpErrors errorMode="Detailed" />
        </system.webServer>
    </location>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    finding = [f for f in result.findings if f.rule_id == "iis.http_errors_detailed"][0]
    assert "api" in finding.description


def test_pure_inheritance_does_not_duplicate_finding(tmp_path: Path) -> None:
    """A location that purely inherits an unsafe global should NOT produce a duplicate."""
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <directoryBrowse enabled="true" />
    </system.webServer>
    <location path="app">
        <system.webServer>
            <httpErrors errorMode="Custom" />
        </system.webServer>
    </location>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    findings = [f for f in result.findings if f.rule_id == "iis.directory_browse_enabled"]
    # Only global fires; the inherited copy at "app" is suppressed.
    assert len(findings) == 1
    assert "app" not in findings[0].description
