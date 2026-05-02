from tests.iis_helpers import (
    build_effective_config,
    parse_iis_config,
)


# ---------------------------------------------------------------------------
# Effective config reconstruction (4.3)
# ---------------------------------------------------------------------------


def _build(xml: str):
    doc = parse_iis_config(xml, file_path="web.config")
    return build_effective_config(doc)


def test_effective_global_section_attributes() -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <directoryBrowse enabled="false" />
    </system.webServer>
</configuration>
"""
    eff = _build(config)
    section = eff.get_effective_section("/directoryBrowse")
    assert section is not None
    assert section.attributes["enabled"] == "false"
    assert section.location_path is None


def test_effective_location_overrides_global_attribute() -> None:
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
    eff = _build(config)

    g = eff.get_effective_section("/directoryBrowse")
    assert g is not None
    assert g.attributes["enabled"] == "false"

    loc = eff.get_effective_section("/directoryBrowse", location_path="uploads")
    assert loc is not None
    assert loc.attributes["enabled"] == "true"
    assert loc.location_path == "uploads"


def test_effective_location_inherits_global_when_no_override() -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <directoryBrowse enabled="false" />
        <httpErrors errorMode="Custom" />
    </system.webServer>
    <location path="api">
        <system.webServer>
            <httpErrors errorMode="Detailed" />
        </system.webServer>
    </location>
</configuration>
"""
    eff = _build(config)

    loc_dir = eff.get_effective_section("/directoryBrowse", location_path="api")
    assert loc_dir is not None
    assert loc_dir.attributes["enabled"] == "false"
    assert loc_dir.location_path == "api"

    loc_err = eff.get_effective_section("/httpErrors", location_path="api")
    assert loc_err is not None
    assert loc_err.attributes["errorMode"] == "Detailed"


def test_effective_last_wins_for_duplicate_global_sections() -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <httpErrors errorMode="Custom" />
    </system.webServer>
    <system.webServer>
        <httpErrors errorMode="Detailed" />
    </system.webServer>
</configuration>
"""
    eff = _build(config)
    section = eff.get_effective_section("/httpErrors")
    assert section is not None
    assert section.attributes["errorMode"] == "Detailed"


def test_effective_child_clear_removes_inherited() -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <modules>
            <add name="Mod1" />
            <add name="Mod2" />
        </modules>
    </system.webServer>
    <location path="api">
        <system.webServer>
            <modules>
                <clear />
                <add name="Mod3" />
            </modules>
        </system.webServer>
    </location>
</configuration>
"""
    eff = _build(config)

    g = eff.get_effective_section("/modules")
    assert g is not None
    assert len(g.children) == 2

    loc = eff.get_effective_section("/modules", location_path="api")
    assert loc is not None
    assert len(loc.children) == 1
    assert loc.children[0].attributes.get("name") == "Mod3"


def test_effective_child_remove_deletes_by_key() -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <modules>
            <add name="Mod1" />
            <add name="Mod2" />
            <add name="Mod3" />
        </modules>
    </system.webServer>
    <location path="api">
        <system.webServer>
            <modules>
                <remove name="Mod2" />
            </modules>
        </system.webServer>
    </location>
</configuration>
"""
    eff = _build(config)

    loc = eff.get_effective_section("/modules", location_path="api")
    assert loc is not None
    names = [c.attributes.get("name") for c in loc.children]
    assert names == ["Mod1", "Mod3"]


def test_effective_child_remove_prefers_known_key_attribute() -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <httpErrors>
            <error statusCode="404" path="/not-found.htm" responseMode="File" />
            <error statusCode="500" path="/server-error.htm" responseMode="File" />
        </httpErrors>
    </system.webServer>
    <location path="api">
        <system.webServer>
            <httpErrors>
                <remove path="/wrong-key.htm" statusCode="404" />
            </httpErrors>
        </system.webServer>
    </location>
</configuration>
"""
    eff = _build(config)

    loc = eff.get_effective_section("/httpErrors", location_path="api")
    assert loc is not None
    status_codes = [c.attributes.get("statusCode") for c in loc.children]
    assert status_codes == ["500"]


def test_effective_child_add_appends() -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <modules>
            <add name="Mod1" />
        </modules>
    </system.webServer>
    <location path="api">
        <system.webServer>
            <modules>
                <add name="Mod2" />
            </modules>
        </system.webServer>
    </location>
</configuration>
"""
    eff = _build(config)

    loc = eff.get_effective_section("/modules", location_path="api")
    assert loc is not None
    names = [c.attributes.get("name") for c in loc.children]
    assert names == ["Mod1", "Mod2"]


def test_effective_all_sections_includes_global_and_locations() -> None:
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
    eff = _build(config)
    all_s = eff.all_sections
    dir_browse = [s for s in all_s if s.tag == "directoryBrowse"]
    assert len(dir_browse) == 2


def test_effective_multiple_locations() -> None:
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
    <location path="admin">
        <system.webServer>
            <directoryBrowse enabled="false" />
        </system.webServer>
    </location>
</configuration>
"""
    eff = _build(config)

    uploads = eff.get_effective_section("/directoryBrowse", location_path="uploads")
    assert uploads is not None
    assert uploads.attributes["enabled"] == "true"

    admin = eff.get_effective_section("/directoryBrowse", location_path="admin")
    assert admin is not None
    assert admin.attributes["enabled"] == "false"


def test_effective_location_merges_attributes_from_global() -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <httpErrors errorMode="Custom" existingResponse="PassThrough" />
    </system.webServer>
    <location path="api">
        <system.webServer>
            <httpErrors errorMode="Detailed" />
        </system.webServer>
    </location>
</configuration>
"""
    eff = _build(config)
    loc = eff.get_effective_section("/httpErrors", location_path="api")
    assert loc is not None
    assert loc.attributes["errorMode"] == "Detailed"
    assert loc.attributes["existingResponse"] == "PassThrough"


def test_effective_empty_config() -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
</configuration>
"""
    eff = _build(config)
    assert eff.global_sections == {}
    assert eff.location_sections == {}


def test_effective_global_child_collection_merge() -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <modules>
            <add name="Mod1" />
        </modules>
    </system.webServer>
    <system.webServer>
        <modules>
            <add name="Mod2" />
        </modules>
    </system.webServer>
</configuration>
"""
    eff = _build(config)
    g = eff.get_effective_section("/modules")
    assert g is not None
    names = [c.attributes.get("name") for c in g.children]
    assert names == ["Mod1", "Mod2"]


def test_effective_nested_location_inherits_from_parent_location() -> None:
    """api/v1 inherits from api, not just from global."""
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <directoryBrowse enabled="false" />
    </system.webServer>
    <location path="api">
        <system.webServer>
            <httpErrors errorMode="Detailed" />
            <directoryBrowse enabled="true" />
        </system.webServer>
    </location>
    <location path="api/v1">
        <system.webServer>
            <directoryBrowse enabled="false" />
        </system.webServer>
    </location>
</configuration>
"""
    eff = _build(config)

    # api/v1 overrides directoryBrowse back to false.
    v1_dir = eff.get_effective_section("/directoryBrowse", location_path="api/v1")
    assert v1_dir is not None
    assert v1_dir.attributes["enabled"] == "false"

    # api/v1 inherits httpErrors from api (not from global which has none).
    v1_err = eff.get_effective_section("/httpErrors", location_path="api/v1")
    assert v1_err is not None
    assert v1_err.attributes["errorMode"] == "Detailed"
    assert v1_err.location_path == "api/v1"


def test_effective_deep_nested_location_inheritance() -> None:
    """api/v1/admin inherits through api/v1 → api → global."""
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <directoryBrowse enabled="false" />
    </system.webServer>
    <location path="api">
        <system.webServer>
            <httpErrors errorMode="Detailed" />
        </system.webServer>
    </location>
    <location path="api/v1">
        <system.webServer>
            <modules>
                <add name="ApiModule" />
            </modules>
        </system.webServer>
    </location>
    <location path="api/v1/admin">
        <system.webServer>
            <directoryBrowse enabled="true" />
        </system.webServer>
    </location>
</configuration>
"""
    eff = _build(config)

    # api/v1/admin overrides directoryBrowse.
    admin_dir = eff.get_effective_section("/directoryBrowse", location_path="api/v1/admin")
    assert admin_dir is not None
    assert admin_dir.attributes["enabled"] == "true"

    # api/v1/admin inherits httpErrors from api.
    admin_err = eff.get_effective_section("/httpErrors", location_path="api/v1/admin")
    assert admin_err is not None
    assert admin_err.attributes["errorMode"] == "Detailed"

    # api/v1/admin inherits modules from api/v1.
    admin_mod = eff.get_effective_section("/modules", location_path="api/v1/admin")
    assert admin_mod is not None
    assert len(admin_mod.children) == 1
    assert admin_mod.children[0].attributes.get("name") == "ApiModule"


# ---------------------------------------------------------------------------
# Origin chain traceability (4.3 supplement)
# ---------------------------------------------------------------------------


def test_effective_origin_chain_global_only() -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <directoryBrowse enabled="false" />
    </system.webServer>
</configuration>
"""
    eff = _build(config)
    section = eff.get_effective_section("/directoryBrowse")
    assert section is not None
    assert len(section.origin_chain) == 1
    assert section.source == section.origin_chain[-1]
    assert section.source.xml_path is not None
    assert "directoryBrowse" in section.source.xml_path


def test_effective_origin_chain_location_override() -> None:
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
    eff = _build(config)
    loc = eff.get_effective_section("/directoryBrowse", location_path="uploads")
    assert loc is not None
    # Chain: global source → location source.
    assert len(loc.origin_chain) == 2
    assert "location" not in (loc.origin_chain[0].xml_path or "")
    assert "location" in (loc.origin_chain[1].xml_path or "")
    # .source is the last (most specific).
    assert loc.source == loc.origin_chain[-1]


def test_effective_origin_chain_deep_inheritance() -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <httpErrors errorMode="Custom" />
    </system.webServer>
    <location path="api">
        <system.webServer>
            <httpErrors errorMode="Detailed" />
        </system.webServer>
    </location>
    <location path="api/v1">
        <system.webServer>
            <httpErrors errorMode="DetailedLocalOnly" />
        </system.webServer>
    </location>
</configuration>
"""
    eff = _build(config)
    v1 = eff.get_effective_section("/httpErrors", location_path="api/v1")
    assert v1 is not None
    # Chain: global → api → api/v1.
    assert len(v1.origin_chain) == 3
    assert v1.attributes["errorMode"] == "DetailedLocalOnly"


def test_effective_origin_chain_pure_inheritance_preserves_chain() -> None:
    """When a location purely inherits (no override), origin chain is preserved."""
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <directoryBrowse enabled="false" />
    </system.webServer>
    <location path="api">
        <system.webServer>
            <httpErrors errorMode="Detailed" />
        </system.webServer>
    </location>
</configuration>
"""
    eff = _build(config)
    # directoryBrowse is purely inherited at "api" location.
    loc = eff.get_effective_section("/directoryBrowse", location_path="api")
    assert loc is not None
    assert len(loc.origin_chain) == 1  # only global source, no override
