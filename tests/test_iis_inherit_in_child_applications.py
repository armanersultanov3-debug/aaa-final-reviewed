"""Tests for ``inheritInChildApplications`` attribute handling.

When ``<location path="X" inheritInChildApplications="false">`` is set, the
section's settings apply to the path ``X`` itself but must NOT cascade into
deeper-nested child applications.  These tests pin that semantic before
the implementation lands and after.
"""

from __future__ import annotations

from webconf_audit.local.iis.effective import (
    build_effective_config,
    merge_effective_configs,
)
from webconf_audit.local.iis.parser import parse_iis_config


def _parse(text: str, *, file_path: str) -> "object":
    return parse_iis_config(text, file_path=file_path)


def test_parser_captures_inherit_in_child_applications_attribute() -> None:
    text = """<?xml version="1.0"?>
<configuration>
    <location path="Site/api" inheritInChildApplications="false">
        <system.webServer>
            <directoryBrowse enabled="true" />
        </system.webServer>
    </location>
    <location path="Site/other">
        <system.webServer>
            <directoryBrowse enabled="false" />
        </system.webServer>
    </location>
</configuration>"""
    doc = _parse(text, file_path="/applicationHost.config")
    # Sections for the two location blocks
    by_loc: dict[str | None, list] = {}
    for section in doc.sections:
        by_loc.setdefault(section.location_path, []).append(section)

    assert "Site/api" in by_loc
    assert "Site/other" in by_loc

    # All sections inside Site/api carry inherit=False; all inside Site/other carry inherit=True
    for section in by_loc["Site/api"]:
        assert section.location_inherit_in_child_applications is False
    for section in by_loc["Site/other"]:
        assert section.location_inherit_in_child_applications is True


def test_effective_section_exposes_inherit_in_child_applications() -> None:
    text = """<?xml version="1.0"?>
<configuration>
    <location path="Site/api" inheritInChildApplications="false">
        <system.webServer>
            <directoryBrowse enabled="true" />
        </system.webServer>
    </location>
</configuration>"""
    doc = _parse(text, file_path="/applicationHost.config")
    eff = build_effective_config(doc)

    section = eff.get_effective_section(
        "/directoryBrowse", location_path="Site/api"
    )
    assert section is not None
    assert section.inherit_in_child_applications is False


def test_location_inherit_false_blocks_cascade_into_child_application() -> None:
    """Settings under a parent <location inheritInChildApplications=false>
    must not appear in the effective view of a deeper-nested child web.config.
    """
    app_host = """<?xml version="1.0"?>
<configuration>
    <location path="Site" inheritInChildApplications="false">
        <system.webServer>
            <directoryBrowse enabled="true" />
        </system.webServer>
    </location>
</configuration>"""
    # web.config of a sub-application at /Site/api/sub.  Note: the
    # web.config does not itself declare directoryBrowse, but its
    # effective view should NOT show enabled=true inherited from
    # applicationHost.config because of inheritInChildApplications=false
    # at the parent <location path="Site"> scope.
    sub_web_config = """<?xml version="1.0"?>
<configuration>
    <system.webServer>
        <httpProtocol>
            <customHeaders>
                <add name="X-Foo" value="bar" />
            </customHeaders>
        </httpProtocol>
    </system.webServer>
</configuration>"""

    ah_doc = _parse(app_host, file_path="/applicationHost.config")
    wc_doc = _parse(sub_web_config, file_path="/web.config")

    ah_eff = build_effective_config(ah_doc)
    wc_eff = build_effective_config(wc_doc)

    # Simulate web.config being analyzed as a child application of
    # path "Site/api/sub" — its effective view must drop the
    # inheritInChildApplications=false parent's settings.
    merged = merge_effective_configs(
        ah_eff,
        wc_eff,
        child_application_path="Site/api/sub",
    )

    sec = merged.get_effective_section("/directoryBrowse")
    # directoryBrowse must NOT be inherited into the global scope of the
    # child web.config because the parent <location> blocks the cascade.
    assert sec is None


def test_location_inherit_true_does_cascade_into_child_application() -> None:
    """Sanity check: without inheritInChildApplications=false the cascade
    works (this is the default semantic that should not regress)."""
    app_host = """<?xml version="1.0"?>
<configuration>
    <location path="Site">
        <system.webServer>
            <directoryBrowse enabled="true" />
        </system.webServer>
    </location>
</configuration>"""
    sub_web_config = """<?xml version="1.0"?>
<configuration>
    <system.webServer>
        <httpProtocol>
            <customHeaders>
                <add name="X-Foo" value="bar" />
            </customHeaders>
        </httpProtocol>
    </system.webServer>
</configuration>"""

    ah_doc = _parse(app_host, file_path="/applicationHost.config")
    wc_doc = _parse(sub_web_config, file_path="/web.config")

    ah_eff = build_effective_config(ah_doc)
    wc_eff = build_effective_config(wc_doc)

    merged = merge_effective_configs(
        ah_eff,
        wc_eff,
        child_application_path="Site/api/sub",
    )

    # The parent <location path="Site"> applies to the sub-application
    # and its directoryBrowse setting cascades into the child's
    # effective view.
    sec = merged.get_effective_section(
        "/directoryBrowse", location_path="Site"
    )
    assert sec is not None
    assert sec.attributes.get("enabled") == "true"


def test_inherit_false_keeps_section_at_exact_location_path() -> None:
    """A <location inheritInChildApplications=false> section is visible
    at its own scope; only the cascade into deeper applications is blocked.
    """
    app_host = """<?xml version="1.0"?>
<configuration>
    <location path="Site/api" inheritInChildApplications="false">
        <system.webServer>
            <directoryBrowse enabled="true" />
        </system.webServer>
    </location>
</configuration>"""

    ah_doc = _parse(app_host, file_path="/applicationHost.config")
    ah_eff = build_effective_config(ah_doc)

    section = ah_eff.get_effective_section(
        "/directoryBrowse", location_path="Site/api"
    )
    assert section is not None
    assert section.attributes.get("enabled") == "true"


def test_inherit_false_does_not_break_unrelated_location_paths() -> None:
    """A different <location> block with inheritInChildApplications=false
    in applicationHost.config must not block a sibling location in
    web.config from being merged for sibling-only paths.
    """
    app_host = """<?xml version="1.0"?>
<configuration>
    <location path="Site/api" inheritInChildApplications="false">
        <system.webServer>
            <directoryBrowse enabled="true" />
        </system.webServer>
    </location>
</configuration>"""
    web_config = """<?xml version="1.0"?>
<configuration>
    <location path="Site/api">
        <system.webServer>
            <directoryBrowse enabled="false" />
        </system.webServer>
    </location>
</configuration>"""

    ah_doc = _parse(app_host, file_path="/applicationHost.config")
    wc_doc = _parse(web_config, file_path="/web.config")

    ah_eff = build_effective_config(ah_doc)
    wc_eff = build_effective_config(wc_doc)

    # When merging at the same site root (no child-application
    # narrowing), the <location path="Site/api"> in both files refers to
    # the same scope; web.config wins.
    merged = merge_effective_configs(ah_eff, wc_eff)

    sec = merged.get_effective_section(
        "/directoryBrowse", location_path="Site/api"
    )
    assert sec is not None
    assert sec.attributes.get("enabled") == "false"


def test_inherit_false_round_trips_through_merge() -> None:
    """The inherit_in_child_applications flag on an effective section
    survives merge_effective_configs."""
    app_host = """<?xml version="1.0"?>
<configuration>
    <location path="Site/api" inheritInChildApplications="false">
        <system.webServer>
            <directoryBrowse enabled="true" />
        </system.webServer>
    </location>
</configuration>"""
    # web.config without a matching location: the merge keeps the
    # parent's <location> as-is.
    web_config = """<?xml version="1.0"?>
<configuration>
    <system.webServer />
</configuration>"""

    ah_doc = _parse(app_host, file_path="/applicationHost.config")
    wc_doc = _parse(web_config, file_path="/web.config")

    ah_eff = build_effective_config(ah_doc)
    wc_eff = build_effective_config(wc_doc)

    merged = merge_effective_configs(ah_eff, wc_eff)

    sec = merged.get_effective_section(
        "/directoryBrowse", location_path="Site/api"
    )
    assert sec is not None
    # The inherit_in_child_applications flag must round-trip through merge.
    assert sec.inherit_in_child_applications is False
