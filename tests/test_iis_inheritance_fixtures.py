from __future__ import annotations

from pathlib import Path

from webconf_audit.local.iis.effective import build_effective_config, merge_effective_configs
from webconf_audit.local.iis.parser import parse_iis_config
from webconf_audit.local.iis.rules_runner import run_iis_rules

_FIXTURE_ROOT = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "webserver-configs"
    / "iis"
    / "inheritance-edge-cases"
)
_HANDLER_RULE_IDS = frozenset(
    {
        "iis.cgi_handler_enabled",
        "iis.handler_write_script_execute_enabled",
    }
)
_MODULE_RULE_IDS = frozenset({"iis.webdav_module_enabled"})
_REQUEST_FILTERING_RULE_IDS = frozenset(
    {
        "iis.file_extensions_allow_unlisted",
        "iis.request_filtering_max_query_string_missing",
        "iis.request_filtering_max_query_string_too_high",
        "iis.request_filtering_max_url_missing",
        "iis.request_filtering_max_url_too_high",
        "iis.request_filtering_remove_server_header_disabled",
    }
)


def _parse_config(path: Path):
    return parse_iis_config(path.read_text(encoding="utf-8"), file_path=str(path))


def _load_fixture(
    name: str,
    *,
    base_name: str,
):
    fixture_root = _FIXTURE_ROOT / name
    base_doc = _parse_config(fixture_root / base_name)
    web_doc = _parse_config(fixture_root / "web.config")
    merged = merge_effective_configs(
        build_effective_config(base_doc),
        build_effective_config(web_doc),
    )
    return base_doc, web_doc, merged


def _rule_ids(doc, effective_config) -> set[str]:
    return {finding.rule_id for finding in run_iis_rules(doc, effective_config=effective_config)}


def test_handlers_machine_vs_web_fixture_merges_and_suppresses_handler_findings() -> None:
    base_doc, web_doc, merged = _load_fixture(
        "handlers-machine-vs-web.config",
        base_name="machine.config",
    )

    handlers = merged.get_effective_section("/handlers")
    assert handlers is not None
    assert handlers.attributes["accessPolicy"] == "Read, Script"
    assert [child.attributes.get("name") for child in handlers.children] == [
        "StaticFile",
        "ApiHandler",
    ]
    assert [Path(origin.file_path).name for origin in handlers.origin_chain] == [
        "machine.config",
        "web.config",
    ]

    base_rule_ids = _rule_ids(base_doc, build_effective_config(base_doc))
    merged_rule_ids = _rule_ids(web_doc, merged)

    assert _HANDLER_RULE_IDS <= base_rule_ids
    assert _HANDLER_RULE_IDS.isdisjoint(merged_rule_ids)


def test_modules_clear_then_add_fixture_resets_inherited_modules() -> None:
    base_doc, web_doc, merged = _load_fixture(
        "modules-clear-then-add.config",
        base_name="applicationHost.config",
    )

    modules = merged.get_effective_section("/modules")
    assert modules is not None
    assert [child.attributes.get("name") for child in modules.children] == [
        "StaticFileModule",
        "RequestFilteringModule",
    ]
    assert [Path(origin.file_path).name for origin in modules.origin_chain] == [
        "applicationHost.config",
        "web.config",
    ]

    base_rule_ids = _rule_ids(base_doc, build_effective_config(base_doc))
    merged_rule_ids = _rule_ids(web_doc, merged)

    assert "iis.webdav_module_enabled" in base_rule_ids
    assert _MODULE_RULE_IDS.isdisjoint(merged_rule_ids)


def test_request_filtering_inherited_fixture_merges_children_and_rule_inputs() -> None:
    base_doc, web_doc, merged = _load_fixture(
        "requestFiltering-inherited.config",
        base_name="applicationHost.config",
    )

    request_filtering = merged.get_effective_section("/requestFiltering")
    request_limits = merged.get_effective_section("/requestLimits")
    file_extensions = merged.get_effective_section("/fileExtensions")

    assert request_filtering is not None
    assert request_limits is not None
    assert file_extensions is not None

    assert request_filtering.attributes == {"removeServerHeader": "true"}
    assert request_limits.attributes == {
        "maxAllowedContentLength": "4194304",
        "maxQueryString": "1024",
        "maxUrl": "2048",
    }
    assert file_extensions.attributes == {"allowUnlisted": "false"}
    assert [child.attributes.get("fileExtension") for child in file_extensions.children] == [
        ".config",
        ".json",
    ]
    assert [
        Path(origin.file_path).name for origin in request_filtering.origin_chain
    ] == [
        "applicationHost.config",
        "web.config",
    ]
    assert [Path(origin.file_path).name for origin in request_limits.origin_chain] == [
        "applicationHost.config",
        "web.config",
    ]
    assert [Path(origin.file_path).name for origin in file_extensions.origin_chain] == [
        "applicationHost.config",
        "web.config",
    ]

    base_rule_ids = _rule_ids(base_doc, build_effective_config(base_doc))
    merged_rule_ids = _rule_ids(web_doc, merged)

    assert {
        "iis.file_extensions_allow_unlisted",
        "iis.request_filtering_max_url_too_high",
        "iis.request_filtering_remove_server_header_disabled",
    } <= base_rule_ids
    assert _REQUEST_FILTERING_RULE_IDS.isdisjoint(merged_rule_ids)


_HTTP_COOKIES_RULE_IDS = frozenset(
    {
        "iis.http_cookies_http_only_disabled",
        "iis.http_cookies_require_ssl_missing",
    }
)


def test_three_file_chain_fixture_merges_machine_app_host_and_web_config() -> None:
    """machine.config -> applicationHost.config -> web.config full chain.

    machine.config sets safe defaults for ``httpCookies`` (HttpOnly + SSL).
    applicationHost.config does not touch them.  web.config flips both to
    unsafe values.  The effective view must reflect web.config's unsafe
    override and the cookie rules must fire pointing at web.config.
    """
    fixture_root = _FIXTURE_ROOT / "three-file-chain.config"
    machine_doc = _parse_config(fixture_root / "machine.config")
    app_host_doc = _parse_config(fixture_root / "applicationHost.config")
    web_doc = _parse_config(fixture_root / "web.config")

    machine_eff = build_effective_config(machine_doc)
    app_host_eff = build_effective_config(app_host_doc)
    web_eff = build_effective_config(web_doc)

    chain_eff = merge_effective_configs(machine_eff, app_host_eff)
    chain_eff = merge_effective_configs(chain_eff, web_eff)

    http_cookies = chain_eff.get_effective_section("/httpCookies")
    assert http_cookies is not None
    assert http_cookies.attributes.get("httpOnlyCookies") == "false"
    assert http_cookies.attributes.get("requireSSL") == "false"

    # Origin chain captures both files where the section was contributed.
    origin_files = [Path(o.file_path).name for o in http_cookies.origin_chain]
    assert origin_files == ["machine.config", "web.config"]

    # Machine.config alone has the safe values: cookie rules do not fire.
    machine_rule_ids = _rule_ids(machine_doc, machine_eff)
    assert _HTTP_COOKIES_RULE_IDS.isdisjoint(machine_rule_ids)

    # With the full chain (web.config wins with unsafe values) both
    # cookie rules fire.
    chain_rule_ids = _rule_ids(web_doc, chain_eff)
    assert _HTTP_COOKIES_RULE_IDS <= chain_rule_ids


_DIRECTORY_BROWSE_RULE_ID = "iis.directory_browse_enabled"


def test_location_inherit_false_fixture_blocks_cascade_into_child_application() -> None:
    """`<location path="X" inheritInChildApplications="false">` settings
    must not cascade into a deeper-nested child application's effective
    view.
    """
    fixture_root = _FIXTURE_ROOT / "location-inherit-false.config"
    app_host_doc = _parse_config(fixture_root / "applicationHost.config")
    web_doc = _parse_config(fixture_root / "web.config")

    app_host_eff = build_effective_config(app_host_doc)
    web_eff = build_effective_config(web_doc)

    # Base run on applicationHost.config alone exposes the unsafe
    # directoryBrowse at the location, so the rule fires there.
    base_rule_ids = _rule_ids(app_host_doc, app_host_eff)
    assert _DIRECTORY_BROWSE_RULE_ID in base_rule_ids

    # Child application at "Default Web Site/api/sub" must not inherit
    # the unsafe directoryBrowse setting.
    merged = merge_effective_configs(
        app_host_eff,
        web_eff,
        child_application_path="Default Web Site/api/sub",
    )

    # No directoryBrowse section visible in the child's global scope.
    assert merged.get_effective_section("/directoryBrowse") is None
    # And the parent's <location> section was filtered out of the
    # inherited location_sections for ancestor paths.
    assert merged.get_effective_section(
        "/directoryBrowse", location_path="Default Web Site/api"
    ) is None

    # The child's rule run must not emit the directoryBrowse finding.
    child_rule_ids = _rule_ids(web_doc, merged)
    assert _DIRECTORY_BROWSE_RULE_ID not in child_rule_ids


def test_location_inherit_false_fixture_still_applies_at_its_own_scope() -> None:
    """Sanity: settings under inheritInChildApplications=false still apply
    when the analysis target IS the location's own path (not a child)."""
    fixture_root = _FIXTURE_ROOT / "location-inherit-false.config"
    app_host_doc = _parse_config(fixture_root / "applicationHost.config")

    app_host_eff = build_effective_config(app_host_doc)
    section = app_host_eff.get_effective_section(
        "/directoryBrowse", location_path="Default Web Site/api"
    )
    assert section is not None
    assert section.attributes.get("enabled") == "true"
    assert section.inherit_in_child_applications is False


def test_location_cross_file_override_fixture_web_config_wins() -> None:
    """When applicationHost.config and web.config both declare
    `<location path="X">`, web.config's settings win on conflicting
    attributes (it is the more specific source in the chain).
    """
    fixture_root = _FIXTURE_ROOT / "location-cross-file-override.config"
    app_host_doc = _parse_config(fixture_root / "applicationHost.config")
    web_doc = _parse_config(fixture_root / "web.config")

    app_host_eff = build_effective_config(app_host_doc)
    web_eff = build_effective_config(web_doc)
    merged = merge_effective_configs(app_host_eff, web_eff)

    sec = merged.get_effective_section(
        "/directoryBrowse", location_path="Default Web Site/api"
    )
    assert sec is not None
    # web.config's override (enabled=false) wins.
    assert sec.attributes.get("enabled") == "false"
    # And the full source chain is captured (applicationHost first, then web).
    origin_files = [Path(o.file_path).name for o in sec.origin_chain]
    assert origin_files == ["applicationHost.config", "web.config"]

    # applicationHost-only run exposes the unsafe value, so the rule
    # fires for the base config.
    base_rule_ids = _rule_ids(app_host_doc, app_host_eff)
    assert _DIRECTORY_BROWSE_RULE_ID in base_rule_ids

    # Merged run with web.config override: the unsafe value is gone, so
    # the rule does not fire.
    merged_rule_ids = _rule_ids(web_doc, merged)
    assert _DIRECTORY_BROWSE_RULE_ID not in merged_rule_ids
