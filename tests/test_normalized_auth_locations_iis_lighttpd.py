"""IIS and Lighttpd auth-location normalization for the TLS universal rule."""

from __future__ import annotations

from webconf_audit.local.iis.effective import build_effective_config as build_iis_effective
from webconf_audit.local.iis.parser import parse_iis_config
from webconf_audit.local.lighttpd.conditions import LighttpdRequestContext
from webconf_audit.local.lighttpd.effective import (
    build_effective_config as build_lighttpd_effective,
    merge_conditional_scopes,
)
from webconf_audit.local.lighttpd.parser import parse_lighttpd_config
from webconf_audit.local.normalizers.iis_normalizer import normalize_iis
from webconf_audit.local.normalizers.lighttpd_normalizer import normalize_lighttpd
from webconf_audit.local.universal_rules import run_universal_rules


def _rule_ids(config) -> set[str]:
    return {finding.rule_id for finding in run_universal_rules(config)}


def _auth_location_set(config) -> set[tuple[str, str, bool]]:
    return {
        (location.path, location.auth_kind, location.requires_tls)
        for location in config.auth_requiring_locations
    }


def _iis_config(text: str):
    doc = parse_iis_config(
        text,
        file_path="C:/Windows/System32/inetsrv/config/applicationHost.config",
    )
    effective = build_iis_effective(doc)
    return normalize_iis(doc, effective_config=effective)


def _lighttpd_config(text: str):
    ast = parse_lighttpd_config(
        text,
        file_path="/etc/lighttpd/lighttpd.conf",
    )
    effective = build_lighttpd_effective(ast)
    return normalize_lighttpd(ast, effective_config=effective)


def test_iis_basic_auth_on_https_binding_requires_tls() -> None:
    cfg = _iis_config(
        """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.applicationHost>
        <sites>
            <site name="demo" id="1">
                <bindings>
                    <binding protocol="https" bindingInformation="*:443:" />
                </bindings>
            </site>
        </sites>
    </system.applicationHost>
    <system.webServer>
        <security>
            <authentication>
                <basicAuthentication enabled="true" />
            </authentication>
        </security>
    </system.webServer>
</configuration>
""",
    )

    assert _auth_location_set(cfg) == {("/", "basic", True)}
    assert "universal.tls_required_for_authenticated_routes" not in _rule_ids(cfg)


def test_iis_basic_auth_on_http_binding_fires() -> None:
    cfg = _iis_config(
        """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.applicationHost>
        <sites>
            <site name="demo" id="1">
                <bindings>
                    <binding protocol="http" bindingInformation="*:80:" />
                </bindings>
            </site>
        </sites>
    </system.applicationHost>
    <system.webServer>
        <security>
            <authentication>
                <basicAuthentication enabled="true" />
            </authentication>
        </security>
    </system.webServer>
</configuration>
""",
    )

    assert _auth_location_set(cfg) == {("/", "basic", False)}
    assert "universal.tls_required_for_authenticated_routes" in _rule_ids(cfg)


def test_iis_http_binding_with_ssl_flags_requires_tls() -> None:
    cfg = _iis_config(
        """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.applicationHost>
        <sites>
            <site name="demo" id="1">
                <bindings>
                    <binding protocol="http" bindingInformation="*:80:" />
                </bindings>
            </site>
        </sites>
    </system.applicationHost>
    <system.webServer>
        <security>
            <access sslFlags="Ssl" />
            <authentication>
                <basicAuthentication enabled="true" />
            </authentication>
        </security>
    </system.webServer>
</configuration>
""",
    )

    assert _auth_location_set(cfg) == {("/", "basic", True)}
    assert "universal.tls_required_for_authenticated_routes" not in _rule_ids(cfg)


def test_iis_forms_auth_without_explicit_forms_section_is_extracted() -> None:
    cfg = _iis_config(
        """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.applicationHost>
        <sites>
            <site name="demo" id="1">
                <bindings>
                    <binding protocol="https" bindingInformation="*:443:" />
                </bindings>
            </site>
        </sites>
    </system.applicationHost>
    <system.web>
        <authentication mode="Forms" />
    </system.web>
</configuration>
""",
    )

    assert _auth_location_set(cfg) == {("/", "forms", True)}
    assert "universal.tls_required_for_authenticated_routes" not in _rule_ids(cfg)


def test_lighttpd_auth_require_inside_tls_socket_scope_does_not_fire() -> None:
    cfg = _lighttpd_config(
        'server.port = 80\n'
        '$SERVER["socket"] == ":443" {\n'
        '    ssl.engine = "enable"\n'
        '    auth.require = ( "/admin" => ( "method" => "basic", '
        '"realm" => "private", "require" => "valid-user" ) )\n'
        "}\n",
    )

    assert _auth_location_set(cfg) == {("/admin", "basic", True)}
    assert "universal.tls_required_for_authenticated_routes" not in _rule_ids(cfg)


def test_lighttpd_auth_require_outside_tls_only_scope_fires() -> None:
    cfg = _lighttpd_config(
        'server.port = 80\n'
        'auth.require = ( "/admin" => ( "method" => "basic", '
        '"realm" => "private", "require" => "valid-user" ) )\n',
    )

    assert _auth_location_set(cfg) == {("/admin", "basic", False)}
    assert "universal.tls_required_for_authenticated_routes" in _rule_ids(cfg)


def test_lighttpd_merged_scope_uses_host_filtered_auth_locations() -> None:
    ast = parse_lighttpd_config(
        'server.port = 80\n'
        'auth.require = ( "/global" => ( "method" => "basic", '
        '"realm" => "private", "require" => "valid-user" ) )\n'
        '$HTTP["host"] == "secure.example.test" {\n'
        '    ssl.engine = "enable"\n'
        '    auth.require = ( "/secure" => ( "method" => "basic", '
        '"realm" => "private", "require" => "valid-user" ) )\n'
        "}\n",
        file_path="/etc/lighttpd/lighttpd.conf",
    )
    effective = build_lighttpd_effective(ast)
    merged = merge_conditional_scopes(
        effective,
        context=LighttpdRequestContext(host="secure.example.test"),
    )

    cfg = normalize_lighttpd(
        ast,
        effective_config=effective,
        merged_directives=merged,
    )

    assert _auth_location_set(cfg) == {("/secure", "basic", True)}
    assert "universal.tls_required_for_authenticated_routes" not in _rule_ids(cfg)


def test_lighttpd_ast_fallback_extracts_auth_require_locations() -> None:
    ast = parse_lighttpd_config(
        'auth.require = ( "/admin" => ( "method" => "basic", '
        '"realm" => "private", "require" => "valid-user" ) )\n',
        file_path="/etc/lighttpd/lighttpd.conf",
    )

    cfg = normalize_lighttpd(ast)

    assert _auth_location_set(cfg) == {("/admin", "basic", False)}
    assert "universal.tls_required_for_authenticated_routes" in _rule_ids(cfg)
