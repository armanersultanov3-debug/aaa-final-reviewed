"""Tests for auth-requiring route normalization and the universal TLS rule."""

from __future__ import annotations

from webconf_audit.local.apache.parser import parse_apache_config
from webconf_audit.local.iis.effective import IISEffectiveConfig
from webconf_audit.local.iis.parser import IISConfigDocument
from webconf_audit.local.lighttpd.effective import LighttpdEffectiveConfig
from webconf_audit.local.lighttpd.parser import LighttpdConfigAst
from webconf_audit.local.nginx.parser.parser import NginxParser, NginxTokenizer
from webconf_audit.local.normalizers.apache_normalizer import normalize_apache
from webconf_audit.local.normalizers.iis_normalizer import normalize_iis
from webconf_audit.local.normalizers.lighttpd_normalizer import normalize_lighttpd
from webconf_audit.local.normalizers.nginx_normalizer import normalize_nginx
from webconf_audit.local.universal_rules import run_universal_rules


def _rule_ids(config) -> set[str]:
    return {finding.rule_id for finding in run_universal_rules(config)}


def _apache_config(text: str):
    return normalize_apache(
        parse_apache_config(text, file_path="/etc/apache2/httpd.conf"),
    )


def _nginx_config(text: str):
    ast = NginxParser(
        NginxTokenizer(text, file_path="/etc/nginx/nginx.conf").tokenize(),
    ).parse()
    return normalize_nginx(ast)


def _empty_iis_doc() -> IISConfigDocument:
    return IISConfigDocument(
        root_tag="configuration",
        config_kind="web",
        sections=[],
        file_path="C:/inetpub/web.config",
    )


def _auth_location_set(config) -> set[tuple[str, str, bool]]:
    return {
        (location.path, location.auth_kind, location.requires_tls)
        for location in config.auth_requiring_locations
    }


def test_apache_tls_only_auth_scope_does_not_fire():
    cfg = _apache_config(
        "Listen 443 https\n"
        "<VirtualHost *:443>\n"
        "    SSLEngine On\n"
        "    <Location /admin>\n"
        "        AuthType Basic\n"
        "        Require valid-user\n"
        "    </Location>\n"
        "</VirtualHost>\n",
    )

    assert len(cfg.auth_requiring_locations) == 1
    assert ("/admin", "basic", True) in _auth_location_set(cfg)
    assert "universal.tls_required_for_authenticated_routes" not in _rule_ids(cfg)


def test_apache_plain_listener_fires():
    cfg = _apache_config(
        "Listen 80\n"
        "<VirtualHost *:80>\n"
        "    SSLEngine Off\n"
        "    <Location /admin>\n"
        "        AuthType Basic\n"
        "        Require valid-user\n"
        "    </Location>\n"
        "</VirtualHost>\n",
    )

    assert len(cfg.auth_requiring_locations) == 1
    assert ("/admin", "basic", False) in _auth_location_set(cfg)
    assert "universal.tls_required_for_authenticated_routes" in _rule_ids(cfg)


def test_apache_mixed_listener_fires():
    cfg = _apache_config(
        "Listen 80\n"
        "Listen 443 https\n"
        "<VirtualHost *:80 *:443>\n"
        "    SSLEngine On\n"
        "    <Location /admin>\n"
        "        AuthType Basic\n"
        "        Require valid-user\n"
        "    </Location>\n"
        "</VirtualHost>\n",
    )

    assert len(cfg.auth_requiring_locations) == 1
    assert ("/admin", "basic", False) in _auth_location_set(cfg)
    assert "universal.tls_required_for_authenticated_routes" in _rule_ids(cfg)


def test_apache_require_only_scope_is_extracted():
    cfg = _apache_config(
        "Listen 80\n"
        "<Location /staff>\n"
        "    Require group admins\n"
        "</Location>\n",
    )

    assert len(cfg.auth_requiring_locations) == 1
    assert ("/staff", "group", False) in _auth_location_set(cfg)
    assert "universal.tls_required_for_authenticated_routes" in _rule_ids(cfg)


def test_apache_requireall_scope_is_extracted():
    cfg = _apache_config(
        "Listen 80\n"
        "<Location /staff>\n"
        "    <RequireAll>\n"
        "        Require valid-user\n"
        "    </RequireAll>\n"
        "</Location>\n",
    )

    assert len(cfg.auth_requiring_locations) == 1
    assert ("/staff", "valid-user", False) in _auth_location_set(cfg)
    assert "universal.tls_required_for_authenticated_routes" in _rule_ids(cfg)


def test_apache_directorymatch_scope_is_extracted():
    cfg = _apache_config(
        "Listen 80\n"
        "<DirectoryMatch ^/var/www/private>\n"
        "    AuthType Basic\n"
        "    Require valid-user\n"
        "</DirectoryMatch>\n",
    )

    assert len(cfg.auth_requiring_locations) == 1
    assert ("^/var/www/private", "basic", False) in _auth_location_set(cfg)
    assert "universal.tls_required_for_authenticated_routes" in _rule_ids(cfg)


def test_apache_tls_vhost_on_nonstandard_port_still_counts_as_tls():
    cfg = _apache_config(
        "Listen 8443\n"
        "<VirtualHost *:8443>\n"
        "    SSLEngine On\n"
        "    <Location /admin>\n"
        "        AuthType Basic\n"
        "        Require valid-user\n"
        "    </Location>\n"
        "</VirtualHost>\n",
    )

    assert len(cfg.auth_requiring_locations) == 1
    assert ("/admin", "basic", True) in _auth_location_set(cfg)
    assert "universal.tls_required_for_authenticated_routes" not in _rule_ids(cfg)


def test_apache_tls_vhost_on_port_80_still_counts_as_tls():
    cfg = _apache_config(
        "Listen 80\n"
        "<VirtualHost *:80>\n"
        "    SSLEngine On\n"
        "    <Location /admin>\n"
        "        AuthType Basic\n"
        "        Require valid-user\n"
        "    </Location>\n"
        "</VirtualHost>\n",
    )

    assert len(cfg.auth_requiring_locations) == 1
    assert ("/admin", "basic", True) in _auth_location_set(cfg)
    assert "universal.tls_required_for_authenticated_routes" not in _rule_ids(cfg)


def test_apache_global_ssl_on_nonstandard_port_counts_as_tls():
    cfg = _apache_config(
        "Listen 8443\n"
        "SSLEngine On\n"
        "<Location /admin>\n"
        "    AuthType Basic\n"
        "    Require valid-user\n"
        "</Location>\n",
    )

    assert len(cfg.auth_requiring_locations) == 1
    assert ("/admin", "basic", True) in _auth_location_set(cfg)
    assert "universal.tls_required_for_authenticated_routes" not in _rule_ids(cfg)


def test_apache_authtype_none_disables_auth_scope():
    cfg = _apache_config(
        "Listen 443 https\n"
        "SSLEngine On\n"
        "<Location /admin>\n"
        "    AuthType Basic\n"
        "    Require valid-user\n"
        "    AuthType None\n"
        "</Location>\n",
    )

    assert cfg.auth_requiring_locations == ()
    assert "universal.tls_required_for_authenticated_routes" not in _rule_ids(cfg)


def test_apache_no_auth_extracted():
    cfg = _apache_config("Listen 80\n")

    assert cfg.auth_requiring_locations == ()
    assert "universal.tls_required_for_authenticated_routes" not in _rule_ids(cfg)


def test_nginx_tls_only_auth_basic_does_not_fire():
    cfg = _nginx_config(
        "http {\n"
        "    server {\n"
        "        listen 443 ssl;\n"
        "        location /admin {\n"
        '            auth_basic "private";\n'
        "            auth_basic_user_file /etc/nginx/.htpasswd;\n"
        "        }\n"
        "    }\n"
        "}\n",
    )

    assert len(cfg.auth_requiring_locations) == 1
    assert ("/admin", "basic", True) in _auth_location_set(cfg)
    assert "universal.tls_required_for_authenticated_routes" not in _rule_ids(cfg)


def test_nginx_plain_auth_basic_fires():
    cfg = _nginx_config(
        "http {\n"
        "    server {\n"
        "        listen 80;\n"
        "        location /admin {\n"
        '            auth_basic "private";\n'
        "            auth_basic_user_file /etc/nginx/.htpasswd;\n"
        "        }\n"
        "    }\n"
        "}\n",
    )

    assert len(cfg.auth_requiring_locations) == 1
    assert ("/admin", "basic", False) in _auth_location_set(cfg)
    assert "universal.tls_required_for_authenticated_routes" in _rule_ids(cfg)


def test_nginx_auth_request_and_auth_jwt_are_extracted():
    cfg = _nginx_config(
        "http {\n"
        "    server {\n"
        "        listen 80;\n"
        "        location /request {\n"
        "            auth_request /internal/auth;\n"
        "        }\n"
        "        location /jwt {\n"
        '            auth_jwt "private";\n'
        "        }\n"
        "    }\n"
        "}\n",
    )

    assert len(cfg.auth_requiring_locations) == 2
    assert _auth_location_set(cfg) == {
        ("/request", "request", False),
        ("/jwt", "jwt", False),
    }
    assert "universal.tls_required_for_authenticated_routes" in _rule_ids(cfg)


def test_nginx_server_level_auth_is_extracted_as_root_scope():
    cfg = _nginx_config(
        "http {\n"
        "    server {\n"
        "        listen 80;\n"
        '        auth_basic "private";\n'
        "        location /admin {\n"
        "            proxy_pass http://backend;\n"
        "        }\n"
        "    }\n"
        "}\n",
    )

    assert ("/", "basic", False) in _auth_location_set(cfg)
    assert "universal.tls_required_for_authenticated_routes" in _rule_ids(cfg)


def test_nginx_http_level_auth_is_inherited():
    cfg = _nginx_config(
        "http {\n"
        '    auth_basic "private";\n'
        "    server {\n"
        "        listen 80;\n"
        "        location /admin {\n"
        "            proxy_pass http://backend;\n"
        "        }\n"
        "    }\n"
        "}\n",
    )

    assert ("/", "basic", False) in _auth_location_set(cfg)
    assert "universal.tls_required_for_authenticated_routes" in _rule_ids(cfg)


def test_nginx_server_auth_off_disables_inherited_http_auth():
    cfg = _nginx_config(
        "http {\n"
        '    auth_basic "private";\n'
        "    server {\n"
        "        listen 80;\n"
        "        auth_basic off;\n"
        "        location /admin {\n"
        "            proxy_pass http://backend;\n"
        "        }\n"
        "    }\n"
        "}\n",
    )

    assert cfg.auth_requiring_locations == ()
    assert "universal.tls_required_for_authenticated_routes" not in _rule_ids(cfg)


def test_nginx_location_root_auth_off_disables_inherited_server_auth():
    cfg = _nginx_config(
        "http {\n"
        "    server {\n"
        "        listen 80;\n"
        '        auth_basic "private";\n'
        "        location / {\n"
        "            auth_basic off;\n"
        "        }\n"
        "    }\n"
        "}\n",
    )

    assert cfg.auth_requiring_locations == ()
    assert "universal.tls_required_for_authenticated_routes" not in _rule_ids(cfg)


def test_nginx_auth_basic_off_disables_auth_scope():
    cfg = _nginx_config(
        "http {\n"
        "    server {\n"
        "        listen 80;\n"
        "        location /admin {\n"
        '            auth_basic "private";\n'
        "            auth_basic off;\n"
        "        }\n"
        "    }\n"
        "}\n",
    )

    assert cfg.auth_requiring_locations == ()
    assert "universal.tls_required_for_authenticated_routes" not in _rule_ids(cfg)


def test_nginx_mixed_listeners_fires():
    cfg = _nginx_config(
        "http {\n"
        "    server {\n"
        "        listen 80;\n"
        "        listen 443 ssl;\n"
        "        location /admin {\n"
        '            auth_basic "private";\n'
        "            auth_basic_user_file /etc/nginx/.htpasswd;\n"
        "        }\n"
        "    }\n"
        "}\n",
    )

    assert len(cfg.auth_requiring_locations) == 1
    assert ("/admin", "basic", False) in _auth_location_set(cfg)
    assert "universal.tls_required_for_authenticated_routes" in _rule_ids(cfg)


def test_nginx_named_location_is_ignored():
    cfg = _nginx_config(
        "http {\n"
        "    server {\n"
        "        listen 80;\n"
        "        location @fallback {\n"
        '            auth_basic "private";\n'
        "        }\n"
        "    }\n"
        "}\n",
    )

    assert cfg.auth_requiring_locations == ()
    assert "universal.tls_required_for_authenticated_routes" not in _rule_ids(cfg)


def test_nginx_no_auth_extracted():
    cfg = _nginx_config("http {\n    server {\n        listen 80;\n    }\n}\n")

    assert cfg.auth_requiring_locations == ()
    assert "universal.tls_required_for_authenticated_routes" not in _rule_ids(cfg)


def test_empty_iis_and_lighttpd_configs_have_no_auth_locations_or_findings():
    iis_cfg = normalize_iis(_empty_iis_doc(), effective_config=IISEffectiveConfig(global_sections={}))
    lighttpd_cfg = normalize_lighttpd(LighttpdConfigAst(nodes=[]), effective_config=LighttpdEffectiveConfig())

    for cfg in (iis_cfg, lighttpd_cfg):
        assert cfg.auth_requiring_locations == ()
        assert "universal.tls_required_for_authenticated_routes" not in _rule_ids(cfg)
