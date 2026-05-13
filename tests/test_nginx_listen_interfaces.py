from __future__ import annotations

import pytest

from webconf_audit.local.nginx.parser.parser import NginxParser, NginxTokenizer
from webconf_audit.local.normalized import NormalizedConfig, NormalizedListenPoint
from webconf_audit.local.normalizers.nginx_normalizer import normalize_nginx
from webconf_audit.local.universal_rules import run_universal_rules


def _normalized_nginx_config(listen_directive: str) -> NormalizedConfig:
    text = (
        "http {\n"
        "    server {\n"
        f"        {listen_directive};\n"
        "    }\n"
        "}\n"
    )
    tokens = NginxTokenizer(text, file_path="/etc/nginx/nginx.conf").tokenize()
    ast = NginxParser(tokens).parse()
    return normalize_nginx(ast)


def _listen_point(listen_directive: str) -> NormalizedListenPoint:
    cfg = _normalized_nginx_config(listen_directive)
    assert len(cfg.scopes) == 1
    assert len(cfg.scopes[0].listen_points) == 1
    return cfg.scopes[0].listen_points[0]


@pytest.mark.parametrize(
    ("listen_directive", "expected_address", "expected_port", "expected_kind"),
    [
        ("listen 80", None, 80, "wildcard_ipv4"),
        ("listen 0.0.0.0:80", "0.0.0.0", 80, "wildcard_ipv4"),
        ("listen 127.0.0.1:80", "127.0.0.1", 80, "loopback"),
        ("listen [::]:80", "[::]", 80, "wildcard_ipv6"),
        ("listen [::1]:80", "[::1]", 80, "loopback"),
        ("listen unix:/var/run/nginx.sock", "unix:/var/run/nginx.sock", 0, "unix"),
        ("listen 1.2.3.4:80", "1.2.3.4", 80, "specific"),
    ],
)
def test_nginx_listen_forms_are_classified(
    listen_directive: str,
    expected_address: str | None,
    expected_port: int,
    expected_kind: str,
) -> None:
    listen_point = _listen_point(listen_directive)

    assert listen_point.address == expected_address
    assert listen_point.port == expected_port
    assert listen_point.address_kind == expected_kind


@pytest.mark.parametrize(
    ("listen_directive", "should_emit"),
    [
        ("listen 80", True),
        ("listen 0.0.0.0:80", True),
        ("listen [::]:80", True),
        ("listen 127.0.0.1:80", False),
        ("listen [::1]:80", False),
        ("listen 1.2.3.4:80", False),
        ("listen unix:/var/run/nginx.sock", False),
    ],
)
def test_universal_listen_rule_only_fires_for_wildcards(
    listen_directive: str,
    should_emit: bool,
) -> None:
    cfg = _normalized_nginx_config(listen_directive)
    rule_ids = {finding.rule_id for finding in run_universal_rules(cfg)}

    assert ("universal.listen_on_all_interfaces" in rule_ids) is should_emit
