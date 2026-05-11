from webconf_audit.local.apache.rules.directory_without_allowoverride import (
    find_directory_without_allowoverride,
)
from tests.apache_helpers import parse_apache_config


def _parse(config_text: str):
    return parse_apache_config(config_text, file_path="httpd.conf")


def _location_tuple(finding):
    assert finding.location is not None
    return finding.location.file_path, finding.location.line


def test_directory_root_skipped_owned_by_other_rule() -> None:
    findings = find_directory_without_allowoverride(
        _parse(
            "<Directory />\n"
            "    Options None\n"
            "</Directory>\n"
            '<Directory "/var/www">\n'
            "    AllowOverride None\n"
            "</Directory>\n"
        )
    )

    assert findings == []


def test_non_root_directory_with_no_allowoverride_anywhere_finds() -> None:
    findings = find_directory_without_allowoverride(
        _parse(
            '<Directory "/var/www">\n'
            "    Options -Indexes\n"
            "</Directory>\n"
        )
    )

    assert len(findings) == 1
    finding = findings[0]
    assert _location_tuple(finding) == ("httpd.conf", 1)
    assert finding.metadata == {"directory_path": "/var/www"}


def test_non_root_directory_inherits_allowoverride_from_server_level_silent() -> None:
    findings = find_directory_without_allowoverride(
        _parse(
            '<Directory "/var/www">\n'
            "    AllowOverride None\n"
            "</Directory>\n"
            "<VirtualHost *:80>\n"
            "    ServerName app.test\n"
            '    <Directory "/var/www">\n'
            "        Options -Indexes\n"
            "    </Directory>\n"
            "</VirtualHost>\n"
        )
    )

    assert findings == []


def test_non_root_directory_inherits_allowoverride_from_parent_directory_silent() -> None:
    findings = find_directory_without_allowoverride(
        _parse(
            '<Directory "/var/www">\n'
            "    AllowOverride None\n"
            "</Directory>\n"
            '<Directory "/var/www/app">\n'
            "    Options -Indexes\n"
            "</Directory>\n"
        )
    )

    assert findings == []


def test_main_server_directory_missing_not_masked_by_vhost_override() -> None:
    findings = find_directory_without_allowoverride(
        _parse(
            '<Directory "/srv/www">\n'
            "    Options -Indexes\n"
            "</Directory>\n"
            "<VirtualHost *:80>\n"
            "    ServerName app.test\n"
            '    <Directory "/srv/www">\n'
            "        AllowOverride None\n"
            "    </Directory>\n"
            "</VirtualHost>\n"
        )
    )

    assert len(findings) == 1
    finding = findings[0]
    assert _location_tuple(finding) == ("httpd.conf", 1)
    assert finding.metadata == {"directory_path": "/srv/www"}


def test_non_root_directory_explicit_allowoverride_silent() -> None:
    findings = find_directory_without_allowoverride(
        _parse(
            '<Directory "/var/www">\n'
            "    AllowOverride FileInfo AuthConfig\n"
            "    Options -Indexes\n"
            "</Directory>\n"
        )
    )

    assert findings == []


def test_non_root_directory_inside_ifmodule_disabled_no_finding() -> None:
    findings = find_directory_without_allowoverride(
        _parse(
            "LoadModule rewrite_module modules/mod_rewrite.so\n"
            "<IfModule !mod_rewrite.c>\n"
            '    <Directory "/var/www">\n'
            "        Options -Indexes\n"
            "    </Directory>\n"
            "</IfModule>\n"
        )
    )

    assert findings == []


def test_redirect_only_vhost_directory_skipped() -> None:
    findings = find_directory_without_allowoverride(
        _parse(
            "<VirtualHost *:80>\n"
            "    ServerName redirect.test\n"
            "    Redirect permanent / https://redirect.test/\n"
            '    <Directory "/var/www/redirect">\n'
            "        Options -Indexes\n"
            "    </Directory>\n"
            "</VirtualHost>\n"
        )
    )

    assert findings == []


def test_two_vhosts_only_one_has_explicit_allowoverride_finding_for_other() -> None:
    findings = find_directory_without_allowoverride(
        _parse(
            "<VirtualHost *:80>\n"
            "    ServerName alpha.test\n"
            '    <Directory "/var/www/app">\n'
            "        AllowOverride None\n"
            "        Options -Indexes\n"
            "    </Directory>\n"
            "</VirtualHost>\n"
            "<VirtualHost *:80>\n"
            "    ServerName beta.test\n"
            '    <Directory "/var/www/app">\n'
            "        Options -Indexes\n"
            "    </Directory>\n"
            "</VirtualHost>\n"
        )
    )

    assert len(findings) == 1
    finding = findings[0]
    assert _location_tuple(finding) == ("httpd.conf", 10)
    assert finding.metadata == {
        "scope_name": "beta.test",
        "directory_path": "/var/www/app",
    }
