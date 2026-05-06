from pathlib import Path

import pytest

from webconf_audit.local.iis import analyze_iis_config
from webconf_audit.local.iis.effective import build_effective_config
from webconf_audit.local.iis.parser import (
    IISParseError,
    parse_iis_config,
)
from webconf_audit.models import AnalysisResult


_SAFE_BASELINE_ALLOWED_RULE_IDS = {
    "iis.authorization_policy_missing",
    "iis.deployment_retail_not_enabled",
    "iis.http_cookies_http_only_disabled",
    "iis.http_cookies_require_ssl_missing",
    "iis.http_runtime_version_header_enabled",
    "iis.missing_hsts_header",
    "iis.logging_not_configured",
    "iis.max_allowed_content_length_missing",
    "iis.request_filtering_allow_high_bit",
    "iis.request_filtering_max_query_string_missing",
    "iis.request_filtering_max_url_missing",
    "iis.request_filtering_remove_server_header_disabled",
    "iis.schannel_aes256_not_enabled",
    "iis.trust_level_full",
}

MINIMAL_APPLICATION_HOST_CONFIG = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.applicationHost>
        <sites>
            <site name="Default Web Site" id="1">
                <bindings>
                    <binding protocol="http" bindingInformation="*:80:example.test" />
                </bindings>
            </site>
        </sites>
    </system.applicationHost>
    <system.webServer>
        <security>
            <requestFiltering>
                <requestLimits maxAllowedContentLength="30000000" />
                <fileExtensions allowUnlisted="false" />
            </requestFiltering>
        </security>
    </system.webServer>
</configuration>
"""

MINIMAL_WEB_CONFIG = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <httpErrors errorMode="Custom" />
        <security>
            <requestFiltering>
                <requestLimits maxAllowedContentLength="4194304" />
                <fileExtensions allowUnlisted="false" />
            </requestFiltering>
        </security>
    </system.webServer>
    <system.web>
        <compilation debug="false" />
        <customErrors mode="RemoteOnly" />
    </system.web>
</configuration>
"""


__all__ = [
    "AnalysisResult",
    "IISParseError",
    "MINIMAL_APPLICATION_HOST_CONFIG",
    "MINIMAL_WEB_CONFIG",
    "Path",
    "_SAFE_BASELINE_ALLOWED_RULE_IDS",
    "analyze_iis_config",
    "build_effective_config",
    "parse_iis_config",
    "pytest",
]
