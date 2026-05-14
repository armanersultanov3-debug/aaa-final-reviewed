# Local Analysis Demo

This folder contains a practical end-to-end scenario for the `local`
analysis mode of `webconf-audit`.

The demo:

- simulates a local administrator workflow;
- passes the main configuration file to the CLI;
- lets `webconf-audit` resolve includes and inheritance from that
  entrypoint;
- validates that the same configuration trees are accepted by the
  real server binaries running in Docker containers.

## Covered Servers

- Nginx
- Apache HTTP Server
- Lighttpd
- Microsoft IIS

Compose services (Nginx, Apache, Lighttpd only — IIS has no Docker validation):

- `nginx`
- `apache`
- `lighttpd`

Each scenario uses a main config file plus additional include or inheritance
artifacts where the server model requires them:

- `nginx/nginx.conf`
- `apache/conf/httpd.conf`
- `lighttpd/lighttpd.conf`
- `iis/web.config`
- `iis/machine.config`

## Directory Layout

```text
demo/local_admin/
|-- docker-compose.yml
|-- README.md
|-- nginx/
|   |-- nginx.conf
|   `-- conf.d/insecure.conf
|-- apache/
|   `-- conf/
|       |-- httpd.conf
|       `-- extra/insecure.conf
|-- apache\htdocs/
|   `-- .htaccess
|-- lighttpd/
|   |-- lighttpd.conf
|   |-- conf.d/insecure.conf
|   `-- docker/Dockerfile
|-- iis/
|   |-- machine.config
|   `-- web.config
`-- reports/
```

## What Is Intentionally Demonstrated

### Nginx

Main entrypoint: `nginx/nginx.conf`

Included file: `nginx/conf.d/insecure.conf`

Intentional findings:

- `nginx.server_tokens_on`
- `nginx.autoindex_on`
- `nginx.if_in_location`

### Apache HTTP Server

Main entrypoint: `apache/conf/httpd.conf`

Included file: `apache/conf/extra/insecure.conf`

Additional distributed config: `apache\htdocs/.htaccess`

Intentional findings:

- `apache.options_indexes`
- `apache.options_includes_enabled`
- `apache.index_options_fancyindexing_enabled`
- `apache.index_options_scanhtmltitles_enabled`
- `apache.allowoverride_all_in_directory`
- `apache.htaccess_enables_directory_listing`
- `apache.htaccess_enables_cgi`
- `apache.htaccess_disables_security_headers`
- `apache.htaccess_rewrite_without_limit`
- `apache.htaccess_weakens_security`
- `apache.htaccess_contains_security_directive` (×3: Options, Options, Header)
- `apache.server_status_exposed`

The Apache demo now exercises more than a flat global config:
- `VirtualHost` with `ServerName` / `ServerAlias`;
- `Location` inside a `VirtualHost`;
- `.htaccess` discovery from `DocumentRoot`;
- `AllowOverride`-controlled `.htaccess` findings;
- a global `/server-status` location defined through the included file.

### Lighttpd

Main entrypoint: `lighttpd/lighttpd.conf`

Included file: `lighttpd/conf.d/insecure.conf`

Intentional findings:

- `lighttpd.dir_listing_enabled` (from `conf.d/insecure.conf`)
- `lighttpd.weak_ssl_cipher_list` (from `conf.d/insecure.conf`)
- `lighttpd.ssl_honor_cipher_order_missing` (from `conf.d/insecure.conf`)
- `lighttpd.missing_strict_transport_security` (absence finding)
- `lighttpd.missing_x_content_type_options` (absence finding)
- `lighttpd.url_access_deny_missing` (absence finding)
- `lighttpd.mod_status_public` (from `lighttpd.conf`, no remoteip restriction)
- `lighttpd.access_log_missing` (mod_accesslog loaded without accesslog.filename)
- `lighttpd.max_request_size_missing` (absence finding)
- `lighttpd.max_connections_missing` (absence finding)
- `lighttpd.mod_cgi_enabled` (from `lighttpd.conf`)

The Lighttpd demo demonstrates variable expansion (`var.basedir`), findings
split across files, a valid but weak TLS listener on `:8443` backed by a
generated self-signed PEM inside the demo image, and absence-based rules that
fire when hardening directives are not present.

### Microsoft IIS

Main entrypoint: `iis/web.config`

Inherited base config: `iis/machine.config`

No Docker validation (IIS does not run in Linux containers).

Intentional findings:

- `iis.directory_browse_enabled` (directoryBrowse enabled="true")
- `iis.http_errors_detailed` (errorMode="Detailed")
- `iis.ssl_not_required` (sslFlags="None")
- `iis.ssl_weak_cipher_strength` (sslFlags="Ssl" without Ssl128 at location "api")
- `iis.request_filtering_allow_double_escaping` (allowDoubleEscaping="true")
- `iis.request_filtering_allow_high_bit` (allowHighBitCharacters="true")
- `iis.max_allowed_content_length_missing` (requestLimits without maxAllowedContentLength)
- `iis.logging_not_configured` (dontLog="true")
- `iis.custom_headers_expose_server` (X-Powered-By + X-AspNetMvc-Version)
- `iis.missing_hsts_header` (no Strict-Transport-Security in customHeaders)
- `iis.asp_script_error_sent_to_browser` (scriptErrorSentToBrowser="true")
- `iis.webdav_module_enabled` (WebDAVModule in modules collection)
- `iis.cgi_handler_enabled` (CgiModule handler mapping)
- `iis.custom_errors_off` (customErrors mode="Off")
- `iis.compilation_debug_enabled` (debug="true")
- `iis.trace_enabled` (trace enabled="true")
- `iis.http_runtime_version_header_enabled` (enableVersionHeader="true")
- `iis.forms_auth_require_ssl_missing` (requireSSL="false")
- `iis.session_state_cookieless` (cookieless="UseUri")
- `iis.anonymous_auth_enabled` (anonymous + basic auth combination)

The IIS demo exercises all 20 IIS local rules, including attribute-based
checks, collection/children-based checks (WebDAV, CGI, custom headers),
absence checks (HSTS, logging, content length), cross-section checks
(anonymous auth combination), and location-scoped findings (weak TLS at
"api" path). It also exercises the three-level inheritance chain used by the
analyzer: `machine.config → applicationHost.config`-equivalent base →
`web.config`.

## Docker Compose Workflow

Bring the validation environment up:

```powershell
docker compose -f demo/local_admin/docker-compose.yml up -d --build
```

The services use fixed Compose names and fixed container names:

- `nginx` -> `webconf-audit-validation-nginx`
- `apache` -> `webconf-audit-validation-apache`
- `lighttpd` -> `webconf-audit-validation-lighttpd`

They also use `restart: unless-stopped` so the stack can stay up as a persistent
local demo environment between manual checks.

Stop and remove the containers:

```powershell
docker compose -f demo/local_admin/docker-compose.yml down --remove-orphans
```

## Native Server Syntax Checks

Nginx:

```powershell
docker compose -f demo/local_admin/docker-compose.yml run --rm nginx nginx -t -c /etc/nginx/nginx.conf
```

Apache:

```powershell
docker compose -f demo/local_admin/docker-compose.yml run --rm apache httpd -t -f /usr/local/apache2/conf/httpd.conf
```

Lighttpd:

```powershell
docker compose -f demo/local_admin/docker-compose.yml run --rm lighttpd lighttpd -tt -f /etc/lighttpd/lighttpd.conf
```

## Running `webconf-audit`

Nginx:

```powershell
.\.venv\Scripts\python.exe -m webconf_audit.cli analyze-nginx .\demo\local_admin\nginx\nginx.conf
```

Apache:

```powershell
.\.venv\Scripts\python.exe -m webconf_audit.cli analyze-apache .\demo\local_admin\apache\conf\httpd.conf
```

Lighttpd:

```powershell
.\.venv\Scripts\python.exe -m webconf_audit.cli analyze-lighttpd .\demo\local_admin\lighttpd\lighttpd.conf
```

IIS:

```powershell
.\.venv\Scripts\python.exe -m webconf_audit.cli analyze-iis .\demo\local_admin\iis\web.config --machine-config .\demo\local_admin\iis\machine.config
```

### JSON Output

All `analyze-*` commands support `--format json` (or `-f json`) for
machine-readable output:

```powershell
.\.venv\Scripts\python.exe -m webconf_audit.cli analyze-nginx .\demo\local_admin\nginx\nginx.conf --format json
.\.venv\Scripts\python.exe -m webconf_audit.cli analyze-apache .\demo\local_admin\apache\conf\httpd.conf -f json
```

The JSON envelope contains `generated_at`, `summary`, `results`,
`findings` (severity-sorted), and `issues` (level-sorted).

## Helper Scripts

### Local Analysis

For a single reproducible end-to-end run of local (file-based) analysis:

```powershell
.\scripts\run_local_admin_demo.ps1
```

The script:

1. builds/pulls the needed images;
2. validates each config with the native server binary;
3. starts the three containers through Docker Compose;
4. runs `webconf-audit` against the main config file of each server (including IIS);
5. generates both text and JSON reports for each server;
6. writes observed outputs to `demo/local_admin/reports/`;
7. leaves the Compose stack running for manual inspection.

### External Analysis

With the Compose stack already running, probe the servers from outside:

```powershell
.\scripts\run_external_demo.ps1
```

The script:

1. checks that the Compose containers are running;
2. probes each server via `analyze-external localhost:PORT --no-scan-ports`;
3. generates text and JSON reports for nginx (18080), apache (18081), lighttpd (18082);
4. saves reports to `demo/local_admin/reports/`.

Since the containers run on localhost without TLS, TLS-specific findings will
not appear. This is expected for a local demo.

## Observed Result From The Current Run

The current scenario was executed in the local environment and confirmed that:

- all three Linux config sets pass native server syntax validation;
- all three containers can be started successfully;
- `webconf-audit` analyzes each scenario from the main config path;
- findings from included files are surfaced with the included file path in the output;
- Apache analysis sees global config, included config, `VirtualHost`, and `.htaccess` together;
- IIS analysis runs from `web.config` with explicit `machine.config` inheritance (no Docker).

Observed findings in the confirmed run (server-specific + universal):

- Nginx: `9 findings / 0 issues` (8 server-specific + 1 universal, 1 suppressed)
- Apache: `39 findings / 0 issues` (35 server-specific + 4 universal)
- Lighttpd: `28 findings / 0 issues` (21 server-specific + 7 universal, 1 suppressed)
- IIS: `52 findings / 1 issue` (47 server-specific + 5 universal, 2 suppressed)

Universal findings (rule IDs starting with `universal.`) come from the
normalization layer and are common across all servers. They cover TLS
configuration, security headers, directory listing, server identification
disclosure, and listen-address auditing.

## Port Mapping

The Compose stack publishes host ports for external probing:

| Service   | Host Port | Container Port |
|-----------|-----------|----------------|
| nginx     | 18080     | 80             |
| apache    | 18081     | 80             |
| lighttpd  | 18082     | 8080           |

These ports allow `analyze-external` to probe running servers from the host.

## Limitations

- This is a practical demo scenario, not a generalized integration framework.
- The scenario intentionally covers only a small subset of the implemented rules.
- The Apache scenario uses a minimal real configuration that fits the current
  parser, not the full stock `httpd.conf` from the official image.
- Containers run on localhost without TLS, so TLS-specific external findings
  will not appear.
