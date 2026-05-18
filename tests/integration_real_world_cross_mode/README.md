# Real-world cross-mode integration tests

This directory brings up real-world web server configs in Docker containers
bound to localhost ports and asserts that:

1. The **local** analyzer (`analyze-nginx`, `analyze-apache`,
   `analyze-lighttpd`) flags the expected issues against the *source config
   file* shipped with the case.
2. The **external** analyzer (`analyze-external`) flags the expected issues
   when probing the same container over `http(s)://127.0.0.1:<port>/`.
3. Cross-mode invariants hold: for HTTPS endpoints, every "missing header"
   finding the local analyzer reports must also surface in the external
   probe.

The local and external analyzers are independent code paths; this is the
closest end-to-end regression we have for the whole pipeline.

## Safety

- Every endpoint binds on `127.0.0.1` only. No port forwarder leaks the
  service to the rest of the host network.
- Self-signed TLS certificates are generated at image build time inside the
  container; no third-party CA or domain is touched.
- The external analyzer is invoked with `scan_ports=False` so no port
  enumeration leaves the host network namespace.

## Cases (11)

| Case | Server | Scheme | Port | Origin |
|---|---|---|---|---|
| `nginx-docker-default` | nginx | http | 18100 | Stock nginx Docker default layout |
| `nginx-docs-reverse-proxy` | nginx | http | 18101 | NGINX reverse-proxy documentation (with an `http-echo` upstream sidecar in the same network namespace) |
| `nginx-docs-tls-server` | nginx | https | 18102 | NGINX SSL/TLS termination documentation |
| `apache-docker-httpd-default` | apache | http | 18103 | Apache httpd Docker default layout |
| `apache-docs-vhost-htaccess` | apache | http | 18104 | Apache VirtualHost + `.htaccess` documentation |
| `apache-docs-tls-vhost` | apache | https | 18105 | Apache `mod_ssl` example vhost |
| `lighttpd-docs-default` | lighttpd | http | 18106 | Lighttpd sample/default configuration |
| `lighttpd-docs-fastcgi-tls` | lighttpd | https | 18107 | Lighttpd `mod_openssl` documentation |
| `nginx-mozilla-modern` | nginx | https | 18108 | Mozilla SSL Configuration Generator (modern) |
| `nginx-mozilla-intermediate` | nginx | https | 18109 | Mozilla SSL Configuration Generator (intermediate) |
| `nginx-mozilla-old` | nginx | https | 18110 | Mozilla SSL Configuration Generator (old) |

The full per-case metadata, including source URLs and the rule subsets we
expect to fire, lives in [`manifest.json`](./manifest.json).

## Patches applied to public configs

Two public configs needed small fixes to actually run in their stock images;
the public-source-derived copies in `demo/real_world_configs/` are left
unchanged for documentation fidelity:

- `apache-docs-vhost-htaccess` and `apache-docs-tls-vhost`: changed
  `Options -Indexes FollowSymLinks` to `Options -Indexes +FollowSymLinks`.
  Apache rejects mixed-sign Options groups since 2.4.
- `lighttpd-docs-default`: relative `var.server_root = "www"` /
  `var.log_root = "logs"` replaced with absolute `/opt/lighttpd/...`. Newer
  lighttpd (1.4.79+) rejects relative document-root.
- `lighttpd-docs-fastcgi-tls`: same absolute-paths patch; removed the
  `mod_fastcgi` block (the demo expects a PHP backend we deliberately do not
  ship) but kept the TLS half intact.

These patches are intentional — they reflect the same fixups a real admin
would apply before deploying a copy-pasted documentation snippet.

## Running

```shell
# All cases
uv run --locked pytest tests/integration_real_world_cross_mode

# A single case
uv run --locked pytest tests/integration_real_world_cross_mode -k nginx-mozilla-modern
```

The session-scoped fixture in [`conftest.py`](./conftest.py) brings the
compose stack up before any test and tears it down afterwards. If Docker is
not available the suite is skipped collectively.
