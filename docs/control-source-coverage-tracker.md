<!-- Generated from src/webconf_audit/data/control_source_coverage.yml; refresh with `webconf-audit coverage export --format markdown --output docs/control-source-coverage-tracker.md --force`. -->
# Control Source Coverage Tracker

This generated view summarizes scanner-evidence coverage within the declared project scope. It does not certify compliance with any source.

Target assessment is reported separately through `webconf-audit assess`; coverage status is not a per-target result.

The denominator is `full + partial + policy-review + uncovered`. Only `full` items enter the numerator.

## Snapshot Summary

| Control source | Applicable | Full | Partial | `policy-review` | Uncovered | Full coverage |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| CIS NGINX Benchmark v3.0.0 | 15 | 7 | 7 | 1 | 0 | 46.7% |
| CIS Apache HTTP Server 2.4 Benchmark v2.3.0 | 19 | 17 | 2 | 0 | 0 | 89.5% |
| CIS Microsoft IIS 10 Benchmark v1.2.1 | 10 | 8 | 1 | 0 | 1 | 80.0% |
| OWASP Top 10:2025 | 8 | 0 | 8 | 0 | 0 | 0.0% |
| OWASP ASVS v5.0.0 | 22 | 14 | 8 | 0 | 0 | 63.6% |
| NIST SP 800-52 Rev. 2 | 10 | 10 | 0 | 0 | 0 | 100.0% |
| PCI DSS v4.0.1 | 11 | 0 | 9 | 0 | 2 | 0.0% |
| ISO/IEC 27002:2022 | 10 | 8 | 2 | 0 | 0 | 80.0% |

## Status Vocabulary

| Status | Meaning |
| --- | --- |
| `full` | All mandatory subclaims are implemented for the documented scope. |
| `partial` | A real narrower signal is implemented, with explicit limitations. |
| `policy-review` | Evidence is surfaced for operator judgment. |
| `uncovered` | The item is applicable but has no adequate evidence path. |
| `excluded` | The item is outside the denominator for a documented boundary. |

## CIS NGINX Benchmark v3.0.0

Selected web-server-visible CIS NGINX controls. Package source, service-account, operating-system permission, approved-port, private-key permission, and mandatory-access-control requirements remain outside this scanner-evidence denominator.

Applicable count: 15. Full count: 7. Partial count: 7. `policy-review` count: 1. Uncovered count: 0. Excluded count: 0.

| Counted item | Status | Current basis / limitations |
| --- | --- | --- |
| NGINX v3.0.0 §2.4.2 Unknown-host handling | `full` | Local default-server checks and a bounded runtime probe detect hosts that are not rejected. |
| NGINX v3.0.0 §2.5.2 Default welcome content | `full` | Safe external probes identify the default Nginx welcome or index page. |
| NGINX v3.0.0 §2.5.4 Reverse-proxy disclosure | `partial` | The rule detects an unsafe Host forwarding pattern in reverse-proxy configuration. Limitations: Complete reverse-proxy header semantics and application-generated disclosure are not modeled. |
| NGINX v3.0.0 §3.1 Access log format | `partial` | The rule validates the presence of significant audit fields in a named log format. Limitations: The final JSON, SIEM, and organization-specific log format remains an operator policy. |
| NGINX v3.0.0 §3.3 Error log level | `partial` | The rule detects an error log level that is too restrictive for useful security diagnostics. Limitations: The preferred warn, notice, or info level depends on operating policy and workload. |
| NGINX v3.0.0 §3.4 Forwarded source-IP headers | `full` | The rule checks source-IP forwarding headers for proxy-like upstream directives. |
| NGINX v3.0.0 §4.1.1 HTTP to HTTPS redirect | `full` | Local redirect analysis and runtime redirect probes identify cleartext listeners without an HTTPS transition. |
| NGINX v3.0.0 §4.1.2 Trusted certificate chain | `partial` | Runtime certificate probing detects an incomplete served chain. Limitations: A local ssl_certificate path alone cannot prove every chain served by the deployed endpoint. |
| NGINX v3.0.0 §4.1.5 Cipher policy | `full` | The rule parses configured cipher strings and reports known weak cipher posture. |
| NGINX v3.0.0 §4.1.9 / §4.1.10 (NGINX v3.0.0 §4.1.9, NGINX v3.0.0 §4.1.10) TLS session cache and timeout | `full` | The rules validate session cache and timeout configuration in effective HTTP and server scopes. |
| NGINX v3.0.0 §4.1.12 HTTP/3 and Alt-Svc posture | `policy-review` | The opt-in rule reports the QUIC listener, effective http3 state, and effective Alt-Svc advertisement for operator review. Limitations: Runtime HTTP/3 negotiation is not proven. |
| NGINX v3.0.0 §5.1.1 Sensitive locations | `partial` | The rule detects sensitive location scopes that lack an IP restriction. Limitations: A complete sensitive-path catalog is deployment-specific. |
| NGINX v3.0.0 §5.1.2 HTTP method restrictions | `full` | The rules detect missing or unsafe HTTP method restrictions in sensitive and site-wide scopes. |
| NGINX v3.0.0 §5.2.4 / §5.2.5 (NGINX v3.0.0 §5.2.4, NGINX v3.0.0 §5.2.5) Connection and rate limit values | `partial` | Structural checks and opt-in review expose configured rate-limit values. Limitations: The reasonableness of a limit depends on the workload and capacity model. |
| NGINX v3.0.0 §5.3.2 / §5.3.3 (NGINX v3.0.0 §5.3.2, NGINX v3.0.0 §5.3.3) CSP and Referrer-Policy quality | `partial` | Header checks and opt-in CSP review expose missing or unsafe policy values. Limitations: Complete application-specific CSP and referrer semantics are not proven. |

## CIS Apache HTTP Server 2.4 Benchmark v2.3.0

Selected configuration-visible CIS Apache HTTP Server controls. Installation planning, service accounts, filesystem permissions, log storage and rotation, private-key metadata, SELinux, and AppArmor remain outside this scanner-evidence denominator.

Applicable count: 19. Full count: 17. Partial count: 2. `policy-review` count: 0. Uncovered count: 0. Excluded count: 0.

| Counted item | Status | Current basis / limitations |
| --- | --- | --- |
| Apache HTTP Server 2.4 v2.3.0 §2.1-§2.9 (Apache HTTP Server 2.4 v2.3.0 §2.1, Apache HTTP Server 2.4 v2.3.0 §2.2, Apache HTTP Server 2.4 v2.3.0 §2.3, Apache HTTP Server 2.4 v2.3.0 §2.4, Apache HTTP Server 2.4 v2.3.0 §2.5, Apache HTTP Server 2.4 v2.3.0 §2.6, Apache HTTP Server 2.4 v2.3.0 §2.7, Apache HTTP Server 2.4 v2.3.0 §2.8, Apache HTTP Server 2.4 v2.3.0 §2.9) Module minimization | `partial` | Visible LoadModule inventory and selected risky-module checks provide a bounded minimization signal. Limitations: Package and build-time module inventory and business justification are not available. |
| Apache HTTP Server 2.4 v2.3.0 §4.1-§4.2 (Apache HTTP Server 2.4 v2.3.0 §4.1, Apache HTTP Server 2.4 v2.3.0 §4.2) Authorization posture | `partial` | Effective Require and legacy allow/deny semantics are analyzed in visible configuration. Limitations: A deployment-wide authorization claim still depends on application and business context. |
| Apache HTTP Server 2.4 v2.3.0 §4.3-§4.4 (Apache HTTP Server 2.4 v2.3.0 §4.3, Apache HTTP Server 2.4 v2.3.0 §4.4) AllowOverride baseline | `full` | Root and inherited AllowOverride rules cover the visible configuration baseline. |
| Apache HTTP Server 2.4 v2.3.0 §5.1-§5.3 (Apache HTTP Server 2.4 v2.3.0 §5.1, Apache HTTP Server 2.4 v2.3.0 §5.2, Apache HTTP Server 2.4 v2.3.0 §5.3) Options baseline | `full` | Effective Options semantics cover None, ExecCGI, Includes, Indexes, MultiViews, and subtractive options. |
| Apache HTTP Server 2.4 v2.3.0 §5.4-§5.6 (Apache HTTP Server 2.4 v2.3.0 §5.4, Apache HTTP Server 2.4 v2.3.0 §5.5, Apache HTTP Server 2.4 v2.3.0 §5.6) Default content | `full` | The local probe checks active DocumentRoot paths for default HTML and CGI sample content. |
| Apache HTTP Server 2.4 v2.3.0 §5.7 HTTP method restrictions | `full` | Sensitive-scope and site-wide rules detect absent or unsafe method policy. |
| Apache HTTP Server 2.4 v2.3.0 §5.9 HTTP protocol options | `full` | The rule validates effective HttpProtocolOptions strictness. |
| Apache HTTP Server 2.4 v2.3.0 §5.10-§5.13 (Apache HTTP Server 2.4 v2.3.0 §5.10, Apache HTTP Server 2.4 v2.3.0 §5.11, Apache HTTP Server 2.4 v2.3.0 §5.12, Apache HTTP Server 2.4 v2.3.0 §5.13) Sensitive files | `full` | Rules cover backup and temporary files, .ht files, VCS metadata, and sensitive configuration extensions. |
| Apache HTTP Server 2.4 v2.3.0 §5.14-§5.15 (Apache HTTP Server 2.4 v2.3.0 §5.14, Apache HTTP Server 2.4 v2.3.0 §5.15) IP request and listen posture | `full` | Rules cover explicit listen addresses, catch-all virtual hosts, and IP request posture. |
| Apache HTTP Server 2.4 v2.3.0 §5.16-§5.18 (Apache HTTP Server 2.4 v2.3.0 §5.16, Apache HTTP Server 2.4 v2.3.0 §5.17, Apache HTTP Server 2.4 v2.3.0 §5.18) Security headers | `full` | Local rules validate framing, Referrer-Policy, and Permissions-Policy headers. |
| Apache HTTP Server 2.4 v2.3.0 §6.1 / §6.3 (Apache HTTP Server 2.4 v2.3.0 §6.1, Apache HTTP Server 2.4 v2.3.0 §6.3) Logging | `full` | Rules cover ErrorLog, CustomLog, destinations, levels, named formats, and significant fields. |
| Apache HTTP Server 2.4 v2.3.0 §6.6-§6.7 (Apache HTTP Server 2.4 v2.3.0 §6.6, Apache HTTP Server 2.4 v2.3.0 §6.7) ModSecurity and CRS | `full` | Rules check visible ModSecurity module and OWASP Core Rule Set configuration inventory. |
| Apache HTTP Server 2.4 v2.3.0 §7.1 / §7.4-§7.12 (Apache HTTP Server 2.4 v2.3.0 §7.1, Apache HTTP Server 2.4 v2.3.0 §7.4, Apache HTTP Server 2.4 v2.3.0 §7.5, Apache HTTP Server 2.4 v2.3.0 §7.6, Apache HTTP Server 2.4 v2.3.0 §7.7, Apache HTTP Server 2.4 v2.3.0 §7.8, Apache HTTP Server 2.4 v2.3.0 §7.9, Apache HTTP Server 2.4 v2.3.0 §7.10, Apache HTTP Server 2.4 v2.3.0 §7.11, Apache HTTP Server 2.4 v2.3.0 §7.12) TLS policy | `full` | Rules cover protocol, cipher, ordering, compression, renegotiation, stapling, session, HSTS, and redirect posture. |
| Apache HTTP Server 2.4 v2.3.0 §7.2 Certificate and upstream trust | `full` | Apache SSL proxy trust checks and runtime certificate probes cover observable trust posture. |
| Apache HTTP Server 2.4 v2.3.0 §8.3 Default sample content | `full` | The local content probe checks active document roots for default samples. |
| Apache HTTP Server 2.4 v2.3.0 §8.4 FileETag inode leakage | `full` | The rule detects inode-derived FileETag configuration. |
| Apache HTTP Server 2.4 v2.3.0 §9.1-§9.4 (Apache HTTP Server 2.4 v2.3.0 §9.1, Apache HTTP Server 2.4 v2.3.0 §9.2, Apache HTTP Server 2.4 v2.3.0 §9.3, Apache HTTP Server 2.4 v2.3.0 §9.4) Timeout and keepalive posture | `full` | Rules validate explicit timeout and keepalive thresholds and unsafe default posture. |
| Apache HTTP Server 2.4 v2.3.0 §9.5-§9.6 (Apache HTTP Server 2.4 v2.3.0 §9.5, Apache HTTP Server 2.4 v2.3.0 §9.6) Request read timeout | `full` | The rule models visible RequestReadTimeout and mod_reqtimeout semantics. |
| Apache HTTP Server 2.4 v2.3.0 §10.1-§10.4 (Apache HTTP Server 2.4 v2.3.0 §10.1, Apache HTTP Server 2.4 v2.3.0 §10.2, Apache HTTP Server 2.4 v2.3.0 §10.3, Apache HTTP Server 2.4 v2.3.0 §10.4) Request limits | `full` | Rules validate request line, field count, field size, and body limits. |

## CIS Microsoft IIS 10 Benchmark v1.2.1

Selected IIS and SChannel configuration-visible controls. Broader Windows host hardening, filesystem ACLs, Dynamic IP Restrictions, log storage, ETW, and legacy IIS benchmark editions remain outside this scanner-evidence denominator. FTP stays applicable and uncovered.

Applicable count: 10. Full count: 8. Partial count: 1. `policy-review` count: 0. Uncovered count: 1. Excluded count: 0.

| Counted item | Status | Current basis / limitations |
| --- | --- | --- |
| Microsoft IIS 10 v1.2.1 §1.2 Host header bindings | `full` | The rule detects HTTP and HTTPS bindings without a host name. |
| Microsoft IIS 10 v1.2.1 §1.4 / §1.5 / §1.6 (Microsoft IIS 10 v1.2.1 §1.4, Microsoft IIS 10 v1.2.1 §1.5, Microsoft IIS 10 v1.2.1 §1.6) Application identity and app pool isolation | `full` | Rules consume the effective IIS view to validate app-pool identity, cross-site pool sharing, and anonymous-user posture. |
| Microsoft IIS 10 v1.2.1 §2.1 / §2.2 (Microsoft IIS 10 v1.2.1 §2.1, Microsoft IIS 10 v1.2.1 §2.2) Authorization and anonymous access | `full` | Rules detect anonymous/authenticated access mixups and missing URL authorization policy. |
| Microsoft IIS 10 v1.2.1 §2.5 / §2.7 / §2.8 (Microsoft IIS 10 v1.2.1 §2.5, Microsoft IIS 10 v1.2.1 §2.7, Microsoft IIS 10 v1.2.1 §2.8) Forms credentials | `full` | Rules detect unsafe forms authentication, clear credential formats, and credentials stored in configuration. |
| Microsoft IIS 10 v1.2.1 §2.6 Basic Authentication over non-TLS | `full` | The rule evaluates Basic Authentication together with effective SSL requirements. |
| Microsoft IIS 10 v1.2.1 §3.1 / §3.7-§3.12 (Microsoft IIS 10 v1.2.1 §3.1, Microsoft IIS 10 v1.2.1 §3.7, Microsoft IIS 10 v1.2.1 §3.8, Microsoft IIS 10 v1.2.1 §3.9, Microsoft IIS 10 v1.2.1 §3.10, Microsoft IIS 10 v1.2.1 §3.11, Microsoft IIS 10 v1.2.1 §3.12) ASP.NET and header hardening | `full` | Rules cover retail mode, cookie flags, MachineKey, trust level, Server-header removal, and runtime header corroboration. |
| Microsoft IIS 10 v1.2.1 §4.2 / §4.3 / §4.7 / §4.9 / §4.10 (Microsoft IIS 10 v1.2.1 §4.2, Microsoft IIS 10 v1.2.1 §4.3, Microsoft IIS 10 v1.2.1 §4.7, Microsoft IIS 10 v1.2.1 §4.9, Microsoft IIS 10 v1.2.1 §4.10) Request filtering | `full` | Rules evaluate unsafe request limits, unlisted file extensions, and CGI restriction settings. |
| Microsoft IIS 10 v1.2.1 §4.8 Handler write, script, and execute policy | `full` | The handler rule detects write, script, or execute access combined with executable handlers. |
| Microsoft IIS 10 v1.2.1 §6.1 / §6.2 (Microsoft IIS 10 v1.2.1 §6.1, Microsoft IIS 10 v1.2.1 §6.2) FTP encryption and logon restrictions | `uncovered` | The project does not parse IIS FTP authorization, logon, or channel-encryption configuration. |
| Microsoft IIS 10 v1.2.1 §7.1-§7.6 / §7.10-§7.12 (Microsoft IIS 10 v1.2.1 §7.1, Microsoft IIS 10 v1.2.1 §7.2, Microsoft IIS 10 v1.2.1 §7.3, Microsoft IIS 10 v1.2.1 §7.4, Microsoft IIS 10 v1.2.1 §7.5, Microsoft IIS 10 v1.2.1 §7.6, Microsoft IIS 10 v1.2.1 §7.10, Microsoft IIS 10 v1.2.1 §7.11, Microsoft IIS 10 v1.2.1 §7.12) SChannel TLS posture | `partial` | Registry or JSON-export evidence and external TLS probes cover selected SChannel protocol and cipher settings. Limitations: Full credit requires complete SChannel evidence when registry data is absent or incomplete. |

## OWASP Top 10:2025

Selected categories with web-server configuration or safe-probe signals. Category alignment is not an application-wide OWASP assessment and does not imply compliance.

Applicable count: 8. Full count: 0. Partial count: 8. `policy-review` count: 0. Uncovered count: 0. Excluded count: 2.

| Counted item | Status | Current basis / limitations |
| --- | --- | --- |
| A01:2025 Broken Access Control | `partial` | Server-side access restrictions and exposed administrative or status endpoints provide narrower evidence. Limitations: Application authorization and object-level access control are not observable. |
| A02:2025 Security Misconfiguration | `partial` | The project detects many web-server misconfiguration signals. Limitations: The 2025 alignment is derived from reviewed A05:2021 mappings and does not prove the whole category. |
| A03:2025 Software Supply Chain Failures | `partial` | Safe probes detect publicly exposed dependency manifests. Limitations: Dependency governance, provenance, build integrity, and update processes are outside scope. |
| A04:2025 Cryptographic Failures | `partial` | TLS protocol and cipher configuration provides bounded cryptographic evidence. Limitations: The alignment is derived from reviewed A02:2021 mappings and does not cover application data cryptography. |
| A05:2025 Injection | `partial` | Rules detect selected CRLF response-splitting patterns in Nginx configuration. Limitations: Application query, command, template, and interpreter injection sinks are not analyzed. |
| A07:2025 Authentication Failures | `partial` | Safe probes detect selected exposed credential files. Limitations: Complete identity, session, enrollment, and recovery flows are not observable. |
| A08:2025 Software or Data Integrity Failures | `partial` | The SRI probe detects external scripts lacking observable integrity metadata. Limitations: Build, update, artifact-signing, and deployment integrity are outside scope. |
| A09:2025 Security Logging and Alerting Failures | `partial` | Server log-format rules detect missing significant audit fields. Limitations: Active alerting, SIEM routing, retention, and incident response are not proven. |
| A06:2025 Insecure Design | `excluded` | Application design assurance is outside the web-server configuration and safe-probe perimeter. Exclusion: The category requires application threat modeling and design evidence. Boundary: Application architecture and secure design lifecycle. |
| A10:2025 Mishandling of Exceptional Conditions | `excluded` | Application exceptional-condition handling is outside the web-server configuration and safe-probe perimeter. Exclusion: The category requires application control-flow and failure-handling evidence. Boundary: Application source code and runtime exception behavior. |

## OWASP ASVS v5.0.0

Selected ASVS 5.0 web frontend, transport, and deployed-resource requirements. The ledger records scanner evidence, not an ASVS verification or certification.

Applicable count: 22. Full count: 14. Partial count: 8. `policy-review` count: 0. Uncovered count: 0. Excluded count: 0.

| Counted item | Status | Current basis / limitations |
| --- | --- | --- |
| v5.0.0-3.3.1 / 3.3.2 / 3.3.3 / 3.3.4 (v5.0.0-3.3.1, v5.0.0-3.3.2, v5.0.0-3.3.3, v5.0.0-3.3.4) Cookie security attributes | `partial` | Runtime cookie probes observe Secure, HttpOnly, SameSite, and __Secure-/__Host- prefix contracts. Limitations: Only cookies observed in bounded responses are assessed. |
| v5.0.0-3.4.1 HTTP Strict Transport Security | `full` | Universal, local, and external rules validate HSTS presence and significant policy values. |
| v5.0.0-3.4.2 Cross-origin resource sharing | `partial` | Runtime rules detect wildcard and credential combinations. Limitations: Application-specific origin allowlists and route semantics are not proven. |
| v5.0.0-3.4.3 Content Security Policy quality | `partial` | Rules detect missing or unsafe CSP directives, nonce reuse, and selected SRI gaps. Limitations: Complete application-specific nonce, hash, and source authorization is not proven. |
| v5.0.0-3.4.4 Content type sniffing protection | `full` | Universal, local, and external rules detect missing or invalid X-Content-Type-Options. |
| v5.0.0-3.4.5 Referrer policy | `full` | Rules detect missing or unsafe Referrer-Policy values. |
| v5.0.0-3.4.6 Framing policy | `full` | Local and runtime CSP framing rules detect missing frame-ancestors protection. |
| v5.0.0-3.4.7 CSP reporting | `partial` | Rules detect configured reporting syntax or observed header presence. Limitations: Receiver ownership, availability, retention, and response handling are not tested. |
| v5.0.0-3.4.8 Cross-Origin-Opener-Policy | `partial` | A runtime rule observes a missing COOP header. Limitations: Document isolation relevance depends on application behavior. |
| v5.0.0-3.7.1 Authenticated routes require TLS | `full` | The normalized universal rule detects authentication-requiring scopes exposed on non-TLS listeners. |
| v5.0.0-12.1.1 Deprecated TLS protocols | `full` | Local, SChannel, normalized, and external rules detect deprecated protocol posture. |
| v5.0.0-12.1.2 TLS cipher posture | `partial` | Local and runtime checks detect selected weak cipher and negotiation signals. Limitations: The project is not a complete cipher-inventory and client-compatibility suite. |
| v5.0.0-12.1.4 OCSP and must-staple | `partial` | Local stapling checks and runtime observations provide revocation-related evidence. Limitations: End-to-end revocation availability and policy assurance are not proven. |
| v5.0.0-12.2.1 HTTPS without cleartext fallback | `full` | TLS-intent, redirect, authentication-over-HTTP, and runtime HTTPS probes cover cleartext fallback posture. |
| v5.0.0-12.2.2 Certificate validation | `full` | Runtime and proxy-trust rules detect selected certificate validation failures. |
| v5.0.0-13.4.1 Source-control metadata exposure | `full` | Safe probes detect exposed .git and .svn metadata. |
| v5.0.0-13.4.2 Production debug features | `full` | IIS and external rules detect visible debug features and detailed error endpoints. |
| v5.0.0-13.4.3 Directory listings | `full` | Universal, server-specific, and runtime rules detect enabled directory listing. |
| v5.0.0-13.4.4 TRACE method | `full` | Local and external rules detect enabled TRACE behavior. |
| v5.0.0-13.4.5 Documentation and monitoring endpoints | `full` | Safe probes and server rules detect public status, information, Swagger UI, and OpenAPI specification endpoints. |
| v5.0.0-13.4.6 Component and version disclosure | `full` | Server token, header, and dependency-manifest rules detect component or version disclosure. |
| v5.0.0-13.4.7 Exposed secret and configuration material | `partial` | Local deny-list rules and safe artifact probes detect selected sensitive files. Limitations: A complete application-specific allowlist and secret inventory are outside scope. |

## NIST SP 800-52 Rev. 2

Selected TLS server requirements from NIST SP 800-52 Rev. 2.

Applicable count: 10. Full count: 10. Partial count: 0. `policy-review` count: 0. Uncovered count: 0. Excluded count: 0.

| Counted item | Status | Current basis / limitations |
| --- | --- | --- |
| 3.1.1 / 3.1.2 (3.1.1, 3.1.2) TLS version posture | `full` | Local, SChannel, normalized, and external rules detect deprecated TLS versions. |
| 3.3.1 Recommended cipher posture | `full` | Weak cipher checks and runtime AEAD or forward-secrecy observations cover the selected posture. |
| 3.3.2 Server cipher preference | `full` | Local preference directives and bounded runtime observations provide server preference evidence. |
| 3.4 Certificate validity and chain quality | `full` | External X.509 probes validate expiry, identity, chain, and selected signature properties. |
| 3.5 Secure renegotiation | `full` | Local unsafe-renegotiation checks and runtime handshake evidence cover renegotiation posture. |
| 3.6 TLS compression | `full` | Local and runtime rules detect enabled or negotiated TLS compression. |
| 4.2 OCSP and must-staple | `full` | Local stapling rules and runtime must-staple observations provide OCSP-related evidence. |
| 4.3 Revocation evidence | `full` | The runtime OCSP stapling probe provides direct observable revocation evidence. |
| 4.2.4 HTTP Strict Transport Security | `full` | Universal, local, and external HSTS rules cover significant policy posture. |
| NO PLAINTEXT FALLBACK No plaintext fallback | `full` | Redirect, TLS-intent, and runtime HTTPS rules detect plaintext fallback. |

## PCI DSS v4.0.1

Selected PCI DSS requirements with server-visible evidence. The ledger records related scanner signals and does not determine cardholder-data scope or PCI DSS compliance.

Applicable count: 11. Full count: 0. Partial count: 9. `policy-review` count: 0. Uncovered count: 2. Excluded count: 2.

| Counted item | Status | Current basis / limitations |
| --- | --- | --- |
| Req. 2.2.1 Configuration standards | `partial` | The registry links web-server hardening findings to configuration-standard evidence. Limitations: The scanner cannot prove a complete maintained standard across every in-scope component. |
| Req. 2.2.5 Insecure services and protocols | `partial` | Rules detect selected risky modules, methods, WebDAV, CGI, and exposed status services. Limitations: Business justification and complete service necessity review remain organizational. |
| Req. 2.2.6 System security parameters | `partial` | Rules detect selected disclosure, default-content, debug, and exposed-file conditions. Limitations: Complete in-scope parameter coverage is not proven. |
| Req. 4.2.1 Strong cryptography over public networks | `partial` | TLS, HSTS, redirect, and plaintext-fallback rules provide transport evidence. Limitations: The scanner cannot determine whether a route transmits PAN over an open public network. |
| Req. 6.2.4 Software engineering techniques | `uncovered` | Related hardening findings do not prove secure software engineering techniques. |
| Req. 6.4.3 Payment-page script management | `partial` | The cross-origin SRI probe covers a bounded payment-page script integrity signal. Limitations: Script authorization, inventory, change control, and payment-page scope are not proven. |
| Req. 8.3.1 Authentication-factor protection | `partial` | Server-visible authentication configuration and exposed credential files provide bounded evidence. Limitations: Complete authentication-factor lifecycle protection is not observable. |
| Req. 8.3.2 Cryptographic protection in transit | `partial` | Rules detect authentication paths exposed without required TLS. Limitations: Complete authentication data flow and endpoint scope are not proven. |
| Req. 8.3.5 / 8.3.6 (Req. 8.3.5, Req. 8.3.6) Password reset and complexity requirements | `uncovered` | Current web-server rules do not observe first-use password changes, reset handling, length, or composition. |
| Req. 10.2.1 Audit logging enabled | `partial` | Configuration rules detect selected missing access and error logging. Limitations: Active logging across every in-scope component is not proven. |
| Req. 10.2.2 Audit log event details | `partial` | Rules validate selected significant access-log fields. Limitations: The complete required event set and detail semantics are not proven. |
| Req. 10.5 Audit log retention and protection | `excluded` | Retention and protection depend on storage, access control, and operational processes. Exclusion: The requirement needs host, storage, and process evidence not available to the analyzer. Boundary: Log storage, retention, integrity protection, and operational access. |
| Req. 12 Organizational security policies | `excluded` | Organizational policy governance is outside server configuration analysis. Exclusion: The requirement is organizational and process-oriented. Boundary: Security policy, roles, governance, risk management, and personnel processes. |

## ISO/IEC 27002:2022

Selected ISO/IEC 27002:2022 controls with web-server-visible technical evidence. The mapping is an engineering alignment, not an ISO conformity assessment.

Applicable count: 10. Full count: 8. Partial count: 2. `policy-review` count: 0. Uncovered count: 0. Excluded count: 0.

| Counted item | Status | Current basis / limitations |
| --- | --- | --- |
| 5.15 Access control | `full` | Local authorization, authentication, method, and sensitive-scope rules provide direct configuration evidence. |
| 8.5 Secure authentication | `full` | Rules detect Basic Authentication over cleartext, unsafe credentials, and selected authentication posture. |
| 8.15 Logging | `full` | Access and error log enablement, destination, and field-quality rules provide direct evidence. |
| 8.16 Monitoring activities | `partial` | Logging findings provide server-side monitoring inputs. Limitations: Alerting, SOC workflows, correlation, and incident response are outside scope. |
| 8.18 Privileged utility programs | `partial` | Rules detect selected CGI, WebDAV, handler, and server-status capabilities. Limitations: Complete privileged utility inventory, authorization, and governance require host and process context. |
| 8.20 Network security | `full` | Listener, host-binding, catch-all virtual-host, and IP request rules provide direct network configuration evidence. |
| 8.21 Network services security | `full` | TLS, HSTS, redirect, and plaintext authentication rules provide direct network-service evidence. |
| 8.24 Use of cryptography | `full` | TLS protocol, cipher, compression, renegotiation, and certificate rules provide direct cryptographic evidence. |
| 8.26 Application security requirements | `full` | Declared direct CORS, TRACE, and production-debug rules complement the broader header and cookie evidence. |
| 8.27 Secure architecture and engineering principles | `full` | Configuration hardening, least-functionality, and exposed-resource rules provide direct engineering evidence. |
