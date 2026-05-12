# Benchmarks Covering — Cross-Standard Mapping And Backlog

This document is the cross-cutting benchmarks/standards companion to
`docs/rule-coverage.md` and `docs/standards-roadmap.md`. It records, for every
standard or benchmark family that is **not yet** in the canonical
`CWE / OWASP / ASVS / CIS` columns, an honest **candidate** mapping against the
existing 374-rule inventory plus the rule-level work needed to cover the
remaining requirements honestly.

Nothing in this document changes rule behaviour. It is a planning artefact.
The same documentation-only fence used by `docs/standards-roadmap.md` applies:
no rule registry edits, no CIS section IDs added to the existing rule rows of
`docs/rule-coverage.md`, no severity / tag / metadata changes. Final rule
column updates live in dedicated standards-mapping PRs that follow this
planning document.

## 1. Why a separate file

`docs/standards-roadmap.md` covers **CIS NGINX v3.0.0**, **CIS Apache HTTP
Server 2.4 v2.3.0**, **CIS Microsoft IIS 10 v1.2.1**, **OWASP Top 10 2021**,
**OWASP ASVS v5.0.0**, and **CWE**. Everything outside that perimeter — NIST,
PCI DSS, HIPAA, ISO/IEC 27001/27002, CIS Critical Security Controls v8, BSI
IT-Grundschutz, MITRE ATT&CK Enterprise, OWASP Cheat Sheet Series, OWASP API
Security Top 10, CWE Top 25, Lighttpd vendor / DevSec lighttpd-baseline,
**ФСТЭК / ФСБ / ГОСТ / ЦБ РФ** — is currently unmapped or only mentioned in
prose. This file is the single planning surface for those families.

## 2. Methodology

The same conservative rules apply as in `docs/standards-roadmap.md`:

- Cite exact, versioned identifiers. No standard reference from memory.
- Prefer an empty cell over a stretched mapping.
- Mark partial coverage with the limitation, e.g.
  `NIST SP 800-52 Rev. 2 §3.3.1 (partial: observed negotiated cipher posture only)`.
- Use the existing gap labels: `covered`, `direct-rule`, `parser-depth`,
  `probe-depth`, `out-of-scope`, `research`. Historical `host-depth` items are
  treated as out of scope because this tool does not inspect host OS posture.
- Treat every entry below as a **candidate** until a follow-up PR moves the
  reference into the canonical `docs/rule-coverage.md` columns.

Direct rule citations refer to rule IDs already shipped in the registry. They
can be looked up in `docs/rule-coverage.md` for severity, input kind, and the
existing CWE / OWASP / ASVS / CIS mappings.

## 3. Source baseline

Sources verified as published or current standards on 2026-05-05:

- [NIST SP 800-52 Rev. 2](https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final)
  — *Guidelines for the Selection, Configuration, and Use of TLS
  Implementations*, August 2019.
- [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
  — *Security and Privacy Controls for Information Systems and Organizations*,
  September 2020 (with control updates through Rev. 5.1.1).
- [NIST SP 800-44 Version 2](https://csrc.nist.gov/publications/detail/sp/800-44/ver-2/final)
  — *Guidelines on Securing Public Web Servers*, September 2007. Dated but
  still on the NIST Publications list; treat it as historical/legacy where the
  newer SP 800-53/52 control families overlap.
- [NIST SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html)
  — *Digital Identity Guidelines: Authentication and Lifecycle Management*.
- [NIST Cybersecurity Framework 2.0](https://www.nist.gov/cyberframework)
  — released February 2024.
- [PCI DSS v4.0.1](https://docs-prv.pcisecuritystandards.org/PCI%20DSS/Standard/PCI-DSS-v4_0_1.pdf)
  — *Payment Card Industry Data Security Standard*, June 2024.
- [CIS Critical Security Controls v8.1](https://www.cisecurity.org/controls/v8-1)
  — released June 2024.
- *HIPAA Security Rule*, 45 CFR Part 164, Subpart C
  ([§164.302–§164.318](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C)).
- [ISO/IEC 27001:2022](https://www.iso.org/standard/27001) and
  [ISO/IEC 27002:2022](https://www.iso.org/standard/75652.html).
- [BSI IT-Grundschutz Compendium](https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/IT-Grundschutz/IT-Grundschutz-Kompendium/it-grundschutz-kompendium_node.html)
  — module **APP.3.2 Web-Server**, current edition.
- [MITRE ATT&CK Enterprise v15](https://attack.mitre.org/versions/v15/)
  — released April 2024.
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/) — living
  reference; cheat sheets are versioned individually.
- [OWASP API Security Top 10 (2023)](https://owasp.org/API-Security/editions/2023/en/0x00-header/).
- [CWE Top 25 Most Dangerous Software Weaknesses (2024)](https://cwe.mitre.org/top25/archive/2024/2024_cwe_top25.html).
- [DevSec lighttpd-baseline](https://github.com/dev-sec/lighttpd-baseline)
  — community InSpec profile; treat as vendor-style guidance, not a
  benchmark.
- [lighttpd Security wiki](https://redmine.lighttpd.net/projects/lighttpd/wiki/Docs_Security)
  — vendor security notes.

Russian sources verified on the same date:

- ФСТЭК России, [Приказ № 17 от 11.02.2013](https://fstec.ru/dokumenty/vse-dokumenty/prikazy/prikaz-fstek-rossii-ot-11-fevralya-2013-g-n-17)
  «Об утверждении Требований о защите информации, не составляющей
  государственную тайну, содержащейся в государственных информационных
  системах» (с учётом действующих редакций).
- ФСТЭК России, [Приказ № 21 от 18.02.2013](https://fstec.ru/dokumenty/vse-dokumenty/prikazy/prikaz-fstek-rossii-ot-18-fevralya-2013-g-n-21)
  «Об утверждении Состава и содержания организационных и технических мер по
  обеспечению безопасности персональных данных при их обработке в
  информационных системах персональных данных».
- ФСТЭК России, методический документ «Меры защиты информации в
  государственных информационных системах», 11.02.2014, разделы **ИАФ**,
  **УПД**, **РСБ**, **АНЗ**, **ЗИС**.
- ФСТЭК России, [Банк данных угроз](https://bdu.fstec.ru/) (БДУ) —
  каталог угроз `УБИ.NNN`.
- ФСБ России, [Приказ № 378 от 10.07.2014](http://publication.pravo.gov.ru/Document/View/0001201408180004)
  «Об утверждении Состава и содержания организационных и технических мер по
  обеспечению безопасности персональных данных… с использованием средств
  криптографической защиты информации».
- [ГОСТ Р 57580.1-2017](https://docs.cntd.ru/document/1200146534)
  «Безопасность финансовых (банковских) операций. Защита информации
  финансовых организаций».
- ГОСТ Р ИСО/МЭК 27001-2021, ГОСТ Р ИСО/МЭК 27002-2021 — локализованные
  редакции ISO/IEC 27001/27002.
- Банк России, [Положение № 683-П от 17.04.2019](http://www.cbr.ru/Queries/UniDbQuery/File/90134/1185)
  и Положение № 716-П от 08.04.2020 — требования к защите информации в
  финансовых организациях и управлению операционным риском.
- НКЦКИ / ГосСОПКА — система обмена сведениями об инцидентах. Контекст для
  логирования.

## 4. Already covered standards (recap)

| Standard | Where it lives | Status |
| --- | --- | --- |
| CWE | `docs/rule-coverage.md` (per-rule column) and `webconf_audit/standards.py:cwe()` | Complete across all five rule families. |
| OWASP Top 10 2021 | `docs/rule-coverage.md` (per-rule column) and `webconf_audit/standards.py:owasp_top10_2021()` | Complete across all five rule families. |
| OWASP ASVS v5.0.0 | `docs/rule-coverage.md` (`ASVS` column) plus follow-up gap list in `docs/standards-roadmap.md` | First-pass complete; direct-rule follow-up from `STD-GAP-013` is now folded into the current mapping, with deeper TLS/runtime follow-up still tracked in `STD-GAP-014`. |
| CIS NGINX Benchmark v3.0.0 | `docs/rule-coverage.md` (`CIS / Vendor` column) plus the Nginx gap table in the same file | Existing-rule reference pass complete. |
| CIS Apache HTTP Server 2.4 v2.3.0 | `docs/rule-coverage.md` plus the Apache gap table in the same file | Existing-rule reference pass complete. |
| CIS Microsoft IIS 10 v1.2.1 (incl. SChannel) | `docs/rule-coverage.md` plus the IIS/SChannel gap table in the same file | Existing-rule reference pass complete. |

This document does not duplicate those mappings. It only references them when
a row crosses standards (for example, the same TLS rule that already cites
ASVS v5.0.0-12.1.1 is also a NIST SP 800-52 Rev. 2 §3.1 candidate).

## 5. Standards not yet planned — candidate coverage

For each standard below the table layout is:

- **Already-covered rules** — rule IDs whose existing signal honestly proves
  the requirement. Merits a `covered` or partial `(partial: …)` cell after
  review.
- **Partial / cross-source rules** — rule IDs where the signal is real but
  scoped narrower than the standard control or relies on a different mode
  (config vs. probe vs. host).
- **Gap follow-up** — concrete rule additions needed to cover the remaining
  parts of the standard. Gap label is one of the canonical labels.

### 5.1 NIST SP 800-52 Rev. 2 — TLS Selection / Configuration

NIST SP 800-52 Rev. 2 is the closest external mirror for the universal /
external / per-server TLS rules already in the registry.

| 800-52 Rev. 2 section | Topic | Already-covered rules (candidate `covered`) | Partial / cross-source rules | Gap follow-up |
| --- | --- | --- | --- | --- |
| §3.1.1 / §3.1.2 | TLS 1.2 mandatory; TLS 1.3 recommended | `universal.weak_tls_protocol`, `nginx.weak_ssl_protocols`, `apache.tls_legacy_versions_explicitly_enabled`, `apache.ssl_protocol_missing_or_weak`, `lighttpd.tls_legacy_versions_explicitly_enabled`, `lighttpd.ssl_protocol_policy_missing_or_weak`, `iis.schannel_tls12_not_enabled`, `iis.schannel_weak_protocol_enabled`, `external.tls_1_0_supported`, `external.tls_1_1_supported` | `nginx.missing_ssl_protocols` (presence-only), `external.tls_1_3_not_supported` (info) | — |
| §3.3.1 | Recommended cipher suites | `universal.weak_tls_ciphers`, `nginx.ssl_ciphers_weak`, `apache.ssl_cipher_suite_weak`, `lighttpd.weak_ssl_cipher_list`, `iis.schannel_aes128_enabled`, `iis.schannel_aes256_not_enabled`, `iis.ssl_weak_cipher_strength`, `external.weak_cipher_suite` | `nginx.missing_ssl_ciphers`, `apache.ssl_cipher_suite_missing` (presence-only companion rules), `external.tls_forward_secrecy_not_observed`, `external.tls_aead_cipher_not_negotiated` (partial: observed negotiated cipher posture only) | `covered`: observe-only coverage now includes single-handshake forward-secrecy and AEAD posture evidence; preference-order proof remains tracked under §3.3.2. |
| §3.3.2 | Server preference order | `apache.ssl_honor_cipher_order_not_on`, `lighttpd.ssl_honor_cipher_order_missing`, `nginx.missing_ssl_prefer_server_ciphers`, `iis.schannel_cipher_suite_order_not_preferred` | `external.tls_server_cipher_preference_not_observed` (partial: bounded TLS 1.2 probe only) | `partial`: bounded multi-offer TLS 1.2 observation exists, but broader preference inventory remains out of scope for observe-only mode. |
| §3.4 | Server certificate validation | `external.certificate_expired`, `external.certificate_expires_soon`, `external.tls_certificate_self_signed`, `external.cert_chain_incomplete`, `external.cert_san_mismatch`, `external.tls_ct_log_evidence_missing`, `external.tls_weak_signature_algorithm` | `external.cert_chain_length_unusual` (advisory) | — |
| §3.5 | Insecure renegotiation disabled | `apache.ssl_insecure_renegotiation_enabled`, `nginx.ssl_conf_command_unsafe_renegotiation_enabled`, `lighttpd.ssl_insecure_renegotiation_enabled` | `external.tls_secure_renegotiation_not_observed` (partial: initial handshake advertisement only) | `covered`: observe-only mode now records whether the initial ServerHello advertised secure renegotiation support; no active renegotiation attempt is performed. |
| §3.6 | TLS compression disabled | `apache.ssl_compression_enabled`, `nginx.ssl_conf_command_tls_compression_enabled`, `lighttpd.ssl_compression_enabled` | `external.tls_negotiated_compression` (partial: initial handshake observation only) | `covered`: observe-only mode now records the negotiated compression method from the initial handshake; TLS 1.3 remains excluded because compression is forbidden there. |
| §4.2.4 | HSTS strongly recommended | `universal.missing_hsts`, `nginx.missing_hsts_header`, `nginx.hsts_header_unsafe`, `apache.missing_hsts_header`, `apache.hsts_header_unsafe`, `lighttpd.missing_strict_transport_security`, `lighttpd.strict_transport_security_unsafe`, `iis.missing_hsts_header`, `iis.hsts_header_unsafe`, `external.hsts_header_missing`, `external.hsts_header_invalid`, `external.hsts_max_age_too_short`, `external.hsts_missing_include_subdomains` | — | — |
| §4.2 / §4.3 | OCSP stapling | `nginx.ssl_stapling_disabled`, `nginx.ssl_stapling_missing_resolver`, `nginx.ssl_stapling_without_verify`, `apache.ssl_use_stapling_not_on`, `apache.ssl_stapling_cache_missing`, `external.tls_must_staple_not_observed` | `external.ocsp_stapling_not_observed` (generic handshake evidence only) | — |
| Top-level "no plaintext fallback" | Reject HTTP for sensitive endpoints | `universal.tls_intent_without_config`, `nginx.missing_ssl_certificate`, `nginx.missing_ssl_certificate_key`, `nginx.missing_http_to_https_redirect`, `nginx.auth_basic_over_http`, `apache.missing_http_to_https_redirect`, `apache.basic_auth_over_http`, `lighttpd.ssl_engine_not_enabled`, `lighttpd.ssl_pemfile_missing`, `lighttpd.basic_auth_over_http`, `iis.ssl_not_required`, `iis.basic_auth_without_ssl`, `iis.forms_auth_require_ssl_missing`, `external.https_not_available`, `external.http_not_redirected_to_https` | — | — |

### 5.2 NIST SP 800-53 Rev. 5 — Security Controls

The closest control families for `webconf-audit` are SC (System and
Communications Protection), AU (Audit and Accountability), AC (Access
Control), CM (Configuration Management), IA (Identification and
Authentication), and SI (System and Information Integrity).

| 800-53 Rev. 5 control | Topic | Already-covered rules (candidate `covered` / `partial`) | Gap follow-up |
| --- | --- | --- | --- |
| SC-8 / SC-8(1) | Transmission confidentiality and integrity | All TLS-presence and HTTP→HTTPS rules from §5.1 above. | `parser-depth`: a `tls_required_for_authenticated_routes` rule using effective-config when an auth-requiring location lacks `ssl` listener selection. |
| SC-13 | Cryptographic protection | All weak-protocol / weak-cipher / cipher-order rules from §5.1 above. | — |
| SC-23 / SC-23(3) | Session authenticity | `external.cookie_missing_secure_on_https`, `external.cookie_missing_httponly`, `external.cookie_missing_samesite`, `external.cookie_samesite_none_without_secure`, `external.cookie_prefix_contract_violated`, `iis.http_cookies_http_only_disabled`, `iis.session_state_cookieless`, `iis.forms_auth_protection_unsafe` | — |
| AC-3 / AC-3(7) | Access enforcement | `nginx.allow_all_with_deny_all`, `nginx.missing_access_restrictions_on_sensitive_locations`, `nginx.sensitive_location_missing_ip_filter`, `lighttpd.url_access_deny_missing`, `iis.authorization_allows_anonymous_users`, `iis.anonymous_auth_enabled`, `apache.allowoverride_all_in_directory`, `apache.allowoverride_not_none`, `apache.htaccess_*` family | `parser-depth`: Apache inherited/effective authorization coverage now includes `Require local` plus legacy `Order` / `Allow` / `Deny` / `Satisfy` defaults for the current status/info and request-method rules; broader application-specific authorization matrices still need deployment context. |
| AC-4 | Information flow enforcement | `nginx.proxy_missing_source_ip_headers` | `parser-depth`: outbound proxy / upstream TLS trust modelling. |
| AU-2 / AU-3 / AU-12 | Event logging, content of audit records, audit record generation | `nginx.missing_access_log`, `nginx.missing_error_log`, `nginx.missing_log_format`, `nginx.error_log_too_restrictive`, `nginx.log_format_missing_fields`, `apache.custom_log_missing`, `apache.error_log_missing`, `apache.error_log_unsafe_destination`, `apache.log_level_too_restrictive`, `apache.log_format_missing_fields`, `apache.missing_log_format`, `lighttpd.access_log_missing`, `lighttpd.error_log_missing`, `iis.logging_not_configured` | covered: current `nginx.log_format_missing_fields` / `apache.log_format_missing_fields` require `user-agent`, `request-id`, forwarded-chain, and TLS protocol/cipher fields where applicable. |
| AU-9 | Protection of audit information | none direct — `out-of-scope` | Log-file ownership / mode requires filesystem inspection outside this tool. |
| CM-6 | Configuration settings | catch-all for every misconfig rule (`server_tokens_*`, `*.options_*`, `*.directory_*`, `*.autoindex_*`, etc.). | — |
| CM-7 / CM-7(1) | Least functionality | `lighttpd.mod_cgi_enabled`, `lighttpd.mod_webdav_enabled`, `lighttpd.webdav_write_access_enabled`, `iis.webdav_module_enabled`, `iis.cgi_handler_enabled`, `iis.handler_write_script_execute_enabled`, `apache.options_execcgi_enabled`, `apache.options_includes_enabled`, `apache.options_multiviews_enabled`, `apache.trace_enable_not_off`, `external.trace_method_allowed`, `external.dangerous_http_methods_enabled`, `external.allow_header_dangerous_methods`, `external.webdav_methods_exposed`, `apache.server_status_exposed`, `apache.server_info_exposed`, `external.server_status_exposed`, `external.server_info_exposed`, `external.nginx_status_exposed`, `external.apache.mod_status_public`, `lighttpd.mod_status_public` | `parser-depth`: Apache module minimization still needs build/package context, but visible ModSecurity / CRS inventory is now covered by direct local rules in addition to the existing module-aware foundation from `STD-GAP-007`. |
| IA-2 / IA-5 / IA-5(1) | Identification and authentication | `nginx.missing_auth_basic_user_file`, `nginx.auth_basic_over_http`, `apache.basic_auth_over_http`, `lighttpd.basic_auth_over_http`, `iis.basic_auth_without_ssl`, `iis.credentials_password_format_clear`, `iis.credentials_stored_in_config`, `iis.forms_auth_require_ssl_missing`, `iis.machine_key_validation_weak`, `iis.machine_key_legacy_validation_weak`, `external.htpasswd_exposed` | — |
| SI-10 / SI-10(2) | Information input validation | `iis.request_filtering_allow_double_escaping`, `iis.request_filtering_allow_high_bit`, `iis.file_extensions_allow_unlisted`, `iis.isapi_cgi_restrictions_allow_unlisted`, `iis.request_filtering_max_url_too_high`, `iis.request_filtering_max_query_string_too_high`, `apache.limit_request_field_size_too_high`, `nginx.sensitive_config_files_not_restricted`, `apache.sensitive_config_files_not_restricted` | covered: Apache header-byte limits are already present, and the Nginx/Apache sensitive-extension rules now provide the direct deny-list baseline signal. |
| SI-11 | Error handling | `iis.http_errors_detailed`, `iis.custom_errors_off`, `iis.asp_script_error_sent_to_browser`, `iis.deployment_retail_not_enabled`, `iis.compilation_debug_enabled`, `iis.trace_enabled`, `apache.error_document_404_missing`, `apache.error_document_500_missing`, `external.iis.detailed_error_page`, `external.elmah_axd_exposed`, `external.trace_axd_exposed`, `external.phpinfo_exposed` | — |
| SC-5 / SC-5(1) | Resource availability / DoS | All `*.missing_limit_*`, `*.missing_client_*_timeout`, `*.timeout_too_high`, `*.keepalive_*`, `*.client_max_body_size_*`, `apache.limit_request_*`, `iis.max_allowed_content_length_missing` | — |
| SC-7 | Boundary protection | `apache.listen_requires_explicit_address`, `universal.listen_on_all_interfaces`, `iis.binding_without_host_header` | `parser-depth`: Nginx `listen` interface modelling. |

### 5.3 NIST SP 800-44 Rev. 2 — Public Web Servers

SP 800-44 Rev. 2 is from 2007 and is largely superseded by 800-53 Rev. 5
control content. Its main remaining value for this project is the
*structure*: chapter 5 (Web Server Software Hardening), chapter 6 (Logging),
chapter 7 (Authentication and Encryption), chapter 8 (Implementing a Secure
Network Infrastructure).

| SP 800-44 v2 chapter | Topic | Already-covered rules (candidate `partial: legacy reference`) |
| --- | --- | --- |
| §5.2 | Disable unneeded modules / services | Same set as CM-7, including status probes `external.server_status_exposed`, `apache.server_status_exposed`, `external.apache.mod_status_public`, plus module/service checks such as `lighttpd.mod_cgi_enabled` and `iis.webdav_module_enabled`. |
| §5.3 | Server software identification removal | `nginx.server_tokens_on`, `apache.server_tokens_not_prod`, `apache.server_signature_not_off`, `lighttpd.server_tag_not_blank`, `iis.custom_headers_expose_server`, `iis.request_filtering_remove_server_header_disabled`, `external.server_version_disclosed`, `external.x_powered_by_header_present`, `external.x_aspnet_version_header_present`, `external.iis.aspnet_version_header_present`, `external.nginx.version_disclosed_in_server_header`, `external.apache.version_disclosed_in_server_header`, `external.lighttpd.version_in_server_header`. |
| §5.4 | Default content removal | `external.nginx.default_welcome_page`, `external.apache.default_welcome_page`, `external.iis.default_welcome_page`, `external.lighttpd.default_welcome_page` (partial). |
| §6 | Logging | Same set as AU-2 / AU-3. |
| §7 | Authentication and encryption | Same set as IA-2 / SC-8 / SC-13. |

Recommendation: register SP 800-44 references only as `partial: legacy
reference` companions, not as the primary external citation, because newer
800-53 / 800-52 wording is more current.

### 5.4 NIST SP 800-63B — Authentication / Session

Most of 800-63B sits at the application layer. Web-server-config visible
parts:

| 800-63B section | Topic | Already-covered rules (candidate `partial`) | Gap follow-up |
| --- | --- | --- | --- |
| §5.1.1.2 | Memorized secret transport over authenticated protected channel | `nginx.auth_basic_over_http`, `apache.basic_auth_over_http`, `lighttpd.basic_auth_over_http`, `iis.basic_auth_without_ssl`, `iis.credentials_password_format_clear`, `iis.credentials_stored_in_config`, `external.htpasswd_exposed` | — |
| §7.1 | Session bindings (cookie attributes) | All cookie-attribute rules from §5.2 / SC-23 above, plus `external.cookie_prefix_contract_violated`. | — |
| §10.4 | Reauthentication | out-of-scope (application). | — |

### 5.5 NIST CSF 2.0 — Cybersecurity Framework

CSF 2.0 functions of interest: **PR.DS** (Data Security), **PR.AA** (Identity
Management, Authentication, Access Control), **PR.PS** (Platform Security),
**DE.CM** (Continuous Monitoring).

| CSF 2.0 outcome | Topic | Already-covered rules (candidate `covered`) |
| --- | --- | --- |
| PR.DS-02 | Data-in-transit protected | All TLS / HSTS / redirect rules from §5.1. |
| PR.AA-05 | Access permissions / authorizations enforced | All AC-3 rules from §5.2. |
| PR.PS-01 | Configurations of platforms managed | Catch-all for hardening rules. |
| PR.PS-04 | Logs generated, made available | All AU-2 rules from §5.2. |
| DE.CM-09 | Computing hardware/software configurations monitored | not directly — `out-of-scope`. |

CSF is a high-level framework, so rule rows should cite at most **one**
`PR.*` outcome per rule.

### 5.6 PCI DSS v4.0.1

PCI DSS is the highest-leverage missing standard: the project is essentially
already aligned with the relevant requirements.

| PCI DSS v4.0.1 requirement | Topic | Already-covered rules (candidate `covered`) | Gap follow-up |
| --- | --- | --- | --- |
| 2.2.1 | Configuration standards developed | catch-all for every misconfig rule. | — |
| 2.2.5 | Where insecure services / protocols / daemons in use, business justification documented and security features implemented | `lighttpd.mod_cgi_enabled`, `lighttpd.mod_webdav_enabled`, `lighttpd.webdav_write_access_enabled`, `iis.webdav_module_enabled`, `apache.trace_enable_not_off`, `external.trace_method_allowed`, `external.dangerous_http_methods_enabled`, `external.webdav_methods_exposed` | — |
| 2.2.6 | System security parameters configured to prevent misuse | `nginx.server_tokens_on`, `apache.server_tokens_not_prod`, `apache.server_signature_not_off`, `lighttpd.server_tag_not_blank`, `iis.custom_headers_expose_server`, `external.phpinfo_exposed`, `external.elmah_axd_exposed`, `external.trace_axd_exposed`, `external.git_metadata_exposed`, `external.svn_metadata_exposed`, `external.web_config_exposed`, `external.htaccess_exposed`, `external.htpasswd_exposed`, `external.env_file_exposed`, `external.backup_file_exposed` | - |
| 4.2.1 | Strong cryptography for transmissions over open public networks | All TLS / HSTS / redirect rules from §5.1. | — |
| 6.2.4 | Common attack vectors / hardening | `nginx.executable_scripts_allowed_in_uploads`, `iis.handler_write_script_execute_enabled`, `iis.cgi_handler_enabled`, `iis.request_filtering_*` family, `apache.htaccess_enables_cgi`, `apache.htaccess_enables_directory_listing`, `apache.htaccess_disables_security_headers`, `apache.htaccess_weakens_security` | — |
| 6.4.3 | Public-facing web app — payment-page scripts integrity | `external.content_security_policy_missing`, `external.content_security_policy_unsafe_inline`, `external.content_security_policy_unsafe_eval`, `external.content_security_policy_object_src_not_none`, `external.content_security_policy_base_uri_not_restricted`, `external.content_security_policy_nonce_reused`, `external.script_src_missing_sri`. | `covered` (partial): bounded HTML parsing on eligible responses now inventories inline scripts and flags cross-origin scripts missing SRI; same-origin SRI remains out of scope and the safe probe is capped at 1 MiB per HTML body. |
| 8.3.1 | Strong authentication for users / administrators | `nginx.missing_auth_basic_user_file`, `nginx.auth_basic_over_http`, `apache.basic_auth_over_http`, `lighttpd.basic_auth_over_http`, `iis.basic_auth_without_ssl`, `external.htpasswd_exposed`, `iis.credentials_password_format_clear`, `iis.credentials_stored_in_config` | — |
| 8.3.2 | Strong cryptography during transmission of all auth factors | `nginx.auth_basic_over_http`, `apache.basic_auth_over_http`, `lighttpd.basic_auth_over_http`, `iis.forms_auth_require_ssl_missing`, `iis.basic_auth_without_ssl`, `iis.forms_auth_protection_unsafe`, all cookie `Secure` / `SameSite=None+Secure` rules. | — |
| 10.2.1 | Audit logs enabled and active | `nginx.missing_access_log`, `apache.custom_log_missing`, `apache.error_log_missing`, `apache.error_log_unsafe_destination`, `lighttpd.access_log_missing`, `lighttpd.error_log_missing`, `iis.logging_not_configured`, `nginx.missing_error_log`, `nginx.error_log_too_restrictive`, `apache.log_level_too_restrictive` | — |
| 10.2.2 | Audit logs record specific items | `nginx.log_format_missing_fields`, `apache.log_format_missing_fields`, `nginx.missing_log_format`, `apache.missing_log_format` | covered: current Nginx/Apache log field rules require `request-id`, forwarded-chain, and TLS protocol/cipher fields where applicable. |
| 10.5 | Audit log retention / protection | none — `out-of-scope`. | — |
| 12.3 | Risks for security technologies / processes evaluated | out-of-scope (process). | — |

### 5.7 CIS Critical Security Controls v8.1

CIS Controls v8.1 sit on top of the per-product CIS Benchmarks. The
benchmark mappings already in `docs/rule-coverage.md` cover the bulk of
sub-control content; the **Control** column adds the high-level rollup that
auditors usually want to see.

| Control | Safeguard | Already-covered rules (candidate `covered`) |
| --- | --- | --- |
| 3.10 | Encrypt sensitive data in transit | All TLS / HSTS / redirect rules from §5.1. |
| 4.1 | Establish and maintain a secure configuration process | catch-all for every hardening rule. |
| 4.6 | Securely manage enterprise assets and software | `nginx.server_tokens_on`, `apache.server_tokens_not_prod`, `lighttpd.server_tag_not_blank`, IIS server-header rules, all `external.*.version_disclosed_in_server_header`. |
| 4.8 | Uninstall or disable unnecessary services on enterprise assets and software | `lighttpd.mod_cgi_enabled`, `lighttpd.mod_webdav_enabled`, `lighttpd.webdav_write_access_enabled`, `iis.webdav_module_enabled`, `iis.cgi_handler_enabled`, `apache.options_execcgi_enabled`, `apache.options_includes_enabled`, `apache.options_multiviews_enabled`. |
| 4.9 | Configure trusted DNS servers on enterprise assets | `nginx.ssl_stapling_missing_resolver` (partial, scoped to OCSP). |
| 8.2 | Collect audit logs | All AU-2 rules from §5.2. |
| 8.5 | Collect detailed audit logs | `nginx.log_format_missing_fields`, `apache.log_format_missing_fields`. |
| 8.7 | Collect URL request audit logs | `nginx.missing_access_log`, `apache.custom_log_missing`, `lighttpd.access_log_missing`, `iis.logging_not_configured`. |
| 9.5 | Implement DMARC | out-of-scope (mail). |
| 12.6 | Use of secure network management and communication protocols | All TLS rules from §5.1. |
| 13.5 | Manage access control for remote assets | All AC-3 rules from §5.2. |

### 5.8 HIPAA Security Rule (45 CFR §164.30x)

| Citation | Topic | Already-covered rules (candidate `partial: hardening evidence only`) |
| --- | --- | --- |
| §164.312(a)(1) — Access control | Access enforcement | All AC-3 rules from §5.2. |
| §164.312(b) — Audit controls | Logging | All AU-2 rules from §5.2. |
| §164.312(c)(1) — Integrity | Protection from improper alteration | `external.content_security_policy_*`, `external.x_content_type_options_*`, `external.x_frame_options_*`, `iis.http_cookies_http_only_disabled`. |
| §164.312(d) — Person or entity authentication | Auth | All IA-2 rules from §5.2. |
| §164.312(e)(1) — Transmission security | Cleartext / TLS | All §5.1 rules. |
| §164.312(e)(2)(i) — Integrity controls | HSTS, no-sniff, frame-ancestors | HSTS rules + `external.x_content_type_options_*` + `external.x_frame_options_*` + `external.content_security_policy_missing_frame_ancestors`. |
| §164.312(e)(2)(ii) — Encryption | TLS protocols / ciphers | All §5.1 rules. |

HIPAA is regulatory; rule rows should cite §164.312(\*) only, not §164.308
process safeguards.

### 5.9 ISO/IEC 27001:2022 and 27002:2022

27001 itself is management-system level; we map to **ISO/IEC 27002:2022
Annex A** controls.

| 27002:2022 control | Topic | Already-covered rules (candidate `covered`) |
| --- | --- | --- |
| 8.20 | Networks security | All TLS rules + `nginx.default_server_not_rejecting_unknown_hosts`, `nginx.default_tls_server_not_rejecting_unknown_hosts`, `apache.listen_requires_explicit_address`, `iis.binding_without_host_header`, `universal.listen_on_all_interfaces`. |
| 8.21 | Security of network services | All TLS / HSTS / cipher / cookie rules. |
| 8.23 | Web filtering | out-of-scope. |
| 8.24 | Use of cryptography | All TLS / cipher / SChannel rules. |
| 8.5 | Secure authentication | All IA-2 rules from §5.2. |
| 8.15 | Logging | All AU-2 rules from §5.2. |
| 8.16 | Monitoring activities | partial via logging rules. |
| 8.18 | Use of privileged utility programs | `iis.webdav_module_enabled`, `lighttpd.mod_cgi_enabled`, `lighttpd.mod_webdav_enabled`, `lighttpd.webdav_write_access_enabled`, `apache.options_execcgi_enabled`. |
| 8.27 | Secure system architecture and engineering principles | catch-all hardening. |
| 8.34 | Protection of information systems during audit testing | out-of-scope. |

ГОСТ Р ИСО/МЭК 27001-2021 / 27002-2021 are direct localisations: the same
control numbers apply.

### 5.10 BSI IT-Grundschutz APP.3.2 Web-Server

| APP.3.2 requirement | Topic | Already-covered rules (candidate `covered`) | Gap follow-up |
| --- | --- | --- | --- |
| APP.3.2.A1 | Authentisierung | `iis.basic_auth_without_ssl`, `nginx.missing_auth_basic_user_file`, `external.htpasswd_exposed`. | — |
| APP.3.2.A2 | Sichere Konfiguration eines Web-Servers | catch-all hardening. | — |
| APP.3.2.A3 | Sicheres Hochfahren | `out-of-scope`. | — |
| APP.3.2.A4 | Protokollierung | All AU-2 rules. | — |
| APP.3.2.A5 | Authentisierung über HTTP | `nginx.auth_basic_over_http`, `apache.basic_auth_over_http`, `lighttpd.basic_auth_over_http`, `iis.basic_auth_without_ssl`. | — |
| APP.3.2.A11 | Verschlüsselung über TLS | All §5.1 rules. | — |
| APP.3.2.A12 | Sichere Erhebung von Konfigurationsdaten | `out-of-scope`. | — |
| APP.3.2.A14 | Schutz von Web-Anwendungen und Web-Services über Reverse-Proxy | `nginx.proxy_missing_source_ip_headers` (partial). | `parser-depth`: full reverse-proxy upstream-TLS modelling remains broader than today's Nginx rule, but the Apache-side foundation closed in `STD-GAP-007` is now implemented. |

### 5.11 MITRE ATT&CK Enterprise v15

ATT&CK is a context layer. It is most useful as an **observation-side** tag
on disclosure and probe rules.

| ATT&CK technique | Topic | Already-covered rules (candidate `partial: telemetry context`) |
| --- | --- | --- |
| T1190 — Exploit Public-Facing Application | Sensitive paths, debug, framework leaks | `external.git_metadata_exposed`, `external.svn_metadata_exposed`, `external.env_file_exposed`, `external.web_config_exposed`, `external.htaccess_exposed`, `external.phpinfo_exposed`, `external.elmah_axd_exposed`, `external.trace_axd_exposed`, `external.wordpress_admin_panel_exposed`. |
| T1592.002 — Gather Victim Host Information: Software | Server / framework version disclosure | `external.server_version_disclosed`, `external.x_powered_by_header_present`, `external.x_aspnet_version_header_present`, `external.iis.aspnet_version_header_present`, `external.nginx.version_disclosed_in_server_header`, `external.apache.version_disclosed_in_server_header`, `external.lighttpd.version_in_server_header`, `external.apache.etag_inode_disclosure`. |
| T1592.004 — Client Configurations | Server-info / status endpoints | Generic status probes `external.server_status_exposed`, `external.server_info_exposed`, plus server-specific probes `external.nginx_status_exposed`, `external.apache.mod_status_public`, and `external.lighttpd.mod_status_public`. |
| T1213.003 — Code Repositories | VCS metadata leaks | `external.git_metadata_exposed`, `external.svn_metadata_exposed`. |
| T1078 — Valid Accounts | Credential / password file leak | `external.htpasswd_exposed`, `iis.credentials_password_format_clear`, `iis.credentials_stored_in_config`. |
| T1040 — Network Sniffing | Plaintext channel | `external.https_not_available`, `external.http_not_redirected_to_https`, `iis.basic_auth_without_ssl`, `iis.forms_auth_require_ssl_missing`, all HSTS rules. |
| T1505.003 — Server Software Component: Web Shell | Upload + execute | `nginx.executable_scripts_allowed_in_uploads`, `iis.handler_write_script_execute_enabled`. |
| T1557 — Adversary-in-the-Middle | Cleartext / weak TLS | All §5.1 weak-protocol / weak-cipher rules. |

Implementation rule: ATT&CK should be a **secondary** tag, never the only
standards reference.

### 5.12 OWASP Cheat Sheet Series

The Cheat Sheet Series is the natural per-rule companion for external probe
rules. `docs/rule-coverage.md` already names it as the conceptual
companion but does not cite per-rule.

| Cheat sheet | Already-covered rules (candidate `covered`) |
| --- | --- |
| HTTP Security Response Headers | All `external.*` header rules + universal / per-server `missing_*` header rules. |
| HTTP Strict Transport Security | All HSTS rules. |
| Transport Layer Security | All §5.1 rules. |
| Content Security Policy | `external.content_security_policy_*`, `nginx.content_security_policy_unsafe`, `nginx.missing_content_security_policy`, `apache.htaccess_disables_security_headers` (partial). |
| Cross-Site Request Forgery Prevention | All `cookie_missing_samesite` / `cookie_samesite_none_without_secure` rules plus `external.cookie_prefix_contract_violated`. |
| Session Management | Cookie rules (including `external.cookie_prefix_contract_violated`) + IIS forms-auth rules. |
| Logging | All AU-2 rules. |
| Authentication | `nginx.missing_auth_basic_user_file`, `nginx.auth_basic_over_http`, `apache.basic_auth_over_http`, `lighttpd.basic_auth_over_http`, `iis.basic_auth_without_ssl`, `external.htpasswd_exposed`. |
| Web Service Security | partial via `external.allow_header_dangerous_methods`, `external.dangerous_http_methods_enabled`. |
| Secure Cookie Attributes | All cookie rules. |

### 5.13 OWASP API Security Top 10 (2023)

API-specific. Most categories are application-layer. Web-server-config
visible parts:

| API Top 10 (2023) | Topic | Already-covered rules (candidate `partial`) | Gap follow-up |
| --- | --- | --- | --- |
| API2:2023 Broken Authentication | Auth transport / storage | Same set as §5.2 IA-2. | — |
| API4:2023 Unrestricted Resource Consumption | Rate / size limits | All `*.missing_limit_*`, `*.timeout_*`, `iis.max_allowed_content_length_missing`, `apache.limit_request_*`. | — |
| API7:2023 Server Side Request Forgery | out-of-scope (application). | — | — |
| API8:2023 Security Misconfiguration | Catch-all hardening. | All hardening rules. | — |
| API9:2023 Improper Inventory Management | out-of-scope. | — | — |
| API10:2023 Unsafe Consumption of APIs | out-of-scope. | — | — |

### 5.14 CWE Top 25 (2024) — severity calibration anchor

The repository already cites CWE per rule. The CWE Top 25 column adds a
**Top 25 rank** when the rule's CWE matches the 2024 list. The main use is
severity calibration: a Top 25 entry is a candidate for raising default
severity from `low` to `medium`.

Top 25 entries with current rule coverage:

| CWE | 2024 rank | Rules carrying this CWE today |
| --- | --- | --- |
| CWE-22 | rank 5 | `nginx.alias_without_trailing_slash`. |
| CWE-352 | rank 4 | none yet — partial via cookie SameSite. |
| CWE-434 | rank 10 | `nginx.executable_scripts_allowed_in_uploads`. |
| CWE-200 | rank 17 | `apache.server_info_exposed`, `apache.server_status_exposed`, `apache.server_tokens_not_prod`, `apache.server_signature_not_off`, `apache.trace_enable_not_off`, `apache.file_etag_inodes`, `nginx.server_tokens_on`, `lighttpd.mod_status_public`, `lighttpd.server_tag_not_blank`, `iis.http_runtime_version_header_enabled`, `iis.custom_headers_expose_server`, `iis.request_filtering_remove_server_header_disabled`, all external `*.version_disclosed_in_server_header` and `external.phpinfo_exposed` / `external.trace_method_*` / `external.nginx_status_exposed` / `external.server_status_exposed` / `external.server_info_exposed` / `external.x_powered_by_header_present` / `external.x_aspnet_version_header_present`. |
| CWE-287 | rank 14 | `iis.anonymous_auth_enabled`, `iis.authorization_allows_anonymous_users`, `iis.basic_auth_without_ssl` (CWE-319, but linked), `nginx.missing_auth_basic_user_file`. |
| CWE-863 | rank 18 | `nginx.allow_all_with_deny_all`. |
| CWE-798 | rank 22 | `iis.credentials_stored_in_config`. |
| CWE-400 | rank 24 | every `*.missing_*_timeout` and `*.missing_limit_*`. |
| CWE-1004 / CWE-1275 | hardening | cookie rules. |

Historical note: CWE-798 was rank 18 in the 2023 list and remains present in
the 2024 Top 25 at rank 22.

`STD-GAP` follow-up is purely calibration: severity bump for rules with a
Top 25 CWE that were still `low`. No new rules are required.

### 5.15 Lighttpd vendor / DevSec lighttpd-baseline

Lighttpd has no CIS Benchmark, but the
[DevSec lighttpd-baseline](https://github.com/dev-sec/lighttpd-baseline)
profile and the [lighttpd Security wiki](https://redmine.lighttpd.net/projects/lighttpd/wiki/Docs_Security)
are reasonable substitute references. The Lighttpd table in
`docs/rule-coverage.md` is currently the only family with no `CIS / Vendor`
content.

| DevSec / vendor reference | Already-covered rules (candidate `vendor reference`) |
| --- | --- |
| DevSec lighttpd-01 server.tag | `lighttpd.server_tag_not_blank`. |
| DevSec lighttpd-02 dir-listing | `lighttpd.dir_listing_enabled`. |
| DevSec lighttpd-03 ssl modes | `lighttpd.ssl_engine_not_enabled`, `lighttpd.ssl_pemfile_missing`, `lighttpd.ssl_protocol_policy_missing_or_weak`, `lighttpd.weak_ssl_cipher_list`, `lighttpd.ssl_honor_cipher_order_missing`. |
| DevSec lighttpd-05 forbidden methods | `lighttpd.missing_http_method_restrictions`. |
| lighttpd Security wiki — `mod_status` | `lighttpd.mod_status_public`. |
| lighttpd Security wiki — `mod_cgi` / `mod_webdav` | `lighttpd.mod_cgi_enabled`, `lighttpd.mod_webdav_enabled`, `lighttpd.webdav_write_access_enabled`. |
| lighttpd Security wiki — `url.access-deny` | `lighttpd.url_access_deny_missing`. |

`STD-GAP` follow-up: add a `Vendor` column for the Lighttpd table populated
with these references after review.

## 6. Russian standards / benchmarks

This section is in English/Russian mix because every identifier is
authoritative in Russian.

### 6.1 ФСТЭК Приказ № 17 (ГИС) и Приказ № 21 (ИСПДн)

Оба приказа определяют состав и содержание мер защиты для государственных
информационных систем (Приказ № 17) и информационных систем персональных
данных (Приказ № 21). Конкретные технические меры — в методическом документе
ФСТЭК «Меры защиты информации в государственных информационных системах»
(2014, действует), см. §6.2.

Кросс-ссылка: рекомендуется хранить ссылки на классы мер защиты, а не на
сами приказы (приказы только обязывают применять состав мер).

### 6.2 ФСТЭК «Меры защиты информации в государственных информационных системах»

| Класс | Мера | Уже покрыто правилами (кандидат `covered` / `partial`) | Gap follow-up |
| --- | --- | --- | --- |
| ИАФ.1 | Идентификация и аутентификация субъектов доступа | `nginx.missing_auth_basic_user_file`, `nginx.auth_basic_over_http` (partial: HTTP Basic transport protection only), `iis.basic_auth_without_ssl`, `iis.anonymous_auth_enabled`, `iis.authorization_allows_anonymous_users`, `iis.anonymous_auth_uses_specific_user`. | — |
| ИАФ.6 | Защита аутентификационной информации | `nginx.auth_basic_over_http`, `apache.basic_auth_over_http`, `lighttpd.basic_auth_over_http`, `iis.credentials_password_format_clear`, `iis.credentials_stored_in_config`, `iis.forms_auth_require_ssl_missing`, `iis.forms_auth_protection_unsafe`, `external.htpasswd_exposed`, `iis.basic_auth_without_ssl`. | — |
| УПД.5 | Управление доступом субъектов | `nginx.allow_all_with_deny_all`, `nginx.missing_access_restrictions_on_sensitive_locations`, `nginx.sensitive_location_missing_ip_filter`, `lighttpd.url_access_deny_missing`, `iis.authorization_allows_anonymous_users`, `apache.allowoverride_*`. | `parser-depth`: эффективная политика `Require` для Apache. |
| УПД.13 | Защищённый удалённый доступ | Все правила §5.1 (TLS / HSTS / redirect). | — |
| ОПС.3 | Идентификация и аутентификация компонентов | `nginx.proxy_missing_source_ip_headers`. | `parser-depth`: моделирование upstream TLS trust. |
| РСБ.1 | Определение событий безопасности | Все правила AU-2 из §5.2. | — |
| РСБ.3 | Сбор, запись и хранение информации о событиях | `nginx.log_format_missing_fields`, `apache.log_format_missing_fields`. | covered: текущие правила уже требуют `request-id`, `x-forwarded-for` chain и TLS protocol/cipher поля там, где они применимы. |
| РСБ.7 | Защита информации о событиях | `out-of-scope` — права на лог-файлы вне web-server config. | — |
| АНЗ.1 | Выявление, анализ уязвимостей информационной системы | Все external probes по version-disclosure / sensitive paths / debug endpoints. | — |
| АНЗ.2 | Контроль установки обновлений ПО | `out-of-scope`. | — |
| ЗИС.3 | Защита от внутренних и внешних угроз с использованием технологий межсетевого экранирования | `nginx.default_server_not_rejecting_unknown_hosts`, `nginx.default_tls_server_not_rejecting_unknown_hosts`, `apache.listen_requires_explicit_address`, `iis.binding_without_host_header`, `universal.listen_on_all_interfaces`. | — |
| ЗИС.20 | Защита каналов связи | Все правила §5.1. | — |
| ЗИС.32 | Защита веб-серверов | Catch-all для всех hardening-правил. | — |

### 6.3 ФСТЭК БДУ — Банк данных угроз

БДУ — это каталог угроз `УБИ.NNN`, не мер. Полезен как secondary tag для
disclosure / exposure правил.

| УБИ | Заголовок | Уже покрыто правилами (кандидат `partial: telemetry context`) |
| --- | --- | --- |
| УБИ.044 | Угроза несанкционированного доступа к данным за счёт перехвата сетевого трафика | `external.https_not_available`, `external.http_not_redirected_to_https`, `iis.basic_auth_without_ssl`, все HSTS-правила. |
| УБИ.067 | Угроза неправомерного ознакомления с защищаемой информацией | `external.git_metadata_exposed`, `external.svn_metadata_exposed`, `external.env_file_exposed`, `external.web_config_exposed`, `external.phpinfo_exposed`. |
| УБИ.072 | Угроза получения несанкционированного доступа путём использования неподконтрольного канала | TLS / weak-cipher правила. |
| УБИ.121 | Угроза искажения web-страниц | `external.content_security_policy_*`, `external.x_frame_options_*`, `external.x_content_type_options_*`. |
| УБИ.184 | Угроза разглашения сведений об учётной записи пользователя информационной системы | `external.htpasswd_exposed`, `iis.credentials_password_format_clear`, `iis.credentials_stored_in_config`, `iis.basic_auth_without_ssl`. |
| УБИ.215 | Угроза перехвата исключительного права | out-of-scope. |

Правило отображения: ссылка на УБИ — это **второй тег**, не основной
стандарт. Основной — ФСТЭК-меры из §6.2.

### 6.4 ФСБ Приказ № 378 (СКЗИ)

Приказ № 378 регулирует применение средств криптографической защиты
информации при обработке ПДн. Для веб-сервера это означает, что при
сертифицированной обработке ПДн TLS-стек должен быть на сертифицированных
СКЗИ (ГОСТ-наборы шифров). На уровне `webconf-audit` это:

- **`research`**: добавление детектора ГОСТ-наборов шифров (например,
  `TLS_GOSTR341112_*`, RFC 9189) в нормализацию TLS — отдельный отчётный
  сигнал, **не** правило, потому что присутствие ГОСТ-шифра нейтрально, а
  отсутствие нейтрально вне ИСПДн.
- В любом случае — `out-of-scope` для попытки проверять «сертифицирован ли
  стек как СКЗИ»: это документная процедура, не runtime-сигнал.

#### Research scope для `STD-GAP-033`

Этот research-пункт — не mapping-PR, а отдельная исследовательская задача
с фиксированными границами:

- **Цель**: определить, можно ли добавить **информационный** детектор
  ГОСТ-наборов шифров (RFC 9189: `TLS_GOSTR341112_256_WITH_KUZNYECHIK_*`,
  `TLS_GOSTR341112_256_WITH_MAGMA_*`) в существующий TLS-нормализатор,
  чтобы пользователь мог увидеть «есть/нет ГОСТ-шифров в политике» как
  отдельный сигнал в JSON-отчёте.
- **Acceptance criteria**:
  - детектор работает и для local TLS-конфигов (Nginx `ssl_ciphers`,
    Apache `SSLCipherSuite`, Lighttpd `ssl.cipher-list`), и для external
    probe-data, если вернётся ГОСТ-шифр в ServerHello;
  - НИ ОДНОГО `Finding` детектор не создаёт; в JSON это поле
    `tls_diagnostics.gost_cipher_suites_present: bool` или эквивалент;
  - не делается попытки проверить «сертифицирован ли стек СКЗИ» — это
    out-of-scope.
- **Open questions**:
  - какие OpenSSL-сборки реально умеют ГОСТ-наборы (mainline OpenSSL их
    дропнул из 1.1+; нужны GOST-engine или Stunnel/CryptoPro форки);
  - как это отразить в external probe — нужен `openssl s_client` с
    GOST-engine, чего у обычного скана может не быть;
  - стоит ли вообще ловить ГОСТ-шифры probing-ом, если они почти всегда
    в private deployments внутри РФ.
- **Не делается до тех пор, пока**: `STD-GAP-031` (ФСТЭК Меры) не
  собрал реальный фидбек от пользователей, которые работают в ИСПДн. Без
  такого фидбека признак «ГОСТ-шифр виден» не имеет потребителя.

Артефакт: эта подсекция и есть весь research-выход. Никаких code/doc
изменений за её пределами PR `STD-GAP-033` не делает.

### 6.5 ГОСТ Р 57580.1-2017 (защита ФО)

ГОСТ для финансовых организаций; обязателен для поднадзорных Банку России.
Применим как cross-reference в финтех-аудитории.

| Раздел | Тема | Уже покрыто правилами (кандидат `partial`) |
| --- | --- | --- |
| 7.4 | Управление доступом | Все AC-3 правила из §5.2. |
| 7.6 | Защита информации при её передаче | Все §5.1 правила. |
| 7.7 | Регистрация и мониторинг событий | Все AU-2 правила из §5.2. |
| 7.9 | Защита от вредоносного кода | out-of-scope. |
| 7.10 | Защита виртуальной инфраструктуры | out-of-scope. |

### 6.6 ГОСТ Р ИСО/МЭК 27001-2021 / 27002-2021

Эти ГОСТы — точные русские локализации ISO/IEC 27001:2022 / 27002:2022.
Маппинг — тот же, что в §5.9. Для российской аудитории корректнее ссылаться
именно на ГОСТ-Р редакции.

### 6.7 ЦБ РФ Положение № 683-П / № 716-П

Положения Банка России для финансовых организаций. Конкретные технические
требования делегируют в ГОСТ Р 57580.1-2017 (см. §6.5). Прямых per-rule
ссылок на 683-П / 716-П в `docs/rule-coverage.md` не делать — использовать
ГОСТ Р 57580.1.

### 6.8 НКЦКИ / ГосСОПКА

Не стандарт защиты, а контекст обмена сведениями об инцидентах. Полезен как
ссылка на необходимость **сбора и хранения** журналов в требуемом формате,
что уже покрыто правилами AU-2. Отдельной рулесета не требует.

## 7. Cross-source partial для external probes

`docs/rule-coverage.md` намеренно оставляет колонку `CIS / Vendor`
пустой для всех external rules, потому что external — это runtime-проб, а
CIS Benchmarks — config-level. Это разумное по-умолчанию правило, но для
части CIS-секций runtime evidence действительно есть, и текущий пустой `-`
теряет полезный сигнал.

Кандидаты на cross-source partial (помечать как
`(partial: runtime evidence; primary CIS reference at <local rule>)`):

| External rule | Cross-source CIS section | Существующее «основное» config-level правило |
| --- | --- | --- |
| `external.http_not_redirected_to_https` | CIS NGINX v3.0.0 §4.1.1, CIS Apache 2.4 v2.3.0 §7.1 | `nginx.missing_http_to_https_redirect`, `apache.missing_http_to_https_redirect` |
| `external.https_not_available` | CIS NGINX v3.0.0 §4.1.1, CIS Apache 2.4 v2.3.0 §7.1, CIS IIS 10 v1.2.1 §2.6 | те же + `iis.ssl_not_required`, `iis.basic_auth_without_ssl` |
| `external.tls_1_0_supported`, `external.tls_1_1_supported` | CIS NGINX v3.0.0 §4.1.4, CIS Apache 2.4 v2.3.0 §7.1, CIS IIS 10 v1.2.1 §7.2-§7.5 | `nginx.weak_ssl_protocols`, `apache.ssl_protocol_missing_or_weak`, `iis.schannel_weak_protocol_enabled` |
| `external.weak_cipher_suite` | CIS NGINX v3.0.0 §4.1.5, CIS Apache 2.4 v2.3.0 §7.4, CIS IIS 10 v1.2.1 §7.7-§7.9 | `universal.weak_tls_ciphers`, `nginx.ssl_ciphers_weak`, `apache.ssl_cipher_suite_weak`, `lighttpd.weak_ssl_cipher_list` |
| `external.hsts_*` family | CIS NGINX v3.0.0 §4.1.8, CIS Apache 2.4 v2.3.0 §7.11, CIS IIS 10 v1.2.1 §7.1 | `nginx.missing_hsts_header`, `apache.missing_hsts_header`, `apache.hsts_header_unsafe`, `iis.missing_hsts_header` |
| `external.trace_method_allowed`, `external.trace_method_exposed_via_options` | CIS Apache 2.4 v2.3.0 §5.8 | `apache.trace_enable_not_off` |
| `external.server_status_exposed`, `external.server_info_exposed` | CIS Apache 2.4 v2.3.0 §2.4 / §2.8 | `apache.server_status_exposed`, `apache.server_info_exposed` |
| `external.nginx_status_exposed` | CIS NGINX v3.0.0 §2.5.4 (partial: reverse-proxy disclosure) | none — эта подкатегория сейчас `parser-depth`. |
| `external.x_content_type_options_missing/invalid` | CIS NGINX v3.0.0 §5.3.1, CIS Apache 2.4 v2.3.0 §5.16 / §5.17 / §5.18 (partial) | `nginx.missing_x_content_type_options`, `apache.missing_*_header` family |
| `external.git_metadata_exposed`, `external.svn_metadata_exposed` | CIS NGINX v3.0.0 §2.5.3, CIS Apache 2.4 v2.3.0 §5.10-§5.13 | `nginx.missing_hidden_files_deny`, `apache.vcs_metadata_not_restricted` |
| `external.dangerous_http_methods_enabled`, `external.allow_header_dangerous_methods` | CIS NGINX v3.0.0 §5.1.2, CIS Apache 2.4 v2.3.0 §5.7 | `nginx.missing_http_method_restrictions`, `apache.missing_http_method_restrictions` |
| `external.iis.detailed_error_page` | CIS IIS 10 v1.2.1 §3.4 | `iis.http_errors_detailed`, `iis.asp_script_error_sent_to_browser` |
| `external.iis.aspnet_version_header_present`, `external.x_aspnet_version_header_present` | CIS IIS 10 v1.2.1 §3.11 | `iis.custom_headers_expose_server`, `iis.http_runtime_version_header_enabled` |

Правило: cross-source запись **никогда** не заменяет основной config-level
маппинг — только **дополняет** его, потому что external rule не видит
конфиг и не должен утверждать `covered`. Формат:
`CIS NGINX v3.0.0 §4.1.4 (partial: runtime evidence; primary CIS reference at nginx.weak_ssl_protocols)`.

Дополнительный кандидат для конкретно §2.4.2 default-server reject из
`docs/standards-roadmap.md`: external эквивалент пока **не реализован**, и
прямого probe для unknown-Host runtime-rejection в текущем external-наборе
нет. Это `probe-depth` follow-up: добавить probe «отправляем `Host: random`
на IP и фиксируем поведение».

## 8. Слабые места и риски

(перечень совпадает с обсуждённым; здесь сохранён дословно для трассируемости)

- **NIST полностью отсутствует** — главный системный пробел для federal /
  regulated рынков. Большинство существующих TLS / HSTS / logging-правил
  мгновенно бы получили честный SP 800-52 / SP 800-53 mapping.
- **PCI DSS отсутствует** — а проект практически идеально на нём натянут
  (TLS req 4.2.1, headers, logging req 10).
- **Drift в счётчиках был выявлен и закрыт**: `docs/standards-roadmap.md`
  обновлён до 374 правил (Nginx 83, Apache 84, Lighttpd 49, IIS 52,
  External 93, Universal 13), чтобы совпадать с `docs/rule-coverage.md`.
- **`STD-GAP-012` "standards metadata в reports"** закрыт для core output path:
  `RuleMeta.standards` доезжает в `list-rules --format json`, JSON-отчёты
  содержат finding-level `standards` и top-level `standards` summary, а text
  output поддерживает `--group-by standard`.
- **Lighttpd** не имеет CIS-бенчмарка (это правда — его не существует), но и
  **DevSec lighttpd-baseline / lighttpd vendor docs** не закреплены как
  замещающий источник, поэтому колонка `CIS / Vendor` для Lighttpd «слепая».
- **External probes**: колонка CIS принципиально пуста — это аргументировано
  (probe ≠ config-level CIS), но для §2.4.2 (default-server reject) и §4.1.1
  (HTTP→HTTPS redirect) runtime evidence как раз есть. Можно было бы
  пометить cross-source partial.
- **OWASP Cheat Sheet Series** заявлен как companion для external probes, но
  реально нигде не маппится — это потерянный low-effort выигрыш.
- **ASVS глава V8 (Authentication / Session)** покрыта только косвенно
  (cookies, forms-auth IIS); глава **V11 Cryptography** — фрагментарно через
  V12.

## 9. Implementation backlog (продолжение `STD-GAP-NNN`)

Каждый gap — отдельный PR. Все они **mapping-only** до отдельного решения о
расширении правил.

Решение по охвату от 2026-05-05 зафиксировано в колонке `Status`:

- `accepted` — пункт идёт в основной проект (`docs/rule-coverage.md` или
  отдельный код-PR), порядок исполнения — в колонке `Order`.
- `deferred` — остаётся только в этом плановом документе как справка для
  будущих аудиторий; не несётся в канон.
- `secondary-only` — берётся в проект как secondary tag, не как основная
  колонка; зависит от архитектурного решения по secondary tags
  (`STD-GAP-026` определяет схему).
- `research` — только исследовательская задача, без mapping-PR.

`Order` относится только к `accepted` / `secondary-only` / `research`
пунктам. `STD-GAP-029` намеренно поставлен последним: severity
перераспределяется уже после того, как все benchmark-маппинги стабильны.

| ID | Family | Gap type | Priority | Status | Order | Candidate work |
| --- | --- | --- | --- | --- | --- | --- |
| STD-GAP-016 | NIST SP 800-52 Rev. 2 | covered | P1 | done (2026-05-05) | 5 | ✓ Добавлен консолидированный блок «NIST SP 800-52 Rev. 2 mapping» в `docs/rule-coverage.md`. Покрыты §3.1 (TLS 1.2/1.3), §3.3.1 (cipher suites), §3.3.2 (server preference), §3.4 (certificates), §3.5 (renegotiation), §3.6 (compression), §4.2/§4.3 (OCSP stapling), §4.2.4 (HSTS), no-plaintext-fallback. Подход topic-grouped, не per-row column — совпадает с уже покрытыми TLS-правилами по CIS/CWE-327. Хелпер `nist_sp()` теперь относится к follow-up `STD-GAP-038`, потому что core output path из `STD-GAP-012` уже готов. |
| STD-GAP-017 | NIST SP 800-53 Rev. 5 | covered | P1 | deferred | — | Не берётся в канон: высокая контрол-плотность создаст редундантные SC/AU/AC-теги поверх уже покрытых OWASP/PCI/ФСТЭК. Маппинг доступен в §5.2 на случай появления федеральной аудитории. |
| STD-GAP-018 | NIST SP 800-44 Rev. 2 | research | P3 | deferred | — | Устарел (2007), полностью дублирует SP 800-52/800-53. |
| STD-GAP-019 | NIST SP 800-63B | covered | P2 | deferred | — | Большая часть application-layer; видимая web-config часть дублирует SC-23 / IA-5. |
| STD-GAP-020 | NIST CSF 2.0 | covered | P2 | deferred | — | Слишком высокий уровень: теги выйдут одинаковыми на длинных группах правил. |
| STD-GAP-021 | PCI DSS v4.0.1 | covered | P1 | done (2026-05-05) | 4 | ✓ Добавлен консолидированный блок «PCI DSS v4.0.1 mapping» в `docs/rule-coverage.md`. Покрыты Req. 2.2.1, 2.2.5, 2.2.6, 4.2.1, 6.2.4, 6.4.3, 8.3.1, 8.3.2, 8.3.5/8.3.6, 10.2.1, 10.2.2; Req. 10.5 / 12 явно отмечены как `out-of-scope`. Подход topic-grouped, не per-row column. Хелпер `pci_dss_4()` теперь относится к follow-up `STD-GAP-038`. |
| STD-GAP-022 | CIS Critical Security Controls v8.1 | covered | P2 | deferred | — | Дублирует CIS Benchmarks, которые уже в проекте. |
| STD-GAP-023 | HIPAA Security Rule | covered | P2 | deferred | — | Узкая аудитория (US healthcare), косвенное покрытие. |
| STD-GAP-024 | ISO/IEC 27002:2022 + ГОСТ Р ИСО/МЭК 27002-2021 | covered | P2 | done (2026-05-05) | 7 | ✓ Добавлен блок «ISO/IEC 27002:2022 / ГОСТ Р ИСО/МЭК 27002-2021 mapping» в `docs/rule-coverage.md`. Покрыты 5.15, 8.5, 8.15, 8.16, 8.18, 8.20, 8.21, 8.24, 8.26, 8.27; 8.23 / 8.25 / 8.28 / 8.29 явно `out-of-scope`. ISO и ГОСТ Р в одной строке (ГОСТ — точная локализация). Хелпер `iso_27002_2022()` теперь относится к follow-up `STD-GAP-038`. |
| STD-GAP-025 | BSI IT-Grundschutz APP.3.2 | covered | P3 | deferred | — | Нишевый (DACH). |
| STD-GAP-026 | MITRE ATT&CK Enterprise v15 | direct-rule | P2 | done (2026-05-05) | 9 | ✓ Добавлен в общий блок «Secondary tags» (sub-section «MITRE ATT&CK Enterprise v15») в `docs/rule-coverage.md`. Архитектурное решение: secondary tags живут только в этом блоке, не как новая колонка и не как `StandardReference` записи на правилах. Если `STD-GAP-038` введёт `tier=secondary` — этот блок становится исходником миграции. Покрыты T1190, T1592.002, T1592.004, T1213.003, T1078, T1040, T1505.003, T1557, T1574. |
| STD-GAP-027 | OWASP Cheat Sheet Series | covered | P1 | done (2026-05-05) | 3 | ✓ Добавлен консолидированный блок «OWASP Cheat Sheet Series companions» в `docs/rule-coverage.md` (перед `## Standards mapping plan`). Подход topic-grouped, не per-row column: 15 cheat sheets (HTTP Security Response Headers, HSTS, TLS, CSP, CSRF, Session Management, Logging, Authentication, Credential Stuffing Prevention, Clickjacking Defense, Server Headers, Web Service Security, File Upload, Access Control, Error Handling) с aligned rule IDs. Cheat Sheets — living docs, поэтому отдельная колонка не вводится. |
| STD-GAP-028 | OWASP API Security Top 10 (2023) | covered | P3 | deferred | — | Большая часть out-of-scope для веб-сервера. |
| STD-GAP-029 | CWE Top 25 (2024) | direct-rule | P2 | done (2026-05-05) | 11 (last) | ✓ Calibration rationale из §11 применён в коде: `nginx.alias_without_trailing_slash`, `nginx.allow_all_with_deny_all` и `nginx.missing_auth_basic_user_file` подняты с `low` до `medium`; keep-low решения для disclosure-only правил сохранены. |
| STD-GAP-030 | Lighttpd vendor / DevSec lighttpd-baseline | covered | P2 | done (2026-05-05) | 8 | ✓ Добавлен блок «Lighttpd vendor reference mapping» в `docs/rule-coverage.md`. Решение: НЕ переименовывать `CIS / Vendor` колонку и НЕ заполнять её для Lighttpd, а сделать topic-grouped block (как PCI / NIST / ФСТЭК / ISO / Cheat Sheets) — иначе нарушится policy «не выдумывать CIS-бенчмарк, которого нет». DevSec lighttpd-01/02/03/05 + lighttpd Security wiki + per-module docs; `lighttpd-05` теперь покрыт `lighttpd.missing_http_method_restrictions`. |
| STD-GAP-031 | ФСТЭК «Меры защиты информации в ГИС» (Приказ № 17) | covered | P2 | done (2026-05-05) | 6 | ✓ Добавлен блок «ФСТЭК "Меры защиты информации в ГИС" mapping» в `docs/rule-coverage.md`. Покрыты ИАФ.1, ИАФ.6, УПД.5, УПД.13, ОПС.3, РСБ.1, РСБ.3, ЗИС.3, ЗИС.20, ЗИС.32; РСБ.7 / АНЗ.2 явно `out-of-scope`. Подход topic-grouped. Хелпер `fstec_mera()` теперь относится к follow-up `STD-GAP-038`. |
| STD-GAP-032 | ФСТЭК БДУ | direct-rule | P3 | done (2026-05-05) | 9 | ✓ Добавлен в общий блок «Secondary tags» (sub-section «ФСТЭК БДУ — Банк данных угроз») в `docs/rule-coverage.md`. Покрыты УБИ.044, УБИ.067, УБИ.072, УБИ.121, УБИ.184 со ссылками на `bdu.fstec.ru`. Правила те же, что для ATT&CK: secondary-only, не заменяет primary standard. |
| STD-GAP-033 | ФСБ Приказ № 378 / ГОСТ TLS | research | P3 | done (2026-05-05) | 10 | ✓ Research scope зафиксирован в §6.4 этого документа: цель, acceptance criteria, open questions, блокирующие условия. Артефакт research-задачи — сама подсекция. Реальная имплементация детектора (RFC 9189 ГОСТ-наборы) не запускается до фидбека от ИСПДн-пользователей, собранного через `STD-GAP-031`. |
| STD-GAP-034 | ГОСТ Р 57580.1-2017 | covered | P3 | deferred | — | Узкий финтех; делегирует в ISO 27002 / ФСТЭК Меры, которые уже взяты в `STD-GAP-024` / `STD-GAP-031`. |
| STD-GAP-035 | External cross-source partial | covered | P1 | done (2026-05-05) | 2 | ✓ 17 правил в external-таблице получили cross-source partial CIS-ссылки в `docs/rule-coverage.md`: TLS / HSTS / redirect (NGINX §4.1.1, §4.1.4, §4.1.8 + Apache §7.1, §7.4, §7.11 + IIS §2.6, §7.1, §7.4, §7.5, §7.7-§7.9), TRACE (Apache §5.8), методы (NGINX §5.1.2 + Apache §5.7), VCS metadata (NGINX §2.5.3 + Apache §5.10-§5.13), статус-эндпойнты (Apache §2.4 / §2.8, NGINX §2.5.4), X-Content-Type-Options (NGINX §5.3.1), IIS detailed-error и version header (§3.4 / §3.11). Каждая запись помечена `(partial: runtime evidence; primary CIS reference at <local rule>)`. Вступительный абзац external-секции обновлён. |
| STD-GAP-036 | Drift / sync счётчиков | direct-rule | P1 | done (2026-05-06) | 1 | ✓ Counters обновлены в `docs/standards-roadmap.md` (370 правил: Nginx 83, Apache 84, Lighttpd 49, IIS 52, External 89, Universal 13). Sync-check реализован в `tests/test_rule_coverage_doc.py` (`test_repeated_document_counters_match_registry`): repeated counters в `README.md`, `docs/architecture.md`, `docs/standards-roadmap.md`, `docs/benchmarks-covering.md` и `docs/rule-coverage.md` валидируются против registry. |
| STD-GAP-037 | ASVS V8 / V11 deepening | parser-depth | P3 | deferred | — | Расширение существующего ASVS-покрытия за рамками текущей итерации. |
| STD-GAP-038 | Standard-family helper migration | metadata-depth | P2 | accepted | 12 | Core `STD-GAP-012` output path уже готов. Следующий этап — решить, какие topic-grouped mappings должны стать typed `StandardReference` metadata в правилах, добавить helper-функции для NIST / PCI / ISO / ФСТЭК при необходимости, и отдельно решить, нужен ли `tier=secondary` для ATT&CK / БДУ. |

## 10. Acceptance criteria for new standards-mapping PRs

- versioned identifier обязателен (`NIST SP 800-52 Rev. 2 §3.3.1`,
  `PCI DSS v4.0.1 Req. 4.2.1`, `ФСТЭК «Меры защиты ГИС» п. ИАФ.6`);
- partial-coverage аннотация обязательна, если signal не доказывает полное
  выполнение требования;
- любая ссылка на ATT&CK, БДУ, или CWE Top 25 — **secondary** (не основная);
- `tests/test_rule_coverage_doc.py` должен оставаться зелёным после
  добавления новых столбцов (или после расширения существующих);
- никаких новых правил в одном PR с маппингом — code-level rule additions
  идут отдельным rule-implementation PR из общего backlog.

## 11. CWE Top 25 (2024) severity calibration

Артефакт `STD-GAP-029`. Это выполненная перекалибровка severity для
выбранных правил с CWE из Top 25 (2024). Таблица ниже сохранена как rationale:
какие правила подняты до `medium`, а какие disclosure-only правила оставлены
на прежней severity.

Источник Top 25: [CWE Top 25 Most Dangerous Software Weaknesses (2024)](https://cwe.mitre.org/top25/archive/2024/2024_cwe_top25.html).

Принцип отбора: правило повышалось до `medium`, если

1. его cited CWE входит в Top 25 (2024);
2. signal действительно проявляет exploit primitive (не информационная
   утечка), либо приводит к authn/authz bypass;
3. правило до перекалибровки имело severity `low`.

Правила с CWE из Top 25, но без exploit primitive (например, CWE-200
information disclosure через `Server` header), остаются `low` —
конфигурационная утечка версии не превращается в эксплуатацию сама по
себе.

### Applied bumps

| Rule ID | CWE (Top 25 2024 rank) | Previous | Implemented | Justification |
| --- | --- | --- | --- | --- |
| `nginx.alias_without_trailing_slash` | CWE-22 (rank 5) | low | **medium** | Path traversal — реальный exploit primitive; конфигурационная ошибка сразу даёт выход за корень. Rank 5 в Top 25 — выше большинства WebApp-специфичных классов. |
| `nginx.allow_all_with_deny_all` | CWE-863 (rank 18) | low | **medium** | Несогласованный `allow all; deny all;` ломает порядок ACL и реально пускает анонимный трафик к закрытым ресурсам. Это authorization bypass, не misconfig hint. |
| `nginx.missing_auth_basic_user_file` | CWE-287 (rank 14) | low | **medium** | `auth_basic` без `auth_basic_user_file` оставляет endpoint без эффективной аутентификации. IIS-аналоги (`iis.anonymous_auth_enabled`, `iis.authorization_allows_anonymous_users`) уже medium — bump даёт паритет между server families. |

### Правила, которые **остаются** low (с обоснованием)

| Rule ID | CWE (Top 25 2024 rank) | Decision | Justification |
| --- | --- | --- | --- |
| `nginx.server_tokens_on`, `apache.server_tokens_not_prod`, `apache.server_signature_not_off`, `lighttpd.server_tag_not_blank`, все `external.*.version_disclosed_in_server_header`, `external.x_powered_by_header_present`, `external.x_aspnet_version_header_present`, `external.iis.aspnet_version_header_present` | CWE-200 (rank 17) | keep `low` | Раскрытие версии сервера/фреймворка — информационный сигнал. Top 25 rank 17 у CWE-200 в основном тащат OOB read / memory disclosure из C/C++. Bump до medium создаст шум на типичных production-конфигурациях. |
| `apache.server_info_exposed`, `apache.server_status_exposed`, `external.server_status_exposed`, `external.server_info_exposed`, `external.nginx_status_exposed`, `external.apache.mod_status_public`, `external.lighttpd.mod_status_public`, `lighttpd.mod_status_public` | CWE-200 (rank 17) | keep severity (medium / low по существующей калибровке) | Уже отстроено: medium для public exposure, low для disclosure-only. Top 25 эту структуру не меняет. |
| `apache.file_etag_inodes`, `apache.trace_enable_not_off`, `external.trace_method_allowed`, `external.trace_method_exposed_via_options`, `iis.http_runtime_version_header_enabled`, `iis.custom_headers_expose_server`, `iis.request_filtering_remove_server_header_disabled` | CWE-200 (rank 17) | keep `low` | По той же логике — disclosure / hardening, не exploit primitive. |
| `nginx.executable_scripts_allowed_in_uploads` | CWE-434 (rank 10) | keep `medium` | Уже medium. Top 25 это подтверждает. |
| `iis.credentials_stored_in_config` | CWE-798 (rank 22) | keep `medium` | Уже medium. Top 25 это подтверждает. |
| `iis.anonymous_auth_enabled`, `iis.authorization_allows_anonymous_users`, `iis.basic_auth_without_ssl` | CWE-287 (rank 14) | keep `medium` | Уже medium. |
| `iis.application_pool_identity_*`, `iis.trust_level_full`, `iis.anonymous_auth_uses_specific_user`, `iis.sites_share_application_pool` | CWE-250 / CWE-668 — **не** в Top 25 (CWE-269 близко, но cited класс другой) | keep `medium` | Top 25 не применим: проект использует CWE-250 / CWE-668, эти ID в Top 25 не входят. Предложение не трогает их. |

### Границы перекалибровки

- Не меняет CWE-маппинг на «более удобный для Top 25» — это нарушило бы
  honesty-first methodology. Если CWE-250 в IIS application pool правилах
  сегодня правильный — подмена на CWE-269 ради попадания в Top 25
  запрещена.
- Не вводит «Top 25»-колонку в `docs/rule-coverage.md` — Top 25 это
  каталог приоритетов, не стандарт защиты, и в проекте применяется как
  калибровочный сигнал, не как ссылка на правиле.
- Не меняет severity у правил `low`, чьи CWE в Top 25, но не дают exploit
  primitive (см. таблицу «keep low»).

### Implementation checklist

1. Изменены severity metadata и `Finding.severity` в файлах:
   - `src/webconf_audit/local/nginx/rules/alias_without_trailing_slash.py`,
   - `src/webconf_audit/local/nginx/rules/allow_all_with_deny_all.py`,
   - `src/webconf_audit/local/nginx/rules/missing_auth_basic_user_file.py`.
2. Обновлены регрессионные тесты, которые проверяют severity для этих правил.
3. Обновлены `docs/rule-coverage.md` summary counts и строки инвентаря.
4. `tests/test_rule_coverage_doc.py` остаётся drift-check для registry/docs
   sync.
