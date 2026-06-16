# Security Policy

`webconf-audit` analyzes security-sensitive configuration files and can perform
safe external HTTP/HTTPS/TLS observations. Please avoid posting real secrets,
private infrastructure details, or production configuration files in public
issues.

## Supported Versions

The project is pre-1.0. Security fixes target the latest released `0.1.x`
version and the current `master` branch.

| Version | Supported |
|---------|-----------|
| 0.1.x | yes |
| older versions | no |

## Reporting A Vulnerability

If GitHub private vulnerability reporting is available for the repository, use
it. Otherwise, open a public issue with only a minimal non-sensitive summary and
ask for a private coordination channel.

Please include:

- affected version or commit;
- affected command or analyzer mode;
- minimal reproduction steps using sanitized input;
- expected impact;
- whether the issue affects local parsing, external probing, report output, or
  package distribution.

Please do not include:

- real credentials or tokens;
- full production configuration files;
- private hostnames, IP addresses, certificates, or customer data;
- exploit instructions against third-party systems.

## Scope

Security issues include parser crashes with security impact, unsafe XML or file
handling, unexpected network mutation, credential leakage in reports/logs,
malicious package-distribution behavior, or rule behavior that creates a
misleadingly unsafe default.

Ordinary false positives, false negatives, coverage gaps, and documentation
mistakes should be reported as normal issues unless they create an immediate
security risk.
