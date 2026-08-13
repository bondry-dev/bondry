# Security Policy

Bondry is in pre-alpha development and has not had a security audit. Do not use it to protect production credentials or expose production capabilities yet.

## Reporting a Vulnerability

Report vulnerabilities privately through GitHub's private vulnerability reporting for `bondry-dev/bondry`. Do not open a public issue for a suspected vulnerability.

## Security Principles

- Access is denied unless an explicit policy grants it.
- Authentication and authorization are separate decisions.
- Credentials are handled by authentication adapters and are not part of core invocation data.
- Audit events contain identifiers and outcomes, not credentials or request and response payloads.
- Network listeners default to local-only operation in adapters that provide them.
