# Security Policy

sprig's own attack surface matters more than most CLI tools: it's designed
to run against untrusted, third-party Spring Boot projects (including in
CI), and it reads a `sprig.yml` that may itself come from the scanned
project. A vulnerability in sprig (e.g. a way for a malicious target project
or `sprig.yml` to trigger code execution, path traversal, or a denial of
service in the scanner) is treated as a security issue, not just a bug.

## Reporting a vulnerability

**Please do not open a public issue for a security vulnerability.**

Use [GitHub Security Advisories](https://github.com/vianbas/sprig/security/advisories/new)
to report privately. Include:

- The affected version (`sprig version`)
- A minimal reproduction (a malicious fixture project and/or `sprig.yml`)
- The impact you'd expect (crash, RCE, path traversal, resource exhaustion, ...)

You should get an initial response within a few days. If a report is
confirmed, a fix is prioritized ahead of other work and a coordinated
disclosure timeline is agreed with the reporter before any public advisory
or release notes are published.

## Supported versions

sprig is pre-1.0; only the latest released version is supported.
