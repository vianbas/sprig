# SPR-CONFIG-002 — Hardcoded secret in configuration

| | |
|---|---|
| Severity | MEDIUM |
| Kind | CONFIG |
| Tags | `secrets`, `config` |

## Description

A credential-like property (`password`, `secret`, `token`, `api-key`,
`client-secret`, ...) is set to a literal value in `application.yml` /
`application.properties`. Literal secrets are committed to version control,
appear in logs and backups, and cannot be rotated safely.

## Detection

Fires when a property whose dotted key contains a sensitive segment has a
non-empty, non-placeholder, literal value.

## False-positive rationale

- `spring.datasource.password: ${DB_PASSWORD}` — a placeholder — is **not**
  flagged; that is the recommended pattern.
- Empty values and allow-listed values (`secret-allowlist` in `sprig.yml`) are
  skipped.
- Only keys with a known sensitive segment match, so unrelated keys are
  ignored.

## Remediation

```yaml
spring:
  datasource:
    password: ${DB_PASSWORD}
```

and provide the value through the environment or a secret manager.
