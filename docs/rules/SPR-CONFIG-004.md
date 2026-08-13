# SPR-CONFIG-004 — CORS wildcard with credentials (config)

| | |
|---|---|
| Severity | HIGH |
| Kind | CONFIG |
| Tags | `cors`, `config` |

## Description

CORS configured in `application.yml` with `allowed-origins: "*"` and
`allow-credentials: true` — the config-side twin of SPR-CORS-001. Any origin may
send credentialed requests.

## Detection

Fires when `allowed-origins` contains `*` and `allow-credentials` is `true` in
the same file, under either the Boot 3 key (`spring.web.cors.*`) or the Boot 2
key (`spring.mvc.cors.*`).

## False-positive rationale

- Both keys must be present and match in the **same file** (base vs profile
  files are never merged).
- Concrete origin lists are never flagged.

## Remediation

```yaml
spring:
  web:
    cors:
      allowed-origins: https://app.example.com
      allow-credentials: true
```
