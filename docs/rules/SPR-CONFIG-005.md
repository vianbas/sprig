# SPR-CONFIG-005 — Security debug enabled

| | |
|---|---|
| Severity | LOW |
| Kind | CONFIG |
| Tags | `logging`, `config` |

## Description

`spring.security.debug: true` enables verbose Spring Security logging that can
echo request/principal internals and filter chains in production logs. Usually
left on by accident from local debugging.

## Detection

Fires when `spring.security.debug` is explicitly `true`.

## False-positive rationale

- Only an explicit `true` is flagged; any other value or absence is ignored.

## Remediation

Remove the property, or scope it to a dev-only profile:

```yaml
---
spring:
  config:
    activate:
      on-profile: dev
  security:
    debug: true
```
