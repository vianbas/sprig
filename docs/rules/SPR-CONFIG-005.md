# SPR-CONFIG-005 — Security debug logging enabled

| | |
|---|---|
| Severity | LOW |
| Kind | CONFIG |
| Tags | `logging`, `config` |

## Description

`logging.level.org.springframework.security: DEBUG` turns on Spring Security's
own debug output: the filter chain is printed at startup, and every request
logs the filters it passes through and the authentication that was resolved.
In production that lands request and principal internals in the log stream.
Usually left on by accident after local debugging.

`TRACE` is louder still and is flagged the same way.

## Detection

Fires when `logging.level.org.springframework.security`, or any logger nested
under it such as `logging.level.org.springframework.security.web`, is set to
`DEBUG` or `TRACE`.

## False-positive rationale

- Only `DEBUG` and `TRACE` are flagged. `INFO`, `WARN`, `ERROR` and `OFF` are
  ignored, as is the absence of the property.
- Unrelated loggers are not matched. `logging.level.org.springframework.web` is
  noisy but not security-sensitive, and is left alone.

## Not covered

`@EnableWebSecurity(debug = true)` is the annotation equivalent and produces
the same output. It is a SOURCE-kind concern and is not detected by this rule.

## Remediation

Raise the level, or scope the verbose level to a dev-only profile:

```yaml
logging:
  level:
    org.springframework.security: INFO
---
spring:
  config:
    activate:
      on-profile: dev
logging:
  level:
    org.springframework.security: DEBUG
```
