# SPR-CONFIG-001 — Actuator exposes sensitive endpoints

| | |
|---|---|
| Severity | HIGH |
| Kind | CONFIG |
| Tags | `actuator`, `info-exposure`, `config` |

## Description

`management.endpoints.web.exposure.include: "*"` (or `env`, `heapdump`,
`shutdown`) exposes Spring Boot Actuator over HTTP. The classic CVE pattern:
`/actuator/env` leaks environment variables (secrets, credentials), and
`/actuator/heapdump` leaks process memory — including tokens and keys.

## Detection

Fires when `management.endpoints.web.exposure.include` contains `*`, `env`,
`heapdump`, or `shutdown` (comma-separated or YAML list).

## False-positive rationale

- Safe, explicit lists (`health`, `info`) are never flagged.
- JMX exposure (`management.endpoints.jmx.*`) is not in scope.

## Remediation

```yaml
management:
  endpoints:
    web:
      exposure:
        include: health,info
```

Better still, run management on a non-public port and require authentication.
