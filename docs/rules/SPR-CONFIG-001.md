# SPR-CONFIG-001 — Actuator exposes sensitive endpoints

| | |
|---|---|
| Severity | HIGH |
| Kind | CONFIG |
| Tags | `actuator`, `info-exposure`, `config` |

## Description

`management.endpoints.web.exposure.include: "*"` (or `env`, `heapdump`) puts
Spring Boot Actuator on the application's own HTTP connector. `/actuator/env`
leaks environment variables, which is where credentials live, and
`/actuator/configprops` leaks the resolved configuration alongside it.

What the wildcard reaches depends on the Boot version, and the difference is
worth stating because the older behaviour is the more serious one. Measured
against running apps with `include: "*"` and nothing else set:

| Endpoint | 2.3.12 | 3.3.13 | 3.5.16 |
|---|---|---|---|
| `env`, `configprops`, `beans`, `mappings`, `threaddump`, `loggers`, `metrics` | 200 | 200 | 200 |
| `heapdump` | 200 | 200 | **404** |
| `shutdown` | 404 | 404 | 404 |

- **Through Boot 3.3**, the wildcard alone serves `/actuator/heapdump`: a HPROF
  of the live process, carrying every credential and session token in memory.
- **From Boot 3.4**, the access gate holds `heapdump` at 404 until a second
  property opens it. On those versions this finding marks the exposure, and
  [SPR-CONFIG-006](SPR-CONFIG-006.md) is what reports the disclosure.
- **On every version**, the information leak through `env` and its neighbours
  is real and unauthenticated.

## Detection

Fires when `management.endpoints.web.exposure.include` contains `*`, `env`, or
`heapdump` (comma-separated or YAML list).

## False-positive rationale

- Safe, explicit lists (`health`, `info`) are never flagged.
- JMX exposure (`management.endpoints.jmx.*`) is not in scope.
- **`shutdown` in the exposure list is not flagged**, and used to be. Exposure
  does not reach it: `POST /actuator/shutdown` answered 404 under `include: "*"`
  on 2.3.12, 3.3.13 and 3.5.16 alike, because the endpoint ships switched off in
  every release. It takes `management.endpoint.shutdown.enabled: true` or, from
  3.4, `management.endpoint.shutdown.access: unrestricted` to open, which is
  SPR-CONFIG-006's subject. Flagging the bare token was a HIGH finding with
  nothing behind it (#45).

## Remediation

```yaml
management:
  endpoints:
    web:
      exposure:
        include: health,info
```

Better still, run management on a non-public port and require authentication.
