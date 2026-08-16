# SPR-CONFIG-006 — Actuator shutdown or heapdump both exposed and switched on

| | |
|---|---|
| Severity | CRITICAL |
| Kind | CONFIG |
| Tags | `actuator`, `config` |

## Description

Spring Boot ships `shutdown` and `heapdump` switched off. Reaching either takes
two properties, not one: the endpoint has to be in the web exposure list **and**
its access gate has to be open. This rule fires only when both are true in the
same file, and what it reports is not a possibility but a request that succeeds:

- `POST /actuator/shutdown` returns 200 and the process exits.
- `GET /actuator/heapdump` returns a HPROF of the live heap. Everything the
  application holds in memory is in it: datasource passwords, session tokens,
  signing keys.

Neither gate is enough alone. Measured on Boot 3.5.16, with
`exposure.include: health,info` and `management.endpoint.shutdown.access:
unrestricted` set, `POST /actuator/shutdown` still answers 404. Add the id to
the exposure list and the same request answers 200.

## What reaches what

Every cell below is an observed HTTP status against a running app
(`spring-boot-starter-web` + `spring-boot-starter-actuator`, no security
starter), with `management.endpoints.web.exposure.include: "*"`.

Each cell is `heapdump` / `shutdown`.

| Configuration | 2.3.12 | 3.3.13 | 3.5.16 |
|---|---|---|---|
| exposure only | 200 / 404 | 200 / 404 | **404** / 404 |
| `endpoint.<id>.enabled: true` | 200 / **200** | 200 / **200** | **200** / **200** |
| `endpoints.enabled-by-default: true` | 200 / **200** | 200 / **200** | **200** / **200** |
| `endpoint.<id>.access: unrestricted` | 200 / 404 | 200 / 404 | **200** / **200** |
| `endpoint.<id>.access: read-only` | 200 / 404 | 200 / 404 | **200** / 404 |
| `endpoints.access.default: unrestricted` | 200 / 404 | 200 / 404 | **200** / **200** |
| `endpoints.access.max-permitted` | 200 / 404 | 200 / 404 | **200** / 404 |

Where a row says `<id>`, the id measured was `shutdown` on 2.3.12 and 3.3.13 and
both ids on 3.5.16. `heapdump` needs no help before 3.4, which is the point of
the first row; on 3.3.13 setting `heapdump.enabled: false` takes it from 200 to
404, so the property binds there as well.

The whole `access` family is inert before 3.4, measured rather than assumed.
The pre-3.4 columns of the last row were taken at `max-permitted: none`, the
strictest value there is, and it still left `heapdump` answering 200; the 3.5.16
column is at `read-only`. Everything reading 200 in those two columns is what
exposure alone already gives, which is why `heapdump` on Boot 2.x and 3.3
belongs to SPR-CONFIG-001 rather than here.

Three things fall out of that table and are built into the rule:

- **`read-only` is enough to leak.** `heapdump` is a GET, so read-only access
  serves it. Only `shutdown`, a POST, needs `unrestricted`.
- **Both spellings are live.** `enabled` works from 2.x through 3.5;
  `access` arrived in 3.4 and does nothing before it. Neither replaced the
  other on any version measured.
- **`max-permitted` caps writes only.** `read-only` takes `shutdown` back to
  404 and leaves `heapdump` serving a real dump. It caps both spellings:
  `shutdown.enabled: true` under a `read-only` cap is 404 on 3.5.16.

sprig does not read `pom.xml` or `build.gradle` and so has no idea which Boot
version a scanned project builds against. It reports either spelling and leaves
the version question to this table.

## Detection

Fires when, **within one file**, `management.endpoints.web.exposure.include`
contains `*` or the endpoint id, and one of the following opens that endpoint:

| Property | Opens `shutdown` at | Opens `heapdump` at |
|---|---|---|
| `management.endpoint.<id>.enabled` | `true` | `true` |
| `management.endpoint.<id>.access` | `unrestricted` | `unrestricted`, `read-only` |
| `management.endpoints.enabled-by-default` | `true` | `true` |
| `management.endpoints.access.default` | `unrestricted` | `unrestricted`, `read-only` |

The finding points at the property that opens the gate, because that is the line
a reader has to change.

## False-positive rationale

- **Exposure without access is not a finding.** An open gate on an endpoint
  missing from the exposure list reaches nothing, and neither does exposure
  without the gate. Both are fixtures.
- **A per-endpoint setting beats the blanket one.** `access.default:
  unrestricted` with `shutdown.access: none` leaves shutdown at 404, and the
  rule stays quiet about shutdown while still reporting `heapdump`.
- **`max-permitted` is honoured**, and only against write access, which is
  where a simpler reading would produce a wrong answer in both directions.

  This is the one place the rule knowingly trades a miss for the quiet. The cap
  arrived in 3.4 and does nothing before it: on 3.3.13, `shutdown.enabled: true`
  under `max-permitted: read-only` still answers 200, and the rule stays silent.
  Reading the cap as inert instead would put a CRITICAL finding on every
  correctly capped 3.4+ project, and a 3.4-only property written into a pre-3.4
  project is already a line that does nothing on its own terms.
- **Both keys must be in the same file.** Base and profile files are never
  merged, matching SPR-CONFIG-004.
- **`env`, `configprops`, `beans`, `mappings`, `threaddump` are not in scope.**
  All five answered 200 on all three versions from exposure alone, so an
  `access` property that opens one of them adds no reachability that the
  exposure list has not already granted. Exposing them is SPR-CONFIG-001's
  finding, and #45 proposed covering them here before that was measured.

## Remediation

Take the endpoint out of the exposure list:

```yaml
management:
  endpoints:
    web:
      exposure:
        include: health,info
```

Or close the gate explicitly, which is what to reach for when the wildcard has
to stay:

```yaml
management:
  endpoint:
    shutdown:
      access: none      # Boot 3.4+
      enabled: false    # honoured on 2.3.12, 3.3.13 and 3.5.16
```

If the endpoint is genuinely needed, move management to its own port behind
authentication rather than leaving it on the application connector.
