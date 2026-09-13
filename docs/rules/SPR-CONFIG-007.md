# SPR-CONFIG-007 — CORS open to every origin, without credentials (config)

| | |
|---|---|
| Severity | MEDIUM |
| Kind | CONFIG |
| Tags | `cors`, `config` |

## Description

CORS configured to accept every origin, with `allow-credentials` unset or
`false`, on one of the two surfaces Spring Boot exposes as configuration
properties: Actuator's `management.endpoints.web.cors.*` and GraphQL's
`spring.graphql.cors.*`. Any web page can then read those responses from a
visitor's browser. Without `Access-Control-Allow-Credentials: true` a page can
only read responses to requests made without the visitor's cookies, so what
leaks is what the visitor's browser can reach without logging in.

Measured on Spring Boot 3.5.16, twice, with a request carrying
`Origin: https://evil.example`:

| Configuration | Actuator `GET /actuator/health` | GraphQL `POST /graphql` |
|---|---|---|
| no CORS properties | no `Access-Control-Allow-Origin` | no `Access-Control-Allow-Origin` |
| `allowed-origins: "*"` | `Access-Control-Allow-Origin: *` | `Access-Control-Allow-Origin: *` |
| `allowed-origins: "*"`, `allow-credentials: false` | `Access-Control-Allow-Origin: *` | not measured |
| `allowed-origin-patterns: "*"` | the origin echoed back | not measured |

The GraphQL measurement also set `allowed-methods: POST`. In none of these
responses was `Access-Control-Allow-Credentials` present.

This is the variant that survives on current Spring. The same wildcard with
`allow-credentials: true` is SPR-CONFIG-004, and on Boot 3.5.16 it stopped the
application from starting (Actuator) or answered the request with a 500
(GraphQL).

## Detection

Fires when, **within one namespace and one file**, `allow-credentials` is not
`true` and either:

- `allowed-origins` contains `*`, or
- `allowed-origin-patterns` contains a pattern whose host is a bare `*`: `*`,
  `<scheme>://*` or `<scheme>://*:[*]`.

Values written as a comma-separated string or as a YAML list are both read.

## False-positive rationale

- A concrete origin list is never flagged, and neither is a pattern with a
  bounded host. On Boot 3.5.16, `https://*.example.com` refused
  `https://evil.example` with a 403.
- Origins and credentials are paired within one namespace. An Actuator wildcard
  next to a GraphQL `allow-credentials: true` is reported here rather than as
  SPR-CONFIG-004, because Actuator's own credentials setting is what decides.
- Severity stays MEDIUM whatever `management.endpoints.web.exposure.include`
  says. A broad exposure list is reported by SPR-CONFIG-001 on its own, and a
  configuration file cannot say whether the service is reachable from the
  internet or only from a network a visitor's browser happens to reach. The
  second case is where this finding matters most.
- The legacy `endpoints.cors.*` namespace is not checked. It is declared in
  `spring-boot-actuator-autoconfigure` 2.2.13.RELEASE and absent from
  2.3.12.RELEASE.

## Remediation

List the origins that need cross-origin access:

```yaml
management:
  endpoints:
    web:
      cors:
        allowed-origins: https://app.example.com
```

If nothing needs it, remove the CORS properties. Spring then sends no
`Access-Control-Allow-Origin` header at all.
