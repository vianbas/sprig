# SPR-CONFIG-004 — CORS wildcard with credentials (config)

| | |
|---|---|
| Severity | HIGH |
| Kind | CONFIG |
| Tags | `cors`, `config` |

## Description

CORS configured to accept every origin together with `allow-credentials: true`,
the config-side twin of SPR-CORS-001. Spring Boot exposes exactly two CORS
surfaces as plain configuration properties:

| Namespace | Since | Guards |
|---|---|---|
| `management.endpoints.web.cors.*` | Boot 2.0 | Actuator endpoints |
| `spring.graphql.cors.*` | Boot 2.7 | the GraphQL HTTP endpoint |

Spring MVC's own CORS has no property namespace; it is configured in Java and
belongs to SPR-CORS-001.

"Every origin" can be written two ways, and they fail differently.

### `allowed-origins: "*"`

On Framework 5.2 and below (Boot 2.3 and below) the wildcard is honoured. The
attacker's origin is reflected back with `Access-Control-Allow-Credentials:
true`, so any site can read Actuator responses with the victim's session
attached.

From Framework 5.3, `CorsConfiguration.validateAllowCredentials()` rejects the
combination with an `IllegalArgumentException` that begins "When
allowCredentials is true, allowedOrigins cannot contain the special value "*"".
Where that surfaces depends on the namespace. Measured on Boot 3.5.16, twice:

| Namespace | Result |
|---|---|
| Actuator | the application fails to start, with a `BeanCreationException` caused by that exception |
| GraphQL | the application starts; `POST /graphql` answers 500 with that exception and the preflight answers 403 |

Neither is an exposure, but both are broken deployments.

### `allowed-origin-patterns` with a bare `*` host

Patterns are not subject to that check, which makes them the variant that still
leaks on current Spring. Measured on Boot 3.5.16, twice each, with
`allow-credentials: true`:

| Pattern | Request `Origin` | Response |
|---|---|---|
| `*` | `https://evil.example` | origin echoed back with `Access-Control-Allow-Credentials: true`, on Actuator and on GraphQL |
| `https://*` | `https://evil.example` | origin echoed back with `Access-Control-Allow-Credentials: true` |
| `http://*` | `http://evil.example` | origin echoed back with `Access-Control-Allow-Credentials: true` |
| `https://*:[*]` | `https://evil.example` | origin echoed back with `Access-Control-Allow-Credentials: true` |
| `https://*.example.com` | `https://evil.example` | 403 |
| `https://*.example.com` | `https://a.example.com` | origin echoed back with `Access-Control-Allow-Credentials: true` |

Every row after the first was measured on Actuator. The GraphQL measurement also
set `allowed-methods: POST`.

## Detection

Fires when, **within one namespace and one file**, `allow-credentials` is `true`
and either:

- `allowed-origins` contains `*`, or
- `allowed-origin-patterns` contains a pattern whose host is a bare `*`: `*`,
  `<scheme>://*` or `<scheme>://*:[*]`.

Values written as a comma-separated string or as a YAML list are both read. The
same condition with credentials unset or `false` is SPR-CONFIG-007.

## False-positive rationale

- Origins and credentials are paired inside a single namespace. An Actuator
  wildcard is never paired with a GraphQL `allow-credentials`, or the reverse.
- Both keys must be present in the **same file** (base and profile files are
  never merged).
- Concrete origin lists are never flagged, and neither are patterns with a
  bounded host such as `https://*.example.com`, which refused an unrelated
  origin in the measurement above. A `*` host with a specific port, such as
  `https://*:8080`, is not treated as an any-host pattern; that form was not
  measured.
- This rule used to ignore `allowed-origin-patterns` entirely, on the view that
  patterns deserved a rule of their own. The measurement above shows that a bare
  `*` host gives the exposure the wildcard check exists to prevent, so it is
  reported here (#41).

## Remediation

List the origins explicitly:

```yaml
management:
  endpoints:
    web:
      cors:
        allowed-origins: https://app.example.com
        allow-credentials: true
```

Do not reach for `allowed-origin-patterns: "*"` to silence the startup failure
or the 500. As measured above, it echoes any origin back with credentials, and
this rule reports it.
