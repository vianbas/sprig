# SPR-CONFIG-004 — CORS wildcard with credentials (config)

| | |
|---|---|
| Severity | HIGH |
| Kind | CONFIG |
| Tags | `cors`, `config` |

## Description

CORS configured with `allowed-origins: "*"` and `allow-credentials: true` — the
config-side twin of SPR-CORS-001. Spring Boot exposes exactly two CORS surfaces
as plain configuration properties:

| Namespace | Since | Guards |
|---|---|---|
| `management.endpoints.web.cors.*` | Boot 2.0 | Actuator endpoints |
| `spring.graphql.cors.*` | Boot 2.7 | the GraphQL HTTP endpoint |

Spring MVC's own CORS has no property namespace; it is configured in Java and
belongs to SPR-CORS-001.

What the misconfiguration does depends on the Spring Framework version, and
both outcomes are worth fixing:

- **Framework 5.2 and below (Boot 2.3 and below)** — the wildcard is honoured.
  The attacker's origin is reflected back with
  `Access-Control-Allow-Credentials: true`, so any site can read Actuator
  responses with the victim's session attached.
- **Framework 5.3 and above (Boot 2.4 and above)** —
  `CorsConfiguration.validateAllowCredentials()` rejects the combination while
  the context is being built, so the application fails to start with a
  `BeanCreationException`. Not an exposure, but a broken deployment.

## Detection

Fires when, **within one namespace and one file**, `allowed-origins` contains
`*` and `allow-credentials` is `true`.

## False-positive rationale

- Origins and credentials are paired inside a single namespace. An Actuator
  wildcard is never paired with a GraphQL `allow-credentials`, or the reverse.
- Both keys must be present in the **same file** (base and profile files are
  never merged).
- Concrete origin lists are never flagged.
- `allowed-origin-patterns` is not treated as a wildcard. It is Spring's
  documented way to allow credentials against a matched set of origins, and it
  deserves a rule of its own rather than being folded in here.

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

Do not reach for `allowed-origin-patterns: "*"` to silence a startup failure.
That bypasses the check rather than fixing the configuration, and restores the
exposure the check exists to prevent.
