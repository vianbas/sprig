# SPR-SRC-004 — Method security annotations without `@EnableMethodSecurity`

| | |
|---|---|
| Severity | MEDIUM |
| Kind | SOURCE |
| Tags | `auth`, `source` |

## Description

`@PreAuthorize`, `@Secured` and `@RolesAllowed` are **silently ignored** unless
method security is activated with `@EnableMethodSecurity` (or the legacy
`@EnableGlobalMethodSecurity`). The authorization checks the developer believes
are in place never run.

## Detection

Fires when a project uses `@EnableWebSecurity`, uses any method security
annotation, and never enables method security.

## False-positive rationale

- Requires `@EnableWebSecurity` to be present; a project that activates method
  security through another route (e.g. `@EnableGlobalMethodSecurity`) is not
  flagged.
- Requires an actual method-security annotation to be used — dead configs are
  skipped.

## Remediation

```java
@Configuration
@EnableMethodSecurity
public class SecurityConfig { ... }
```
