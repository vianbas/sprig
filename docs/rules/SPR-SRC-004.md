# SPR-SRC-004 — Method security annotations without method security enabled

| | |
|---|---|
| Severity | MEDIUM |
| Kind | SOURCE |
| Tags | `auth`, `source` |

## Description

`@PreAuthorize`, `@Secured` and `@RolesAllowed` are **silently ignored** unless
method security is activated. The authorization checks the developer believes
are in place never run.

| Stack | Web security | Method security |
|---|---|---|
| Servlet (Spring MVC) | `@EnableWebSecurity` | `@EnableMethodSecurity`, or the legacy `@EnableGlobalMethodSecurity` |
| Reactive (WebFlux) | `@EnableWebFluxSecurity` | `@EnableReactiveMethodSecurity` |

Measured on a Spring Boot 3.5.16 WebFlux app with an unauthenticated `GET` to an
endpoint whose service method carries `@PreAuthorize("hasRole('ADMIN')")` and
returns `Mono<String>`. Each row was measured at least twice with the same
result.

| Method security on the WebFlux app | Response |
|---|---|
| none | 200, protected body returned |
| `@EnableReactiveMethodSecurity` | 401 |
| `@EnableMethodSecurity` | 500, `AuthenticationCredentialsNotFoundException` |
| `@EnableGlobalMethodSecurity(prePostEnabled = true)` | 500, `AuthenticationCredentialsNotFoundException` |

`@EnableReactiveMethodSecurity` also requires the secured method to return a
`Publisher`. On the same app, a `@PreAuthorize` method returning `String` failed
the call with `IllegalStateException`, saying the method must return an instance
of `org.reactivestreams.Publisher`.

## Detection

Fires when the project uses a method security annotation and either:

- uses `@EnableWebSecurity` and enables neither `@EnableMethodSecurity` nor
  `@EnableGlobalMethodSecurity`, reported at the `@EnableWebSecurity`
  annotation; or
- uses `@EnableWebFluxSecurity` and enables none of
  `@EnableReactiveMethodSecurity`, `@EnableMethodSecurity` or
  `@EnableGlobalMethodSecurity`, reported at the `@EnableWebFluxSecurity`
  annotation.

The finding message names which of the two it is.

## False-positive rationale

- Requires `@EnableWebSecurity` or `@EnableWebFluxSecurity` to be present.
- Requires an actual method-security annotation to be used; dead configs are
  skipped.
- A WebFlux project that enables `@EnableMethodSecurity` or
  `@EnableGlobalMethodSecurity` instead of `@EnableReactiveMethodSecurity` is not
  reported. As measured above, those annotations refuse the unauthenticated call
  with a 500 rather than serving it, so "not enforced" would be false. What they
  do for an authenticated caller was not measured, and this rule makes no claim
  about it.

## Remediation

Servlet:

```java
@Configuration
@EnableMethodSecurity
public class SecurityConfig { ... }
```

WebFlux, with secured methods returning `Mono` or `Flux`:

```java
@Configuration
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
public class SecurityConfig { ... }
```
