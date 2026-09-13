# SPR-SRC-003 — `anyRequest().permitAll()` or `anyExchange().permitAll()` without authentication

| | |
|---|---|
| Severity | HIGH |
| Kind | SOURCE |
| Tags | `auth`, `source` |

## Description

A Spring Security filter chain that permits every request and configures no
authentication mechanism leaves **every endpoint public**: authorization is
effectively disabled.

| Stack | Bean type | Call |
|---|---|---|
| Servlet (Spring MVC) | `SecurityFilterChain` | `.anyRequest().permitAll()` |
| Reactive (WebFlux) | `SecurityWebFilterChain` | `.anyExchange().permitAll()` |

Measured on a Spring Boot 3.5.16 WebFlux app with three routes, twice, with an
unauthenticated `GET`: when the chain's only authorization rule was
`anyExchange().permitAll()` and no authentication mechanism was configured, all
three routes answered 200. The same app answered 401 on all three once the chain
said `anyExchange().authenticated()` with `httpBasic`.

## Detection

Fires on a method returning `SecurityFilterChain` whose body contains
`.anyRequest().permitAll()`, or on a method returning `SecurityWebFilterChain`
whose body contains `.anyExchange().permitAll()`, when that body has no matching
`.authenticated()` call and no authentication mechanism (`httpBasic`,
`formLogin`, `oauth2Login`, `oauth2ResourceServer`, `addFilter*`, ...).

The finding message names the bean type, so servlet and WebFlux findings stay
distinguishable in the output.

## False-positive rationale

- Only the `.anyRequest()` and `.anyExchange()` matchers are considered.
  Path-scoped `.requestMatchers("/public/**").permitAll()` and
  `.pathMatchers("/public/**").permitAll()` are **not** flagged; that is the
  intended pattern for allowing specific paths.
- If an auth mechanism or the matching `.authenticated()` call is present, the
  rule stays silent. That is a judgement about intent, not a measurement of
  safety: on the same 3.5.16 WebFlux app, `anyExchange().permitAll()` together
  with `httpBasic` still answered 200 without credentials.
- Only the bean method's own body is read. A `permitAll()` applied to the
  `ServerHttpSecurity` from somewhere else is not seen. halo
  (`halo-dev/halo` at `a559d15`) applies its `anyExchange().permitAll()` from a
  separate configurer (`AuthorizationExchangeConfigurers.java:98`), so this rule
  does not report it.

## Remediation

Servlet:

```java
http
    .authorizeHttpRequests(auth -> auth
        .requestMatchers("/public/**").permitAll()
        .anyRequest().authenticated());
```

WebFlux:

```java
http
    .authorizeExchange(exchanges -> exchanges
        .pathMatchers("/public/**").permitAll()
        .anyExchange().authenticated())
    .httpBasic(Customizer.withDefaults());
```
