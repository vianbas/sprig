# SPR-SRC-005 — Frame options disabled

| | |
|---|---|
| Severity | MEDIUM |
| Kind | SOURCE |
| Tags | `headers`, `clickjacking`, `source` |

## Description

`headers().frameOptions().disable()` removes the `X-Frame-Options` header,
allowing the app to be embedded in a frame on a third-party page. That is the
basis of **clickjacking** attacks: the victim clicks UI the attacker overlays on
your app.

Both stacks have the switch. Measured on a Spring Boot 3.5.16 WebFlux app,
twice: a `SecurityWebFilterChain` calling `frameOptions(f -> f.disable())` sent
no `X-Frame-Options` header, while the same app without that call sent
`X-Frame-Options: DENY`.

## Detection

Fires on a `SecurityFilterChain` or `SecurityWebFilterChain` body that disables
frame options, in either style:

- `.frameOptions().disable()`
- `.headers(h -> h.frameOptions(fo -> fo.disable()))`

## False-positive rationale

- Scoped specifically to `frameOptions` + `disable`. A plain
  `csrf(csrf -> csrf.disable())` is never flagged.
- `frameOptions().sameOrigin()` on the servlet stack and
  `frameOptions(fo -> fo.mode(Mode.SAMEORIGIN))` on WebFlux are safe and not
  flagged.
- A `disable()` that runs only inside an `if`, a ternary or a `switch` case is
  **not** flagged, because the header stays on until that condition holds. halo
  (`halo-dev/halo` at `a559d15`) calls `frameSpec.disable()` only when its
  operator-set `frameOptions.isDisabled()` property is true, and that property
  defaults to `false`; reporting it would say the header is gone from an app
  that sends it by default. This is a knowing miss: a condition that does hold in
  production, such as a profile check, goes unreported as well.

## Remediation

Keep the default (`DENY`), or use `SAMEORIGIN` when the app must be framed by
itself.

Servlet:

```java
http.headers(headers -> headers.frameOptions(fo -> fo.sameOrigin()));
```

WebFlux:

```java
http.headers(headers -> headers.frameOptions(fo -> fo.mode(Mode.SAMEORIGIN)));
```
