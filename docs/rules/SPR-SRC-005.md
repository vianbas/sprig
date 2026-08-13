# SPR-SRC-005 — Frame options disabled

| | |
|---|---|
| Severity | MEDIUM |
| Kind | SOURCE |
| Tags | `headers`, `clickjacking`, `source` |

## Description

`headers().frameOptions().disable()` removes the `X-Frame-Options` header,
allowing the app to be embedded in a frame on a third-party page — the basis of
**clickjacking** attacks (the victim clicks UI the attacker overlays on your
app).

## Detection

Fires on a `SecurityFilterChain` body that disables frame options, in either
style:

- `.frameOptions().disable()`
- `.headers(h -> h.frameOptions(fo -> fo.disable()))`

## False-positive rationale

- Scoped specifically to `frameOptions` + `disable`. A plain
  `csrf(csrf -> csrf.disable())` is never flagged.
- `frameOptions().sameOrigin()` is safe and not flagged.

## Remediation

Keep the default (`DENY`), or use `SAMEORIGIN` when the app must be framed by
itself:

```java
http.headers(headers -> headers.frameOptions(fo -> fo.sameOrigin()));
```
