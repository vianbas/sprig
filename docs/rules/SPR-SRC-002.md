# SPR-SRC-002 — NoOp password encoder / `{noop}` passwords

| | |
|---|---|
| Severity | HIGH |
| Kind | SOURCE |
| Tags | `auth`, `password`, `source` |

## Description

`NoOpPasswordEncoder` (or `User.withDefaultPasswordEncoder()`) stores passwords
**as plaintext**. The `{noop}` prefix in a stored password tells Spring Security
to use no hashing at all. A leaked database then exposes every credential
directly.

## Detection

Fires on any of:

- return type or instantiation of `NoOpPasswordEncoder`;
- `NoOpPasswordEncoder.getInstance()`;
- a string literal starting with `{noop}` (e.g.
  `.password("{noop}admin123")`).

## False-positive rationale

- Only the concrete `NoOpPasswordEncoder` type and the `{noop}` prefix are
  matched — `BCryptPasswordEncoder`, `DelegatingPasswordEncoder`, etc. are
  never flagged.

## Remediation

Use a strong hash:

```java
@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
}
```

and store `{bcrypt}...` hashes in the user store.
