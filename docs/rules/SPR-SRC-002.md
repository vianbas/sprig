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
  `.password("{noop}admin123")` or `"{noop}" + password`), unless the literal
  is an argument or the receiver of `startsWith`, `endsWith`, `equals`,
  `equalsIgnoreCase`, `contains`, `indexOf` or `lastIndexOf`.

## False-positive rationale

- Only the concrete `NoOpPasswordEncoder` type and the `{noop}` prefix are
  matched — `BCryptPasswordEncoder`, `DelegatingPasswordEncoder`, etc. are
  never flagged.
- A `{noop}` literal that a string comparison tests against, such as
  `stored.startsWith("{noop}")`, is code looking for NoOp passwords, not a
  password, and is not flagged. sprig's own implementation of this rule is one,
  and was reported as a finding on this repository before (code-scanning alert
  #29). The cost is that a password literal passed to one of those methods, for
  example `users.contains("{noop}admin")`, goes unreported.

## Remediation

Use a strong hash:

```java
@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
}
```

and store `{bcrypt}...` hashes in the user store.
