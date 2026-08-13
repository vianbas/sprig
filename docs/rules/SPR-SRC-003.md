# SPR-SRC-003 — `anyRequest().permitAll()` without authentication

| | |
|---|---|
| Severity | HIGH |
| Kind | SOURCE |
| Tags | `auth`, `source` |

## Description

A `SecurityFilterChain` that calls `.anyRequest().permitAll()` and configures no
authentication mechanism leaves **every endpoint public** — authorization is
effectively disabled.

## Detection

Fires on a method returning `SecurityFilterChain` whose body contains
`.anyRequest().permitAll()` and no `.anyRequest().authenticated()` and no
authentication mechanism (`httpBasic`, `formLogin`, `oauth2Login`,
`oauth2ResourceServer`, `addFilter*`, ...).

## False-positive rationale

- Only the `.anyRequest()` matcher is considered. Path-scoped
  `.requestMatchers("/public/**").permitAll()` is **not** flagged — that is the
  intended pattern for whitelisting specific paths.
- If an auth mechanism or `.anyRequest().authenticated()` is present, the rule
  stays silent.

## Remediation

```java
http
    .authorizeHttpRequests(auth -> auth
        .requestMatchers("/public/**").permitAll()
        .anyRequest().authenticated());
```
