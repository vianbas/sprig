# SPR-CORS-001 — CORS wildcard with credentials

| | |
|---|---|
| Severity | HIGH |
| Kind | SOURCE |
| Tags | `cors`, `source` |

## Description

`@CrossOrigin(origins = "*")` combined with `allowCredentials = "true"` lets
*browser requests from any origin* send credentialed requests (cookies, HTTP
auth) to your API. Any website the victim visits can issue cross-origin
requests against your app while the victim's session cookies are attached.

## Detection

Fires when a `@CrossOrigin` annotation has `allowCredentials` resolving to
`true`, and either:

- `origins` explicitly contains `"*"`, or
- `origins` is absent altogether **and** `originPatterns` is also absent —
  Spring's own default when neither is set is to allow every origin, so this
  is the same vulnerable combination as an explicit `"*"`.

## False-positive rationale

- An allowlist of concrete origins (`origins = "https://app.example.com"`)
  is never flagged.
- Setting `originPatterns` (even to a wildcard pattern like
  `"https://*.example.com"`) overrides Spring's implicit `"*"` default, so
  it is not flagged as the implicit case — only an explicit `"*"` in
  `origins` itself would still trigger the rule.
- `allowCredentials` defaults to `""` (treated as off), so a bare
  `@CrossOrigin(origins = "*")` or a bare `@CrossOrigin` with nothing set is
  not flagged — matching Spring's own default behavior.

## Remediation

```java
@CrossOrigin(origins = "https://app.example.com", allowCredentials = "true")
```

Never combine a wildcard origin with credentials. If credentials are needed,
enumerate the exact origins.
