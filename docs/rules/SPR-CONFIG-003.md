# SPR-CONFIG-003 — Insecure session cookie flags

| | |
|---|---|
| Severity | MEDIUM |
| Kind | CONFIG |
| Tags | `cookies`, `session`, `config` |

## Description

The session cookie flags are explicitly disabled:

- `http-only: false` — JavaScript can read the session cookie, so an XSS bug
  becomes session theft.
- `secure: false` — the cookie is sent over plain HTTP, enabling interception.

## Detection

Fires when `server.servlet.session.cookie.http-only` or
`server.servlet.session.cookie.secure` is explicitly `false`.

## False-positive rationale

- Only explicit `false` is flagged. The (insecure) Boot default is left alone to
  avoid noise; this rule is a deliberate "you turned it off" signal.
- Any other value (`true`) is never flagged.

## Remediation

```yaml
server:
  servlet:
    session:
      cookie:
        http-only: true
        secure: true
```
