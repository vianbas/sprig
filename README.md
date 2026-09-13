# sprig

[![CI](https://github.com/vianbas/sprig/actions/workflows/ci.yml/badge.svg)](https://github.com/vianbas/sprig/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Semantic-aware security misconfiguration linter for Spring Boot.**

`sprig` statically analyzes a Spring Boot project — **source code and
configuration** — without compiling or running it, and reports security
misconfigurations you'd rather find before a penetration test does.

```console
$ sprig scan .
SPR-CORS-001     [HIGH]   src/main/java/demo/CorsController.java:10  Cross-origin configured with origins=* and allowCredentials=true.
SPR-CONFIG-001   [HIGH]   src/main/resources/application.yml:5        Actuator endpoint(s) exposed: *.
SPR-SRC-002      [HIGH]   src/main/java/demo/PasswordConfig.java:13   Insecure password handling: NoOpPasswordEncoder or {noop} plaintext password used.
SPR-SRC-003      [HIGH]   src/main/java/demo/SecurityConfig.java:14   SecurityFilterChain permits every request via .anyRequest().permitAll() with no authentication mechanism.
SPR-CONFIG-002   [MEDIUM] src/main/resources/application.properties:1  Hardcoded secret in configuration: jwt.token.
...
Checked 5 Java file(s), 1 config file(s) in 84 ms. Found 11 finding(s), 5 high, 5 medium, 1 low.
```

## Why sprig?

Most Spring security scanners only look at source annotations. But many of the
worst, most common Spring Boot vulnerabilities live in **configuration**:
Actuator exposed as `*`, hardcoded secrets, `allowed-origins: "*"` with
credentials, disabled cookie flags. `sprig` analyzes **both**, with rules that
understand Spring semantics — not regex.

- **Source-aware** — understands `@CrossOrigin`, `SecurityFilterChain`
  lambdas, `@PreAuthorize`/method security, `NoOpPasswordEncoder`, frame
  options.
- **Config-aware** — line-accurate `application.yml` / `application.properties`
  analysis, with every rule's property keys checked in CI against Spring Boot's
  own configuration metadata for Boot 2.0 through 3.5.
- **CI-friendly** — stable exit codes and SARIF 2.1.0 output for GitHub code
  scanning.
- **False positives are treated as bugs** — every rule ships an explicit
  false-positive rationale with a fixture behind it, and a rule that fires on
  something it cannot reach gets narrowed rather than documented around.
  SPR-CONFIG-001 lost its `shutdown` token that way. Default `--fail-on HIGH`.

## Getting started

Requires Java 17+.

```console
$ git clone https://github.com/vianbas/sprig.git
$ cd sprig
$ mvn -q package -DskipTests
$ java -jar target/sprig-0.1.0.jar scan /path/to/your-spring-boot-app
```

Or build a self-contained distribution:

```console
$ mvn package
$ target/sprig-0.1.0.jar scan . --output sarif --output-file sprig.sarif
```

## CLI reference

```
sprig scan [DIR]                 Scan a Spring Boot project
  -o, --output <console|json|sarif>   Report format (default: console)
  --output-file <FILE>                Write report to a file
  -f, --fail-on <severity>            Exit 1 when any finding ≥ this severity (default: HIGH)
  -i, --include-rule <ids>            Run only these rules
  -e, --exclude-rule <ids>            Disable these rules
  -c, --config <FILE>                 Rules config (default: ./sprig.yml)
  --exclude-path <globs>              Skip matching paths
  -q, --quiet                         Only print the summary
  -V, --verbose                       Print extra diagnostics

sprig list-rules                 List all detection rules
sprig version                    Print version
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0`  | No findings at or above `--fail-on` |
| `1`  | Findings at or above `--fail-on` |
| `2`  | Operational error (bad path, unreadable config, ...) |

### Rules

| ID | Severity | Target | Finding |
|----|----------|--------|---------|
| SPR-CORS-001 | HIGH | source | `@CrossOrigin` with wildcard (explicit or implicit-default) origins + `allowCredentials=true` |
| SPR-SRC-002 | HIGH | source | `NoOpPasswordEncoder` / `{noop}` plaintext passwords |
| SPR-SRC-003 | HIGH | source | `.anyRequest().permitAll()` without an auth mechanism |
| SPR-SRC-004 | MEDIUM | source | `@EnableWebSecurity` without `@EnableMethodSecurity` while `@PreAuthorize` is used |
| SPR-SRC-005 | MEDIUM | source | `frameOptions().disable()` (clickjacking) |
| SPR-CONFIG-001 | HIGH | config | Actuator `exposure.include` of `*` / `env` / `heapdump` |
| SPR-CONFIG-002 | MEDIUM | config | Hardcoded secrets (password/token/secret literals) |
| SPR-CONFIG-003 | MEDIUM | config | Cookie `http-only`/`secure` explicitly disabled |
| SPR-CONFIG-004 | HIGH | config | CORS wildcard + credentials on Actuator or GraphQL |
| SPR-CONFIG-005 | LOW | config | Spring Security logging at `DEBUG` / `TRACE` |
| SPR-CONFIG-006 | CRITICAL | config | Actuator `shutdown` / `heapdump` both exposed and opened by `access` or `enabled` |

Each rule has a doc with detection details and a false-positive rationale under
[`docs/rules/`](docs/rules/).

### Configuration (`sprig.yml`)

Drop a `sprig.yml` in the scanned project root (or pass `--config`):

```yaml
rules:
  SPR-CONFIG-002:
    enabled: true
    severity: critical
secret-allowlist:
  - dev-password
```

### Custom rules

`sprig.yml` can also define configuration rules of your own, for properties
sprig has no built-in rule for:

```yaml
custom-rules:
  - id: ACME-CONFIG-001
    severity: high
    description: Internal debug endpoints are switched on.
    remediation: Remove acme.debug.enabled from production configuration.
    property: acme.debug.enabled
    equals: "true"
```

Each rule reports one property key, in every configuration file where it
matches. Set exactly one of:

| Key | Reports the property when |
|---|---|
| `equals` | its value, trimmed, is exactly this string |
| `contains` | one of its comma-separated values, or YAML list items, is this string |
| `present: true` | it is set at all |

`id`, `severity`, `description` and `property` are required; `name` and
`remediation` are optional. Ids are upper-case letters and digits in
dash-separated parts, such as `ACME-CONFIG-001`, and the `SPR-` prefix is
reserved for built-in rules. A custom rule honours `--include-rule`,
`--exclude-rule` and the `rules:` overrides above like any other rule, and it
counts towards `--fail-on`. `sprig list-rules` shows built-in rules only.

Matching is limited to fixed strings on purpose. A `sprig.yml` in the scanned
project root is loaded automatically, so its rules run inside your CI, and a
regular expression would let that project make the scan as slow as it likes.
A malformed custom rule, including an unknown key such as `matches`, stops the
scan with exit code 2 instead of being skipped, so a typo cannot quietly turn a
rule off.

### CI with GitHub code scanning

```yaml
- name: Run sprig
  run: java -jar sprig.jar scan . --output sarif --output-file sprig.sarif
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: sprig.sarif
```

## Development

```console
$ mvn test                 # unit + golden + schema validation + e2e
$ mvn test -DupdateGoldens=true   # regenerate golden files after intentional output changes
$ java -jar target/sprig-0.1.0.jar scan src/test/resources/fixtures/demo-app
```

Build toolchain: JDK 21+ (bytecode targets Java 17), Maven.

## Roadmap (ideas)

- [Gradle / Maven plugin integration](https://github.com/vianbas/sprig/issues/27)
- [Custom YAML rules (declarative)](https://github.com/vianbas/sprig/issues/28)
- [Dependency / CVE awareness tied to findings](https://github.com/vianbas/sprig/issues/29)
- [GraalVM native-image binary and Homebrew tap](https://github.com/vianbas/sprig/issues/30)

## Support

`sprig` is developed in the open and maintained by [@vianbas](https://github.com/vianbas).
If sprig catches a real vulnerability in your pipeline or saves your team an
hour, consider becoming a [GitHub Sponsor](https://github.com/sponsors/vianbas) —
sponsorship directly funds maintenance, new rules, and the security review of
existing ones.

## License

MIT — see [LICENSE](LICENSE).
