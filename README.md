# sprig

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
  analysis, with Boot 2 and Boot 3 property names handled.
- **CI-friendly** — stable exit codes and SARIF 2.1.0 output for GitHub code
  scanning.
- **Zero false-positive noise** — default `--fail-on HIGH`, and every rule
  ships an explicit false-positive rationale.

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
| SPR-CORS-001 | HIGH | source | `@CrossOrigin(origins="*")` + `allowCredentials=true` |
| SPR-SRC-002 | HIGH | source | `NoOpPasswordEncoder` / `{noop}` plaintext passwords |
| SPR-SRC-003 | HIGH | source | `.anyRequest().permitAll()` without an auth mechanism |
| SPR-SRC-004 | MEDIUM | source | `@EnableWebSecurity` without `@EnableMethodSecurity` while `@PreAuthorize` is used |
| SPR-SRC-005 | MEDIUM | source | `frameOptions().disable()` (clickjacking) |
| SPR-CONFIG-001 | HIGH | config | Actuator `exposure.include` of `*` / `env` / `heapdump` |
| SPR-CONFIG-002 | MEDIUM | config | Hardcoded secrets (password/token/secret literals) |
| SPR-CONFIG-003 | MEDIUM | config | Cookie `http-only`/`secure` explicitly disabled |
| SPR-CONFIG-004 | HIGH | config | CORS wildcard + credentials in config |
| SPR-CONFIG-005 | LOW | config | `spring.security.debug: true` |

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

- Gradle / Maven plugin integration
- Custom YAML rules (declarative)
- Dependency / CVE awareness tied to findings
- GraalVM native-image binary and Homebrew tap

## Support

`sprig` is developed in the open and maintained by [@vianbas](https://github.com/vianbas).
If sprig catches a real vulnerability in your pipeline or saves your team an
hour, consider becoming a [GitHub Sponsor](https://github.com/sponsors/vianbas) —
sponsorship directly funds maintenance, new rules, and the security review of
existing ones.

## License

MIT — see [LICENSE](LICENSE).
