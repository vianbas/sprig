# Contributing to sprig

## Workflow

1. **Open an issue before writing code**, using one of the templates:
   `bug`, `false-positive`, `false-negative`, `new-rule`, or `enhancement`.
   An issue exists so the *why* is agreed on before the *how* — this
   especially matters for rules, where the false-positive/false-negative
   tradeoff is a design decision, not just an implementation detail.
2. Branch off `main`: `type/short-description`, e.g. `fix/cors-implicit-wildcard`,
   `feat/actuator-shutdown-port-check`, `docs/rule-doc-typo`.
3. Make the change with tests. See [Testing](#testing) below.
4. Open a PR against `main` using the PR template, and link the issue with
   `Closes #N`. Direct pushes to `main` are blocked — every change lands
   through a PR.
5. CI must pass (`mvn verify`, plus the self-scan smoke check) before merge.
6. PRs merge via **squash only** — `main` requires linear history, so merge
   commits and rebase merges are disabled at the repo level. Any open review
   conversations must be resolved first. Commits don't need to be GPG/SSH
   signed to contribute.

## What to expect from review

`sprig` is maintained solo, alongside a day job — so there's no guaranteed
SLA. In practice, first feedback on a PR usually lands within a week, and
follow-ups similarly. If it's been quiet longer than that, a comment nudging
the PR is always welcome.

## Testing

- `mvn test` — unit + rule-fixture + reporter golden tests.
- New rule logic needs a fixture under `src/test/resources/fixtures/<name>/`
  plus a test in `src/test/java/io/sprig/rule/` asserting the exact
  file/line/severity, and — just as important — a fixture proving the rule
  does *not* fire on a safe variant of the same pattern (see
  `secure-app` for examples). A rule without a documented false-positive
  rationale in `docs/rules/<ID>.md` is incomplete.
- Reporter changes that affect output shape need `-DupdateGoldens=true`
  regenerated goldens, committed alongside the change and reviewed as a diff.

## Rule design

Before adding a rule, work through:

- **Detection**: what AST/config shape triggers it? Check both the
  Boot 2 and Boot 3 property names/annotations where they differ.
  [SPR-CORS-001](docs/rules/SPR-CORS-001.md) is a good reference — it
  documents both the explicit `origins="*"` case and Spring's *implicit*
  all-origins default when `origins` is unset.
- **Property keys**: a CONFIG rule must return the keys it matches from
  `Rule.configKeys()`. `ConfigKeyMetadataTest` checks them against Spring
  Boot's own configuration metadata, because Spring ignores unknown properties
  silently and a rule keyed on a property that does not exist can never fire.
  Verify the key against the Boot reference documentation before writing the
  rule, not against what looks plausible. Two rules shipped with invented keys
  before this check existed.
- **False positives**: what looks similar but is safe? Add a fixture for it.
- **Severity**: HIGH/CRITICAL only for directly exploitable misconfigurations;
  MEDIUM/LOW for defense-in-depth or informational findings.

## Local setup

Requires JDK 21+ (bytecode targets Java 17) and Maven.

```console
$ mvn -q package -DskipTests
$ java -jar target/sprig-0.1.0.jar scan src/test/resources/fixtures/demo-app
```

Code is formatted with [Spotless](https://github.com/diffplug/spotless) (google-java-format,
AOSP style) and `mvn verify` fails on unformatted code. Run `mvn spotless:apply` before
committing, or `mvn spotless:check` to just see what's wrong.

## Security

Found a way sprig itself could be exploited (e.g. via a malicious scanned
project or a malicious `sprig.yml`)? See [SECURITY.md](SECURITY.md) — please
don't open a public issue for that.
