package io.sprig.rule;

import static org.assertj.core.api.Assertions.assertThat;

import io.sprig.model.Finding;
import io.sprig.model.ScanOptions;
import io.sprig.model.ScanResult;
import io.sprig.scan.ScanEngine;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;

/** Shared helpers for per-rule tests against fixture projects. */
public abstract class RuleTestBase {

    protected static ScanResult scanFixture(String fixture, Rule rule) {
        Path dir = fixturesDir().resolve(fixture);
        ScanOptions options =
                new ScanOptions(Set.of(rule.id()), Set.of(), null, List.of(), false, false);
        return new ScanEngine().scan(dir, options, RuleRegistry.of(List.of(rule)));
    }

    protected static Path fixturesDir() {
        return Path.of("src", "test", "resources", "fixtures").toAbsolutePath();
    }

    protected static List<Finding> findingsFor(String fixture, Rule rule) {
        return scanFixture(fixture, rule).findings();
    }

    protected static void assertFindingAt(List<Finding> findings, String fileSuffix, int line) {
        assertThat(findings)
                .anySatisfy(
                        f -> {
                            assertThat(f.file().toString()).endsWith(fileSuffix);
                            assertThat(f.line()).isEqualTo(line);
                        });
    }
}
