package io.sprig.rule;

import static org.assertj.core.api.Assertions.assertThat;

import io.sprig.model.ScanOptions;
import io.sprig.model.ScanResult;
import io.sprig.scan.ScanEngine;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

/**
 * Integration check: the intentionally-vulnerable demo app triggers every rule across source and
 * configuration.
 */
class DemoAppIntegrationTest extends RuleTestBase {

    @Test
    void demoAppTriggersEveryRule() {
        ScanResult result =
                new ScanEngine().scan(fixturesDir().resolve("demo-app"), ScanOptions.defaults());
        Set<String> ruleIds =
                result.findings().stream().map(f -> f.ruleId()).collect(Collectors.toSet());
        assertThat(ruleIds)
                .containsExactlyInAnyOrder(
                        "SPR-CONFIG-001",
                        "SPR-CONFIG-002",
                        "SPR-CONFIG-003",
                        "SPR-CONFIG-004",
                        "SPR-CONFIG-005",
                        "SPR-CORS-001",
                        "SPR-SRC-002",
                        "SPR-SRC-003",
                        "SPR-SRC-004",
                        "SPR-SRC-005");
    }
}
