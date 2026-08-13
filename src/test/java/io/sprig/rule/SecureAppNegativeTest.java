package io.sprig.rule;

import static org.assertj.core.api.Assertions.assertThat;

import io.sprig.model.ScanOptions;
import io.sprig.model.ScanResult;
import io.sprig.scan.ScanEngine;
import org.junit.jupiter.api.Test;

/**
 * False-positive regression gate: a correctly-configured Spring app must produce zero findings
 * under the full rule set.
 */
class SecureAppNegativeTest extends RuleTestBase {

    @Test
    void correctlyConfiguredAppYieldsNoFindings() {
        ScanResult result =
                new ScanEngine().scan(fixturesDir().resolve("secure-app"), ScanOptions.defaults());
        assertThat(result.findings()).isEmpty();
    }
}
