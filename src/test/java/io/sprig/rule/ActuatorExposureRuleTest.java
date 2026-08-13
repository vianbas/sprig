package io.sprig.rule;

import static org.assertj.core.api.Assertions.assertThat;

import io.sprig.model.Finding;
import io.sprig.rule.rules.ActuatorExposureRule;
import java.util.List;
import org.junit.jupiter.api.Test;

class ActuatorExposureRuleTest extends RuleTestBase {

    private final ActuatorExposureRule rule = new ActuatorExposureRule();

    @Test
    void flagsWildcardExposure() {
        List<Finding> findings = findingsFor("actuator-exposed", rule);
        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).ruleId()).isEqualTo("SPR-CONFIG-001");
        assertThat(findings.get(0).severity()).isEqualTo(io.sprig.model.Severity.HIGH);
        assertFindingAt(findings, "application.yml", 5);
    }

    @Test
    void doesNotFlagSafeExposure() {
        assertThat(findingsFor("secure-app", rule)).isEmpty();
    }
}
