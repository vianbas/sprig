package io.sprig.rule;

import static org.assertj.core.api.Assertions.assertThat;

import io.sprig.model.Finding;
import io.sprig.model.Severity;
import io.sprig.rule.rules.FrameOptionsDisabledRule;
import java.util.List;
import org.junit.jupiter.api.Test;

class FrameOptionsDisabledRuleTest extends RuleTestBase {

    private final FrameOptionsDisabledRule rule = new FrameOptionsDisabledRule();

    @Test
    void flagsFrameOptionsDisabledInLambdaStyle() {
        List<Finding> findings = findingsFor("frame-options", rule);
        assertThat(findings).hasSize(1);
        Finding f = findings.get(0);
        assertThat(f.ruleId()).isEqualTo("SPR-SRC-005");
        assertThat(f.severity()).isEqualTo(Severity.MEDIUM);
        assertFindingAt(findings, "SecurityConfig.java", 13);
    }

    @Test
    void doesNotFlagSecuredApp() {
        assertThat(findingsFor("secure-app", rule)).isEmpty();
    }
}
