package io.sprig.rule;

import io.sprig.model.Finding;
import io.sprig.model.Severity;
import io.sprig.rule.rules.MissingMethodSecurityRule;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class MissingMethodSecurityRuleTest extends RuleTestBase {

    private final MissingMethodSecurityRule rule = new MissingMethodSecurityRule();

    @Test
    void flagsPreAuthorizeWithoutEnableMethodSecurity() {
        List<Finding> findings = findingsFor("missing-method-sec", rule);
        assertThat(findings).hasSize(1);
        Finding f = findings.get(0);
        assertThat(f.ruleId()).isEqualTo("SPR-SRC-004");
        assertThat(f.severity()).isEqualTo(Severity.MEDIUM);
        assertFindingAt(findings, "SecurityConfig.java", 13);
    }

    @Test
    void doesNotFlagSecuredApp() {
        assertThat(findingsFor("secure-app", rule)).isEmpty();
    }
}
