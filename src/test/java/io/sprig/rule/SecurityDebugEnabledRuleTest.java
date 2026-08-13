package io.sprig.rule;

import static org.assertj.core.api.Assertions.assertThat;

import io.sprig.model.Finding;
import io.sprig.model.Severity;
import io.sprig.rule.rules.SecurityDebugEnabledRule;
import java.util.List;
import org.junit.jupiter.api.Test;

class SecurityDebugEnabledRuleTest extends RuleTestBase {

    private final SecurityDebugEnabledRule rule = new SecurityDebugEnabledRule();

    @Test
    void flagsSecurityDebugEnabled() {
        List<Finding> findings = findingsFor("security-debug", rule);
        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).severity()).isEqualTo(Severity.LOW);
        assertFindingAt(findings, "application.yml", 3);
    }

    @Test
    void doesNotFlagWithoutDebug() {
        assertThat(findingsFor("secure-app", rule)).isEmpty();
    }
}
