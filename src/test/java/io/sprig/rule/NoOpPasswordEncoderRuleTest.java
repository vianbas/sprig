package io.sprig.rule;

import static org.assertj.core.api.Assertions.assertThat;

import io.sprig.model.Finding;
import io.sprig.rule.rules.NoOpPasswordEncoderRule;
import java.util.List;
import org.junit.jupiter.api.Test;

class NoOpPasswordEncoderRuleTest extends RuleTestBase {

    private final NoOpPasswordEncoderRule rule = new NoOpPasswordEncoderRule();

    @Test
    void flagsNoOpPasswordEncoderAndNoopPasswords() {
        List<Finding> findings = findingsFor("noop-encoder", rule);
        assertThat(findings).hasSize(2);
        assertThat(findings).allMatch(f -> f.ruleId().equals("SPR-SRC-002"));
        assertThat(findings).anyMatch(f -> f.file().toString().endsWith("PasswordConfig.java"));
        assertThat(findings)
                .anyMatch(f -> f.file().toString().endsWith("UserDetailsServiceConfig.java"));
    }

    @Test
    void doesNotFlagBcrypt() {
        List<Finding> findings = findingsFor("secure-app", rule);
        assertThat(findings).isEmpty();
    }
}
