package io.sprig.rule;

import static org.assertj.core.api.Assertions.assertThat;

import io.sprig.model.Finding;
import io.sprig.model.Severity;
import io.sprig.rule.rules.CorsConfigWildcardCredentialsRule;
import java.util.List;
import org.junit.jupiter.api.Test;

class CorsConfigWildcardCredentialsRuleTest extends RuleTestBase {

    private final CorsConfigWildcardCredentialsRule rule = new CorsConfigWildcardCredentialsRule();

    @Test
    void flagsWildcardOriginsWithCredentialsInConfig() {
        List<Finding> findings = findingsFor("cors-config", rule);
        assertThat(findings).hasSize(1);
        Finding f = findings.get(0);
        assertThat(f.ruleId()).isEqualTo("SPR-CONFIG-004");
        assertThat(f.severity()).isEqualTo(Severity.HIGH);
        assertFindingAt(findings, "application.yml", 4);
    }

    @Test
    void doesNotFlagExplicitOrigins() {
        assertThat(findingsFor("secure-app", rule)).isEmpty();
    }
}
