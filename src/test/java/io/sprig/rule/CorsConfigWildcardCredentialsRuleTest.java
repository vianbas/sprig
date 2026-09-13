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
    void flagsWildcardOriginsWithCredentialsOnActuator() {
        List<Finding> findings = findingsFor("cors-config", rule);
        assertThat(findings).hasSize(1);
        Finding f = findings.get(0);
        assertThat(f.ruleId()).isEqualTo("SPR-CONFIG-004");
        assertThat(f.severity()).isEqualTo(Severity.HIGH);
        assertThat(f.message())
                .isEqualTo(
                        "management.endpoints.web.cors: allowed-origins=* combined with allow-credentials=true.");
        assertFindingAt(findings, "application.yml", 5);
    }

    @Test
    void flagsWildcardOriginsWithCredentialsOnGraphql() {
        List<Finding> findings = findingsFor("cors-config-graphql", rule);
        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).message()).contains("spring.graphql.cors");
        assertFindingAt(findings, "application.yml", 4);
    }

    @Test
    void doesNotFlagExplicitOrigins() {
        assertThat(findingsFor("secure-app", rule)).isEmpty();
    }

    @Test
    void doesNotPairOriginsAndCredentialsAcrossNamespaces() {
        assertThat(findingsFor("cors-config-cross-namespace", rule)).isEmpty();
    }

    @Test
    void flagsAnyHostOriginPatternWithCredentials() {
        List<Finding> findings = findingsFor("cors-config-pattern-credentials", rule);
        assertThat(findings).hasSize(1);
        Finding f = findings.get(0);
        assertThat(f.severity()).isEqualTo(Severity.HIGH);
        assertThat(f.message())
                .isEqualTo(
                        "management.endpoints.web.cors: allowed-origin-patterns=https://* combined with allow-credentials=true.");
        assertFindingAt(findings, "application.properties", 2);
    }

    @Test
    void doesNotFlagBoundedOriginPatternWithCredentials() {
        assertThat(findingsFor("cors-config-pattern-bounded", rule)).isEmpty();
    }

    @Test
    void leavesWildcardsWithoutCredentialsToSprConfig007() {
        assertThat(findingsFor("cors-config-wildcard-no-credentials", rule)).isEmpty();
        assertThat(findingsFor("cors-config-pattern-no-credentials", rule)).isEmpty();
    }
}
