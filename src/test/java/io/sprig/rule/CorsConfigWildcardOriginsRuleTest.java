package io.sprig.rule;

import static org.assertj.core.api.Assertions.assertThat;

import io.sprig.model.Finding;
import io.sprig.model.Severity;
import io.sprig.rule.rules.CorsConfigWildcardOriginsRule;
import java.util.List;
import org.junit.jupiter.api.Test;

class CorsConfigWildcardOriginsRuleTest extends RuleTestBase {

    private final CorsConfigWildcardOriginsRule rule = new CorsConfigWildcardOriginsRule();

    @Test
    void flagsWildcardOriginsWithoutCredentialsOnBothNamespaces() {
        List<Finding> findings = findingsFor("cors-config-wildcard-no-credentials", rule);
        assertThat(findings).hasSize(2);
        assertThat(findings)
                .allSatisfy(
                        f -> {
                            assertThat(f.ruleId()).isEqualTo("SPR-CONFIG-007");
                            assertThat(f.severity()).isEqualTo(Severity.MEDIUM);
                        });
        assertThat(findings)
                .anySatisfy(
                        f -> {
                            assertThat(f.message())
                                    .isEqualTo(
                                            "management.endpoints.web.cors: allowed-origins=* lets any origin read responses cross-origin.");
                            assertThat(f.line()).isEqualTo(7);
                        });
        assertThat(findings)
                .anySatisfy(
                        f -> {
                            assertThat(f.message())
                                    .startsWith("spring.graphql.cors: allowed-origins=*");
                            assertThat(f.line()).isEqualTo(11);
                        });
    }

    @Test
    void flagsAnyHostOriginPatternWrittenAsList() {
        List<Finding> findings = findingsFor("cors-config-pattern-no-credentials", rule);
        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).message())
                .startsWith("management.endpoints.web.cors: allowed-origin-patterns=");
        assertFindingAt(findings, "application.yml", 8);
    }

    @Test
    void pairsCredentialsWithinTheNamespace() {
        // Actuator accepts every origin; only GraphQL sets allow-credentials=true.
        List<Finding> findings = findingsFor("cors-config-cross-namespace", rule);
        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).message()).startsWith("management.endpoints.web.cors");
        assertFindingAt(findings, "application.yml", 5);
    }

    @Test
    void leavesCredentialedWildcardsToSprConfig004() {
        assertThat(findingsFor("cors-config", rule)).isEmpty();
        assertThat(findingsFor("cors-config-graphql", rule)).isEmpty();
        assertThat(findingsFor("cors-config-pattern-credentials", rule)).isEmpty();
    }

    @Test
    void doesNotFlagConcreteOriginsOrBoundedPatterns() {
        assertThat(findingsFor("cors-config-concrete-no-credentials", rule)).isEmpty();
    }
}
