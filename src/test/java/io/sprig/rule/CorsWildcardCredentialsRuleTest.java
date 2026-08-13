package io.sprig.rule;

import io.sprig.model.Finding;
import io.sprig.model.Severity;
import io.sprig.rule.rules.CorsWildcardCredentialsRule;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class CorsWildcardCredentialsRuleTest extends RuleTestBase {

    private final CorsWildcardCredentialsRule rule = new CorsWildcardCredentialsRule();

    @Test
    void flagsWildcardOriginsWithCredentials() {
        List<Finding> findings = findingsFor("cors-misconfig", rule);
        assertThat(findings).hasSize(1);
        Finding f = findings.get(0);
        assertThat(f.ruleId()).isEqualTo("SPR-CORS-001");
        assertThat(f.severity()).isEqualTo(Severity.HIGH);
        assertThat(f.file().toString()).endsWith("CorsController.java");
        assertThat(f.line()).isEqualTo(10);
    }

    @Test
    void doesNotFlagExplicitOriginAllowlist() {
        List<Finding> findings = findingsFor("secure-app", rule);
        assertThat(findings).isEmpty();
    }

    @Test
    void flagsMissingOriginsAttributeAsImplicitWildcard() {
        List<Finding> findings = findingsFor("cors-default-origin", rule);
        assertThat(findings).hasSize(1);
        Finding f = findings.get(0);
        assertThat(f.ruleId()).isEqualTo("SPR-CORS-001");
        assertThat(f.severity()).isEqualTo(Severity.HIGH);
        assertThat(f.file().toString()).endsWith("CorsController.java");
        assertThat(f.line()).isEqualTo(13);
    }

    @Test
    void doesNotFlagOriginPatternsWithoutOrigins() {
        List<Finding> findings = findingsFor("cors-origin-patterns", rule);
        assertThat(findings).isEmpty();
    }
}
