package io.sprig.rule;

import static org.assertj.core.api.Assertions.assertThat;

import io.sprig.model.Finding;
import io.sprig.rule.rules.HardcodedSecretRule;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

class HardcodedSecretRuleTest extends RuleTestBase {

    private final HardcodedSecretRule rule = new HardcodedSecretRule();

    @Test
    void flagsHardcodedSecretsInYamlAndProperties() {
        List<Finding> findings = findingsFor("hardcoded-secrets", rule);
        assertThat(findings).hasSize(2);
        assertFindingAt(findings, "application.yml", 4);
        assertFindingAt(findings, "application.properties", 1);
    }

    @Test
    void doesNotFlagPlaceholdersOrMissingKeys() {
        assertThat(findingsFor("secure-app", rule)).isEmpty();
    }

    @Test
    void respectsAllowlist() {
        HardcodedSecretRule withAllowlist = new HardcodedSecretRule(Set.of("dev-token-12345"));
        assertThat(findingsFor("hardcoded-secrets", withAllowlist)).hasSize(1);
    }
}
