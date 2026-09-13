package io.sprig.rule;

import static org.assertj.core.api.Assertions.assertThat;

import io.sprig.model.Finding;
import io.sprig.model.Severity;
import io.sprig.rule.rules.PermitAllRequestMatcherRule;
import java.util.List;
import org.junit.jupiter.api.Test;

class PermitAllRequestMatcherRuleTest extends RuleTestBase {

    private final PermitAllRequestMatcherRule rule = new PermitAllRequestMatcherRule();

    @Test
    void flagsAnyRequestPermitAllWithoutAuthMechanism() {
        List<Finding> findings = findingsFor("permit-all-chain", rule);
        assertThat(findings).hasSize(1);
        Finding f = findings.get(0);
        assertThat(f.ruleId()).isEqualTo("SPR-SRC-003");
        assertThat(f.severity()).isEqualTo(Severity.HIGH);
        assertThat(f.message()).startsWith("SecurityFilterChain permits every request");
        assertFindingAt(findings, "SecurityConfig.java", 13);
    }

    @Test
    void doesNotFlagAuthenticatedChains() {
        assertThat(findingsFor("missing-method-sec", rule)).isEmpty();
    }

    @Test
    void doesNotFlagSecuredApp() {
        assertThat(findingsFor("secure-app", rule)).isEmpty();
    }

    @Test
    void flagsAnyExchangePermitAllInWebFluxChain() {
        List<Finding> findings = findingsFor("webflux-permit-all", rule);
        assertThat(findings).hasSize(1);
        Finding f = findings.get(0);
        assertThat(f.ruleId()).isEqualTo("SPR-SRC-003");
        assertThat(f.severity()).isEqualTo(Severity.HIGH);
        assertThat(f.message()).startsWith("SecurityWebFilterChain permits every exchange");
        assertFindingAt(findings, "SecurityConfig.java", 13);
    }

    @Test
    void doesNotFlagAuthenticatedWebFluxChains() {
        assertThat(findingsFor("webflux-method-sec", rule)).isEmpty();
        assertThat(findingsFor("webflux-secure", rule)).isEmpty();
    }
}
