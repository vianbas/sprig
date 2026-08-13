package io.sprig.rule;

import io.sprig.model.Finding;
import io.sprig.rule.rules.InsecureCookieFlagsRule;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class InsecureCookieFlagsRuleTest extends RuleTestBase {

    private final InsecureCookieFlagsRule rule = new InsecureCookieFlagsRule();

    @Test
    void flagsDisabledCookieFlags() {
        List<Finding> findings = findingsFor("cookie-flags", rule);
        assertThat(findings).hasSize(2);
        assertFindingAt(findings, "application.yml", 5); // http-only: false
        assertFindingAt(findings, "application.yml", 6); // secure: false
    }

    @Test
    void doesNotFlagEnabledCookieFlags() {
        assertThat(findingsFor("secure-app", rule)).isEmpty();
    }
}
