package io.sprig.rule;

import static org.assertj.core.api.Assertions.assertThat;

import io.sprig.model.Finding;
import io.sprig.rule.rules.InsecureCookieFlagsRule;
import java.util.List;
import org.junit.jupiter.api.Test;

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
