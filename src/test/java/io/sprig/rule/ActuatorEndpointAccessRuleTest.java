package io.sprig.rule;

import static org.assertj.core.api.Assertions.assertThat;

import io.sprig.model.Finding;
import io.sprig.model.Severity;
import io.sprig.rule.rules.ActuatorEndpointAccessRule;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Each case here mirrors a request measured against a running Boot app. The fixture comments name
 * the version and the status codes, so a change in behaviour is a change to both.
 */
class ActuatorEndpointAccessRuleTest extends RuleTestBase {

    private final ActuatorEndpointAccessRule rule = new ActuatorEndpointAccessRule();

    @Test
    void flagsBothEndpointsWhenExposedAndOpened() {
        List<Finding> findings = findingsFor("actuator-access-open", rule);
        assertThat(findings).hasSize(2);
        assertThat(findings)
                .allSatisfy(
                        f -> {
                            assertThat(f.ruleId()).isEqualTo("SPR-CONFIG-006");
                            assertThat(f.severity()).isEqualTo(Severity.CRITICAL);
                        });
        assertThat(findings)
                .extracting(Finding::propertyPath)
                .containsExactlyInAnyOrder(
                        "management.endpoint.shutdown.access",
                        "management.endpoint.heapdump.access");
        assertFindingAt(findings, "application.yml", 8);
        assertFindingAt(findings, "application.yml", 10);
    }

    /** Read-only is enough for a GET endpoint, and never enough for a POST one. */
    @Test
    void readOnlyOpensHeapdumpButNotShutdown() {
        List<Finding> findings = findingsFor("actuator-access-capped", rule);
        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).propertyPath()).isEqualTo("management.endpoint.heapdump.access");
        assertThat(findings.get(0).message()).contains("dump of process memory");
    }

    /** A blanket default opens what is gated; an explicit per-endpoint setting overrides it. */
    @Test
    void blanketDefaultFiresAndPerEndpointAccessNoneDoesNot() {
        List<Finding> findings = findingsFor("actuator-access-blanket", rule);
        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).propertyPath()).isEqualTo("management.endpoints.access.default");
        assertThat(findings.get(0).message()).contains("heapdump");
    }

    /** The gate is open and the endpoint is not exposed, which reaches nothing. */
    @Test
    void doesNotFlagAccessWithoutExposure() {
        assertThat(findingsFor("actuator-access-not-exposed", rule)).isEmpty();
    }

    @Test
    void doesNotFlagWildcardExposureOnItsOwn() {
        assertThat(findingsFor("actuator-exposed", rule)).isEmpty();
    }

    @Test
    void doesNotFlagSafeConfiguration() {
        assertThat(findingsFor("secure-app", rule)).isEmpty();
    }
}
