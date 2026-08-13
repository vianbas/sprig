package io.sprig.rule;

import io.sprig.model.FindingCollector;
import io.sprig.model.Severity;
import java.util.Set;

/**
 * A single detection rule. Implementations are small, focused and stateless. The interface is
 * deliberately minimal so external/declarative rules can be wrapped later without touching the
 * contract.
 */
public interface Rule {

    /** Stable rule id, a user-facing contract, e.g. {@code SPR-CORS-001}. */
    String id();

    /** Machine-friendly short name, e.g. {@code cors-wildcard-credentials}. */
    String name();

    /** One-sentence description of the misconfiguration. */
    String description();

    /** Fix guidance, emitted with every finding. */
    String remediation();

    /** Default severity. */
    Severity severity();

    /** Free-form tags, e.g. {@code cors}, {@code config}, {@code auth}. */
    default Set<String> tags() {
        return Set.of();
    }

    /** Whether the rule inspects source code, configuration, or both. */
    default RuleKind kind() {
        return RuleKind.HYBRID;
    }

    /** Whether the rule applies to the given scan context (e.g. needs Java sources). */
    default boolean appliesTo(RuleContext ctx) {
        return true;
    }

    /**
     * Returns a rule instance configured with project settings, or {@code this} when the rule has
     * nothing to configure.
     */
    default Rule configure(RulesConfig config) {
        return this;
    }

    /** Run the rule against the scan context, adding findings to the collector. */
    void analyze(RuleContext ctx, FindingCollector findings);
}
