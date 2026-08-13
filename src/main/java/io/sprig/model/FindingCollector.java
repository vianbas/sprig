package io.sprig.model;

import io.sprig.rule.Rule;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * Mutable accumulator handed to rules. Severity is always read from the rule so that a
 * severity-overriding decorator flows through to every finding.
 */
public final class FindingCollector {

    private static final Comparator<Finding> BY_LOCATION =
            Comparator.comparing((Finding f) -> f.file().toString())
                    .thenComparingInt(Finding::line)
                    .thenComparing(Finding::ruleId);

    private final List<Finding> findings = new ArrayList<>();

    public void add(Rule rule, Path file, int line, String message) {
        add(rule, file, line, 0, message, "");
    }

    public void add(Rule rule, Path file, int line, String message, String propertyPath) {
        add(rule, file, line, 0, message, propertyPath);
    }

    public void add(
            Rule rule, Path file, int line, int column, String message, String propertyPath) {
        findings.add(
                new Finding(
                        rule.id(),
                        rule.severity(),
                        message,
                        rule.remediation(),
                        file,
                        line,
                        column,
                        propertyPath));
    }

    /** Returns all findings sorted deterministically by (file, line, ruleId). */
    public List<Finding> all() {
        List<Finding> sorted = new ArrayList<>(findings);
        sorted.sort(BY_LOCATION);
        return List.copyOf(sorted);
    }
}
