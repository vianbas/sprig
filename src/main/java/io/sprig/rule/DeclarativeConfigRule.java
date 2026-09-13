package io.sprig.rule;

import io.sprig.model.FindingCollector;
import io.sprig.model.Severity;
import io.sprig.scan.ConfigEntry;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Set;

/**
 * A configuration rule defined in {@code sprig.yml} instead of compiled in (#28). It reports one
 * property key in every configuration file where the value matches.
 *
 * <p>Matching is limited to fixed strings: an exact value, one comma-separated token, or the key
 * being present. There is no regular expression, because a {@code sprig.yml} in the scanned
 * project's root is loaded automatically, and a pattern supplied by the scanned project would run
 * inside the scanner.
 */
public final class DeclarativeConfigRule implements Rule {

    /** How the property value is compared. */
    public enum Match {
        /** The trimmed value is exactly the expected string. */
        EQUALS,
        /** One of the comma-separated values, or YAML list items, is the expected string. */
        CONTAINS,
        /** The property is set, whatever its value. */
        PRESENT
    }

    private final String id;
    private final String name;
    private final Severity severity;
    private final String description;
    private final String remediation;
    private final String property;
    private final Match match;
    private final String expected;

    DeclarativeConfigRule(
            String id,
            String name,
            Severity severity,
            String description,
            String remediation,
            String property,
            Match match,
            String expected) {
        this.id = id;
        this.name = name;
        this.severity = severity;
        this.description = description;
        this.remediation = remediation;
        this.property = property;
        this.match = match;
        this.expected = expected;
    }

    @Override
    public String id() {
        return id;
    }

    @Override
    public String name() {
        return name;
    }

    @Override
    public String description() {
        return description;
    }

    @Override
    public String remediation() {
        return remediation;
    }

    @Override
    public Severity severity() {
        return severity;
    }

    @Override
    public Set<String> tags() {
        return Set.of("custom", "config");
    }

    @Override
    public RuleKind kind() {
        return RuleKind.CONFIG;
    }

    @Override
    public Set<String> configKeys() {
        return Set.of(property);
    }

    /** Custom rules have no page under sprig's {@code docs/rules/}. */
    @Override
    public String helpUri() {
        return null;
    }

    @Override
    public boolean appliesTo(RuleContext ctx) {
        return ctx.config() != null && !ctx.config().isEmpty();
    }

    @Override
    public void analyze(RuleContext ctx, FindingCollector findings) {
        for (Path file : ctx.config().files()) {
            ConfigEntry entry = ctx.config().entriesFor(file).get(property);
            if (entry == null || !matches(entry.asString())) {
                continue;
            }
            String message =
                    match == Match.PRESENT
                            ? property + " is set: " + description
                            : property + "=" + entry.asString() + ": " + description;
            findings.add(this, entry.source(), entry.line(), message, property);
        }
    }

    private boolean matches(String value) {
        String actual = value == null ? "" : value.trim();
        return switch (match) {
            case EQUALS -> actual.equals(expected);
            case CONTAINS ->
                    Arrays.stream(actual.split(",")).map(String::trim).anyMatch(expected::equals);
            case PRESENT -> true;
        };
    }
}
