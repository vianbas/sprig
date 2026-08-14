package io.sprig.rule.rules;

import io.sprig.model.FindingCollector;
import io.sprig.model.Severity;
import io.sprig.rule.Rule;
import io.sprig.rule.RuleContext;
import io.sprig.rule.RuleKind;
import io.sprig.scan.ConfigEntry;
import java.util.Locale;
import java.util.Set;

/**
 * SPR-CONFIG-005 — Spring Security's loggers are turned up to DEBUG or TRACE, which prints the
 * filter chain and per-request authentication details into production logs. Usually left on by
 * accident after local debugging.
 *
 * <p>This rule previously matched {@code spring.security.debug}, which Spring does not read (#40).
 * Verbose security logging is configured through the logger level instead; the annotation
 * equivalent, {@code @EnableWebSecurity(debug = true)}, is not covered here.
 */
public final class SecurityDebugEnabledRule implements Rule {

    /**
     * Matched exactly and as a prefix, so a narrower logger such as {@code
     * logging.level.org.springframework.security.web} is caught too.
     */
    private static final String KEY = "logging.level.org.springframework.security";

    private static final Set<String> VERBOSE = Set.of("debug", "trace");

    @Override
    public String id() {
        return "SPR-CONFIG-005";
    }

    @Override
    public String name() {
        return "security-debug-enabled";
    }

    @Override
    public String description() {
        return "Spring Security logging is set to DEBUG or TRACE, which can leak request and principal internals in production.";
    }

    @Override
    public String remediation() {
        return "Raise the level to INFO or above, or scope the DEBUG level to a dev-only profile.";
    }

    @Override
    public Severity severity() {
        return Severity.LOW;
    }

    @Override
    public Set<String> tags() {
        return Set.of("logging", "config");
    }

    @Override
    public RuleKind kind() {
        return RuleKind.CONFIG;
    }

    /**
     * The base logger. The rule also matches loggers nested under it, which cannot be enumerated
     * because the logger name is arbitrary.
     */
    @Override
    public Set<String> configKeys() {
        return Set.of(KEY);
    }

    @Override
    public boolean appliesTo(RuleContext ctx) {
        return ctx.config() != null && !ctx.config().isEmpty();
    }

    @Override
    public void analyze(RuleContext ctx, FindingCollector findings) {
        for (ConfigEntry entry : ctx.config().allEntries()) {
            if (!isSecurityLogger(entry.key()) || entry.asString() == null) {
                continue;
            }
            String level = entry.asString().trim().toLowerCase(Locale.ROOT);
            if (VERBOSE.contains(level)) {
                findings.add(
                        this,
                        entry.source(),
                        entry.line(),
                        entry.key() + " is set to " + entry.asString().trim() + ".",
                        entry.key());
            }
        }
    }

    private static boolean isSecurityLogger(String key) {
        return key != null && (key.equals(KEY) || key.startsWith(KEY + "."));
    }
}
