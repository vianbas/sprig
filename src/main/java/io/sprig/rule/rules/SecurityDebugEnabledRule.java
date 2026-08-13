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
 * SPR-CONFIG-005 — {@code spring.security.debug=true} enables verbose security logging that can
 * leak request/principal internals in production. Usually left on by accident.
 */
public final class SecurityDebugEnabledRule implements Rule {

    private static final String KEY = "spring.security.debug";

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
        return "spring.security.debug=true enables verbose security logging that can leak internals in production.";
    }

    @Override
    public String remediation() {
        return "Remove spring.security.debug or scope it to a dev-only profile.";
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

    @Override
    public boolean appliesTo(RuleContext ctx) {
        return ctx.config() != null && !ctx.config().isEmpty();
    }

    @Override
    public void analyze(RuleContext ctx, FindingCollector findings) {
        for (ConfigEntry entry : ctx.config().allEntries()) {
            if (KEY.equals(entry.key())
                    && entry.asString() != null
                    && entry.asString().trim().toLowerCase(Locale.ROOT).equals("true")) {
                findings.add(
                        this,
                        entry.source(),
                        entry.line(),
                        "spring.security.debug is enabled.",
                        entry.key());
            }
        }
    }
}
