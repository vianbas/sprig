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
 * SPR-CONFIG-003 — the session cookie's {@code http-only} or {@code secure} flag is explicitly
 * disabled. Without httpOnly, JavaScript can read the session cookie (XSS → session theft); without
 * secure, it is sent over plain HTTP.
 */
public final class InsecureCookieFlagsRule implements Rule {

    private static final String HTTP_ONLY = "server.servlet.session.cookie.http-only";
    private static final String SECURE = "server.servlet.session.cookie.secure";

    @Override
    public String id() {
        return "SPR-CONFIG-003";
    }

    @Override
    public String name() {
        return "insecure-cookie-flags";
    }

    @Override
    public String description() {
        return "Session cookie flags http-only or secure are explicitly disabled.";
    }

    @Override
    public String remediation() {
        return "Set server.servlet.session.cookie.http-only=true and server.servlet.session.cookie.secure=true (secure especially over HTTPS).";
    }

    @Override
    public Severity severity() {
        return Severity.MEDIUM;
    }

    @Override
    public Set<String> tags() {
        return Set.of("cookies", "session", "config");
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
            boolean disabled =
                    entry.asString() != null
                            && entry.asString().trim().toLowerCase(Locale.ROOT).equals("false");
            if (!disabled) {
                continue;
            }
            if (HTTP_ONLY.equals(entry.key())) {
                findings.add(
                        this,
                        entry.source(),
                        entry.line(),
                        "Session cookie httpOnly flag is disabled.",
                        entry.key());
            } else if (SECURE.equals(entry.key())) {
                findings.add(
                        this,
                        entry.source(),
                        entry.line(),
                        "Session cookie secure flag is disabled.",
                        entry.key());
            }
        }
    }
}
