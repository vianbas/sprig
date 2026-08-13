package io.sprig.rule.rules;

import io.sprig.model.FindingCollector;
import io.sprig.model.Severity;
import io.sprig.rule.Rule;
import io.sprig.rule.RuleContext;
import io.sprig.rule.RuleKind;
import io.sprig.rule.RulesConfig;
import io.sprig.scan.ConfigEntry;

import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;

/**
 * SPR-CONFIG-002 — a credential-like property (password, secret, token, ...)
 * is set to a literal value rather than a {@code ${...}} reference. Literal
 * secrets end up in version control and leak in logs/backups.
 */
public final class HardcodedSecretRule implements Rule {

    private static final Set<String> SENSITIVE_SEGMENTS = Set.of(
            "password", "passwd", "secret", "token", "apikey", "api-key",
            "access-key", "accesskey", "private-key", "privatekey",
            "client-secret", "clientsecret", "credential");

    private final Set<String> allowlist;

    public HardcodedSecretRule() {
        this(Set.of());
    }

    /** Exact values that must never be flagged (wired from the sprig config allowlist). */
    public HardcodedSecretRule(Set<String> allowlist) {
        this.allowlist = Set.copyOf(allowlist);
    }

    @Override
    public String id() {
        return "SPR-CONFIG-002";
    }

    @Override
    public String name() {
        return "hardcoded-secret";
    }

    @Override
    public String description() {
        return "A credential-like property is set to a literal value in configuration.";
    }

    @Override
    public String remediation() {
        return "Move secrets to environment variables or a secret manager and reference them with ${...} placeholders.";
    }

    @Override
    public Severity severity() {
        return Severity.MEDIUM;
    }

    @Override
    public Set<String> tags() {
        return Set.of("secrets", "config");
    }

    @Override
    public RuleKind kind() {
        return RuleKind.CONFIG;
    }

    @Override
    public Rule configure(RulesConfig config) {
        Set<String> merged = new LinkedHashSet<>(allowlist);
        merged.addAll(config.secretAllowlist());
        return new HardcodedSecretRule(merged);
    }

    @Override
    public boolean appliesTo(RuleContext ctx) {
        return ctx.config() != null && !ctx.config().isEmpty();
    }

    @Override
    public void analyze(RuleContext ctx, FindingCollector findings) {
        for (ConfigEntry entry : ctx.config().allEntries()) {
            if (looksLikeSecretKey(entry.key()) && isLiteral(entry) && !allowlist.contains(entry.asString())) {
                findings.add(this, entry.source(), entry.line(),
                        "Hardcoded secret in configuration: " + entry.key() + ".", entry.key());
            }
        }
    }

    private static boolean looksLikeSecretKey(String key) {
        for (String segment : key.split("\\.")) {
            if (SENSITIVE_SEGMENTS.contains(segment.toLowerCase(Locale.ROOT))) {
                return true;
            }
        }
        return false;
    }

    private static boolean isLiteral(ConfigEntry entry) {
        String value = entry.asString();
        return value != null && !value.isBlank() && !entry.isPlaceholder() && !entry.isEnvRef();
    }
}
