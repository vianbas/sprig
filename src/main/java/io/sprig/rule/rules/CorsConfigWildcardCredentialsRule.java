package io.sprig.rule.rules;

import io.sprig.model.FindingCollector;
import io.sprig.model.Severity;
import io.sprig.rule.Rule;
import io.sprig.rule.RuleContext;
import io.sprig.rule.RuleKind;
import io.sprig.scan.ConfigEntry;

import java.nio.file.Path;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * SPR-CONFIG-004 — CORS configured via {@code spring.web.cors.*} (Boot 3) or
 * {@code spring.mvc.cors.*} (Boot 2) with wildcard allowed-origins combined
 * with allow-credentials=true.
 */
public final class CorsConfigWildcardCredentialsRule implements Rule {

    private static final List<String> ORIGINS_KEYS = List.of(
            "spring.web.cors.allowed-origins",
            "spring.mvc.cors.allowed-origins");

    private static final List<String> CREDENTIALS_KEYS = List.of(
            "spring.web.cors.allow-credentials",
            "spring.mvc.cors.allow-credentials");

    @Override
    public String id() {
        return "SPR-CONFIG-004";
    }

    @Override
    public String name() {
        return "cors-config-wildcard-credentials";
    }

    @Override
    public String description() {
        return "CORS configured with allowed-origins=* and allow-credentials=true in application configuration.";
    }

    @Override
    public String remediation() {
        return "Set allowed-origins to an explicit allowlist when allow-credentials=true; never combine '*' with credentials.";
    }

    @Override
    public Severity severity() {
        return Severity.HIGH;
    }

    @Override
    public Set<String> tags() {
        return Set.of("cors", "config");
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
        for (Path file : ctx.config().files()) {
            Map<String, ConfigEntry> entries = ctx.config().entriesFor(file);
            ConfigEntry origins = firstPresent(entries, ORIGINS_KEYS);
            ConfigEntry credentials = firstPresent(entries, CREDENTIALS_KEYS);
            if (origins == null || credentials == null) {
                continue;
            }
            if (containsWildcard(origins.asString()) && isTrue(credentials.asString())) {
                findings.add(this, origins.source(), origins.line(),
                        "CORS allowed-origins=* combined with allow-credentials=true.", origins.key());
            }
        }
    }

    private static ConfigEntry firstPresent(Map<String, ConfigEntry> entries, List<String> keys) {
        for (String key : keys) {
            ConfigEntry entry = entries.get(key);
            if (entry != null) {
                return entry;
            }
        }
        return null;
    }

    private static boolean containsWildcard(String value) {
        if (value == null) {
            return false;
        }
        for (String token : value.split(",")) {
            if ("*".equals(token.trim())) {
                return true;
            }
        }
        return false;
    }

    private static boolean isTrue(String value) {
        return value != null && value.trim().toLowerCase(Locale.ROOT).equals("true");
    }
}
