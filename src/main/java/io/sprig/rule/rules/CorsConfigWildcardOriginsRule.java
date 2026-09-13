package io.sprig.rule.rules;

import io.sprig.model.FindingCollector;
import io.sprig.model.Severity;
import io.sprig.rule.Rule;
import io.sprig.rule.RuleContext;
import io.sprig.rule.RuleKind;
import io.sprig.scan.ConfigEntry;
import java.nio.file.Path;
import java.util.Map;
import java.util.Set;

/**
 * SPR-CONFIG-007 — CORS configuration that accepts every origin while {@code allow-credentials} is
 * not {@code true}, on Actuator's {@code management.endpoints.web.cors.*} or GraphQL's {@code
 * spring.graphql.cors.*}. Any page can read those responses from a visitor's browser, for requests
 * made without the visitor's cookies.
 *
 * <p>The credentialed variant is SPR-CONFIG-004. Both rules read {@link CorsConfigNamespaces}, so a
 * namespace is reported by at most one of them (#41).
 */
public final class CorsConfigWildcardOriginsRule implements Rule {

    @Override
    public String id() {
        return "SPR-CONFIG-007";
    }

    @Override
    public String name() {
        return "cors-config-wildcard-origins";
    }

    @Override
    public String description() {
        return "CORS configured to accept every origin in application configuration, without credentials: any page can read the responses.";
    }

    @Override
    public String remediation() {
        return "List the origins that need cross-origin access in allowed-origins, or remove the CORS properties if nothing needs it.";
    }

    @Override
    public Severity severity() {
        return Severity.MEDIUM;
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
    public Set<String> configKeys() {
        return CorsConfigNamespaces.CONFIG_KEYS;
    }

    @Override
    public boolean appliesTo(RuleContext ctx) {
        return ctx.config() != null && !ctx.config().isEmpty();
    }

    @Override
    public void analyze(RuleContext ctx, FindingCollector findings) {
        for (Path file : ctx.config().files()) {
            Map<String, ConfigEntry> entries = ctx.config().entriesFor(file);
            for (String prefix : CorsConfigNamespaces.PREFIXES) {
                ConfigEntry open = CorsConfigNamespaces.anyOriginEntry(entries, prefix);
                if (open == null || CorsConfigNamespaces.credentialsAllowed(entries, prefix)) {
                    continue;
                }
                findings.add(
                        this,
                        open.source(),
                        open.line(),
                        prefix
                                + ": "
                                + CorsConfigNamespaces.shortName(open, prefix)
                                + "="
                                + open.asString()
                                + " lets any origin read responses cross-origin.",
                        open.key());
            }
        }
    }
}
