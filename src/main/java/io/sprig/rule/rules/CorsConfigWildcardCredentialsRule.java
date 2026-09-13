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
 * SPR-CONFIG-004 — CORS configured to accept every origin together with allow-credentials=true, on
 * one of the two surfaces Spring Boot exposes as plain configuration properties: Actuator's {@code
 * management.endpoints.web.cors.*} and GraphQL's {@code spring.graphql.cors.*}.
 *
 * <p>"Every origin" is {@code allowed-origins} containing {@code *}, or {@code
 * allowed-origin-patterns} containing a pattern with a bare {@code *} host. On Boot 3.5.16 the
 * first stopped Actuator from starting and failed GraphQL requests with a 500, while the second
 * echoed an unrelated origin back with {@code Access-Control-Allow-Credentials: true} (#41). The
 * same condition without credentials is SPR-CONFIG-007.
 *
 * <p>Spring MVC's own CORS has no property namespace at all; it is configured in Java, which is
 * SPR-CORS-001's territory. This rule previously matched {@code spring.web.cors.*} and {@code
 * spring.mvc.cors.*}, neither of which Spring has ever declared, so it could not fire on a real
 * project (#39).
 */
public final class CorsConfigWildcardCredentialsRule implements Rule {

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
        return "CORS configured with allowed-origins=*, or an allowed-origin-patterns entry whose host is *, and allow-credentials=true in application configuration.";
    }

    @Override
    public String remediation() {
        return "List the permitted origins explicitly when allow-credentials=true; never combine '*' or an any-host origin pattern such as https://* with credentials.";
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
                if (open == null || !CorsConfigNamespaces.credentialsAllowed(entries, prefix)) {
                    continue;
                }
                String name = CorsConfigNamespaces.shortName(open, prefix);
                String value = "allowed-origins".equals(name) ? "*" : open.asString();
                findings.add(
                        this,
                        open.source(),
                        open.line(),
                        prefix
                                + ": "
                                + name
                                + "="
                                + value
                                + " combined with allow-credentials=true.",
                        open.key());
            }
        }
    }
}
