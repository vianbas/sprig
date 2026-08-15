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
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * SPR-CONFIG-004 — CORS configured with wildcard allowed-origins and allow-credentials=true, on one
 * of the two surfaces Spring Boot exposes as plain configuration properties: Actuator's {@code
 * management.endpoints.web.cors.*} and GraphQL's {@code spring.graphql.cors.*}.
 *
 * <p>Spring MVC's own CORS has no property namespace at all; it is configured in Java, which is
 * SPR-CORS-001's territory. This rule previously matched {@code spring.web.cors.*} and {@code
 * spring.mvc.cors.*}, neither of which Spring has ever declared, so it could not fire on a real
 * project (#39).
 */
public final class CorsConfigWildcardCredentialsRule implements Rule {

    /**
     * The property namespaces that bind to a {@code CorsConfiguration}. Origins and credentials are
     * paired within a namespace, never across one: an Actuator wildcard says nothing about whether
     * GraphQL allows credentials.
     */
    private static final List<String> PREFIXES =
            List.of("management.endpoints.web.cors", "spring.graphql.cors");

    private static final String ORIGINS = ".allowed-origins";
    private static final String CREDENTIALS = ".allow-credentials";

    private static final Set<String> CONFIG_KEYS =
            PREFIXES.stream()
                    .flatMap(prefix -> Stream.of(prefix + ORIGINS, prefix + CREDENTIALS))
                    .collect(Collectors.toUnmodifiableSet());

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
        return "List the permitted origins explicitly when allow-credentials=true; never combine '*' with credentials.";
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
        return CONFIG_KEYS;
    }

    @Override
    public boolean appliesTo(RuleContext ctx) {
        return ctx.config() != null && !ctx.config().isEmpty();
    }

    @Override
    public void analyze(RuleContext ctx, FindingCollector findings) {
        for (Path file : ctx.config().files()) {
            Map<String, ConfigEntry> entries = ctx.config().entriesFor(file);
            for (String prefix : PREFIXES) {
                ConfigEntry origins = entries.get(prefix + ORIGINS);
                ConfigEntry credentials = entries.get(prefix + CREDENTIALS);
                if (origins == null || credentials == null) {
                    continue;
                }
                if (containsWildcard(origins.asString()) && isTrue(credentials.asString())) {
                    findings.add(
                            this,
                            origins.source(),
                            origins.line(),
                            prefix + ": allowed-origins=* combined with allow-credentials=true.",
                            origins.key());
                }
            }
        }
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
