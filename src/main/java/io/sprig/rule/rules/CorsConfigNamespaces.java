package io.sprig.rule.rules;

import io.sprig.scan.ConfigEntry;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * The two property namespaces Spring Boot binds to a {@code CorsConfiguration}: Actuator's {@code
 * management.endpoints.web.cors.*} and GraphQL's {@code spring.graphql.cors.*}. Shared by
 * SPR-CONFIG-004 and SPR-CONFIG-007, which split the same open-origin condition on whether {@code
 * allow-credentials} is {@code true}, so a namespace is reported by at most one of them.
 *
 * <p>Origins and credentials are paired within a namespace, never across one: an Actuator wildcard
 * says nothing about whether GraphQL allows credentials.
 */
final class CorsConfigNamespaces {

    static final List<String> PREFIXES =
            List.of("management.endpoints.web.cors", "spring.graphql.cors");

    private static final String ORIGINS = ".allowed-origins";
    private static final String ORIGIN_PATTERNS = ".allowed-origin-patterns";
    private static final String CREDENTIALS = ".allow-credentials";

    static final Set<String> CONFIG_KEYS =
            PREFIXES.stream()
                    .flatMap(
                            prefix ->
                                    Stream.of(
                                            prefix + ORIGINS,
                                            prefix + ORIGIN_PATTERNS,
                                            prefix + CREDENTIALS))
                    .collect(Collectors.toUnmodifiableSet());

    /**
     * An origin pattern whose host is a bare {@code *}. Measured on Boot 3.5.16 with {@code
     * allow-credentials=true}: {@code https://*}, {@code http://*} and {@code https://*:[*]} each
     * echoed an unrelated origin of their scheme back with {@code Access-Control-Allow-Credentials:
     * true}, while {@code https://*.example.com} refused {@code https://evil.example} with a 403.
     */
    private static final Pattern ANY_HOST_PATTERN =
            Pattern.compile("\\*|[a-zA-Z][a-zA-Z0-9+.-]*://\\*(:\\[\\*])?");

    private CorsConfigNamespaces() {}

    /**
     * The entry that lets every origin through in {@code prefix}, or {@code null}: {@code
     * allowed-origins} containing {@code *}, else {@code allowed-origin-patterns} containing a
     * pattern with a bare {@code *} host.
     */
    static ConfigEntry anyOriginEntry(Map<String, ConfigEntry> entries, String prefix) {
        ConfigEntry origins = entries.get(prefix + ORIGINS);
        if (origins != null && tokens(origins.asString()).contains("*")) {
            return origins;
        }
        ConfigEntry patterns = entries.get(prefix + ORIGIN_PATTERNS);
        if (patterns != null
                && tokens(patterns.asString()).stream()
                        .anyMatch(token -> ANY_HOST_PATTERN.matcher(token).matches())) {
            return patterns;
        }
        return null;
    }

    /** Whether {@code allow-credentials} is set to {@code true} in {@code prefix}. */
    static boolean credentialsAllowed(Map<String, ConfigEntry> entries, String prefix) {
        ConfigEntry credentials = entries.get(prefix + CREDENTIALS);
        return credentials != null
                && credentials.asString() != null
                && credentials.asString().trim().toLowerCase(Locale.ROOT).equals("true");
    }

    /** The property name of {@code entry} within its namespace, e.g. {@code allowed-origins}. */
    static String shortName(ConfigEntry entry, String prefix) {
        return entry.key().substring(prefix.length() + 1);
    }

    private static List<String> tokens(String value) {
        if (value == null) {
            return List.of();
        }
        return Stream.of(value.split(",")).map(String::trim).filter(t -> !t.isEmpty()).toList();
    }
}
