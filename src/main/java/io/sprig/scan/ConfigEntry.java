package io.sprig.scan;

import java.nio.file.Path;

/**
 * A single flattened configuration property with provenance.
 *
 * @param key      dotted key, e.g. {@code management.endpoints.web.exposure.include}
 * @param raw      the raw parsed value (scalar or list)
 * @param asString normalized string form of the value, or {@code null}
 * @param source   the file the property came from
 * @param line     1-based line in the source file
 */
public record ConfigEntry(
        String key,
        Object raw,
        String asString,
        Path source,
        int line) {

    /** Whether the value is a {@code ${...}} placeholder (usually an env reference). */
    public boolean isPlaceholder() {
        return asString != null && asString.contains("${");
    }

    /** Whether the value references an environment variable. */
    public boolean isEnvRef() {
        return asString != null && (asString.matches("\\$\\{[^}]+}") || asString.startsWith("env."));
    }
}
