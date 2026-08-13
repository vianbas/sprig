package io.sprig.model;

import java.nio.file.Path;

/**
 * A single detected security misconfiguration.
 *
 * @param ruleId stable rule identifier (e.g. {@code SPR-CORS-001})
 * @param severity severity of the finding
 * @param message human-readable description of what was found
 * @param remediation fix guidance
 * @param file path relative to the scanned project root
 * @param line 1-based line, {@code 0} when unknown
 * @param column 1-based column, {@code 0} when unknown
 * @param propertyPath dotted config property key (empty for source findings)
 */
public record Finding(
        String ruleId,
        Severity severity,
        String message,
        String remediation,
        Path file,
        int line,
        int column,
        String propertyPath) {

    public String location() {
        return file + ":" + line;
    }
}
