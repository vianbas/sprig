package io.sprig.model;

import io.sprig.rule.Rule;
import java.nio.file.Path;
import java.util.List;

/**
 * Aggregated result of a scan.
 *
 * @param projectRoot the directory that was scanned
 * @param findings all findings, sorted by (file, line, ruleId)
 * @param rules rules actually enabled for this scan, with any {@code sprig.yml} severity override
 *     already applied — the source of truth for reporters that list rule metadata (e.g. the SARIF
 *     rule catalog), so it stays consistent with what {@link #findings} were produced from
 * @param javaFiles number of Java source files analyzed
 * @param configFiles number of Spring configuration files analyzed
 * @param durationMs scan duration
 */
public record ScanResult(
        Path projectRoot,
        List<Finding> findings,
        List<Rule> rules,
        int javaFiles,
        int configFiles,
        long durationMs) {

    public boolean hasFindingsAtOrAbove(Severity threshold) {
        return findings.stream().anyMatch(f -> f.severity().isAtLeast(threshold));
    }

    public long countBy(Severity severity) {
        return findings.stream().filter(f -> f.severity() == severity).count();
    }
}
