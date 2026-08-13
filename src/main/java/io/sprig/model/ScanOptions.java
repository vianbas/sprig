package io.sprig.model;

import java.nio.file.Path;
import java.util.List;
import java.util.Set;

/**
 * Options that configure a scan run. Built by the CLI from command-line flags, or directly by
 * tests.
 *
 * @param includeRules when non-empty, only run these rule ids
 * @param excludeRules rule ids to disable
 * @param configFile path to a sprig rules config (YAML); {@code null} for none
 * @param excludePaths additional path globs to skip during discovery
 * @param verbose print extra diagnostics
 * @param quiet suppress per-finding output
 */
public record ScanOptions(
        Set<String> includeRules,
        Set<String> excludeRules,
        Path configFile,
        List<String> excludePaths,
        boolean verbose,
        boolean quiet) {

    public static ScanOptions defaults() {
        return new ScanOptions(Set.of(), Set.of(), null, List.of(), false, false);
    }
}
