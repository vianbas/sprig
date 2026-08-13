package io.sprig.rule;

import io.sprig.model.ScanOptions;
import io.sprig.scan.ConfigModel;
import io.sprig.scan.SpringContext;
import java.nio.file.Path;

/**
 * Everything a rule needs to make its decision. One of {@code spring} or {@code config} may be
 * {@code null} when the scanned project has no Java sources or no configuration files respectively.
 *
 * @param projectRoot the scanned project root
 * @param spring parsed Java model, or {@code null} when the project has no Java sources
 * @param config parsed configuration model, or {@code null} when the project has none
 * @param options scan options
 */
public record RuleContext(
        Path projectRoot, SpringContext spring, ConfigModel config, ScanOptions options) {}
