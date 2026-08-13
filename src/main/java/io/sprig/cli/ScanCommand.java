package io.sprig.cli;

import io.sprig.model.ScanOptions;
import io.sprig.model.ScanResult;
import io.sprig.model.Severity;
import io.sprig.report.ReportFormat;
import io.sprig.report.Reporter;
import io.sprig.report.ReporterFactory;
import io.sprig.scan.ScanEngine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;

/** The {@code sprig scan} subcommand. */
@Command(
        name = "scan",
        mixinStandardHelpOptions = true,
        description = "Scan a Spring Boot project for security misconfigurations.")
public final class ScanCommand implements Callable<Integer> {

    @Parameters(index = "0", arity = "0..1", defaultValue = ".",
            description = "Project directory to scan (default: current directory).")
    Path target;

    @Option(names = {"-o", "--output"}, defaultValue = "console",
            description = "Report format: ${COMPLETION-CANDIDATES} (default: console).")
    ReportFormat format;

    @Option(names = "--output-file", description = "Write the report to a file instead of stdout.")
    Path outputFile;

    @Option(names = {"-f", "--fail-on"}, defaultValue = "HIGH",
            description = "Exit 1 when any finding at or above this severity exists: ${COMPLETION-CANDIDATES} (default: HIGH).")
    Severity failOn;

    @Option(names = {"-e", "--exclude-rule"}, split = ",", description = "Disable rule id(s). Comma-separated.")
    Set<String> excludeRules = new HashSet<>();

    @Option(names = {"-i", "--include-rule"}, split = ",", description = "Run only these rule id(s). Comma-separated.")
    Set<String> includeRules = new HashSet<>();

    @Option(names = {"-c", "--config"}, description = "Path to a sprig rules config (YAML). Defaults to ./sprig.yml.")
    Path configFile;

    @Option(names = "--exclude-path", split = ",", description = "Additional path globs to skip during discovery.")
    List<String> excludePaths = new ArrayList<>();

    @Option(names = {"-q", "--quiet"}, description = "Only print the summary line.")
    boolean quiet;

    @Option(names = {"-V", "--verbose"}, description = "Print extra diagnostics (e.g. unparseable files).")
    boolean verbose;

    @Override
    public Integer call() {
        try {
            ScanOptions options = new ScanOptions(includeRules, excludeRules, configFile, excludePaths, verbose, quiet);
            ScanResult result = new ScanEngine().scan(target, options);
            Reporter reporter = ReporterFactory.create(format, quiet);
            if (outputFile != null) {
                try (PrintWriter fileOut = new PrintWriter(Files.newBufferedWriter(outputFile, StandardCharsets.UTF_8))) {
                    reporter.write(result, result.rules(), fileOut);
                }
            } else {
                reporter.write(result, result.rules(), new PrintWriter(System.out, true));
            }
            return result.hasFindingsAtOrAbove(failOn) ? ExitCodes.FINDINGS : ExitCodes.OK;
        } catch (Exception e) {
            if (verbose) {
                e.printStackTrace(System.err);
            } else {
                System.err.println("sprig: error: " + e.getMessage());
            }
            return ExitCodes.ERROR;
        }
    }
}
