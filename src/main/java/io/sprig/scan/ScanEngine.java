package io.sprig.scan;

import io.sprig.model.Finding;
import io.sprig.model.FindingCollector;
import io.sprig.model.ScanOptions;
import io.sprig.model.ScanResult;
import io.sprig.model.Severity;
import io.sprig.rule.Rule;
import io.sprig.rule.RuleContext;
import io.sprig.rule.RuleRegistry;
import io.sprig.rule.RulesConfig;
import io.sprig.rule.SeverityOverriddenRule;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * The scan orchestrator: discover → parse → run rules → build result.
 */
public final class ScanEngine {

    public ScanResult scan(Path target, ScanOptions options) {
        return scan(target, options, RuleRegistry.load());
    }

    /** Scans with an explicit registry (used by tests to run a configured rule instance). */
    public ScanResult scan(Path target, ScanOptions options, RuleRegistry registry) {
        if (!Files.exists(target)) {
            throw new ScanException("Path does not exist: " + target);
        }
        if (!Files.isDirectory(target)) {
            throw new ScanException("Not a directory: " + target);
        }

        long start = System.nanoTime();

        ProjectFiles files = ProjectScanner.discover(target, options.excludePaths());
        SpringContext spring = files.javaFiles().isEmpty() ? null : JavaSourceParser.parseAll(files.javaFiles());
        ConfigModel config = files.configFiles().isEmpty() ? ConfigModel.empty() : ConfigLoader.load(files.configFiles());

        RulesConfig rulesConfig = loadRulesConfig(options.configFile(), target);

        List<Rule> rules = registry.enabled(options);
        if (!rulesConfig.isEmpty()) {
            rules = rules.stream()
                    .filter(r -> rulesConfig.isRuleEnabled(r.id()))
                    .map(r -> r.configure(rulesConfig))
                    .toList();
        }

        RuleContext ctx = new RuleContext(target, spring, config, options);
        FindingCollector collector = new FindingCollector();
        for (Rule rule : rules) {
            if (rule.appliesTo(ctx)) {
                rule.analyze(ctx, collector);
            }
        }

        Path root = target.toAbsolutePath().normalize();
        List<Finding> findings = new ArrayList<>();
        for (Finding f : collector.all()) {
            Path file = f.file().toAbsolutePath().normalize();
            Path relative = root.relativize(file);
            Severity severity = rulesConfig.severityOverride(f.ruleId()).orElse(f.severity());
            findings.add(new Finding(f.ruleId(), severity, f.message(), f.remediation(),
                    relative, f.line(), f.column(), f.propertyPath()));
        }

        // Same rules that were actually run, with any severity override applied —
        // handed to reporters so rule-catalog metadata (e.g. SARIF security-severity)
        // matches the enabled/disabled set and severities findings were produced with.
        List<Rule> reportedRules = rules.stream()
                .map(r -> rulesConfig.severityOverride(r.id())
                        .<Rule>map(sev -> new SeverityOverriddenRule(r, sev))
                        .orElse(r))
                .toList();

        long durationMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
        return new ScanResult(root, findings, reportedRules, files.javaFiles().size(), files.configFiles().size(), durationMs);
    }

    private static RulesConfig loadRulesConfig(Path configFile, Path target) {
        if (configFile != null) {
            if (!Files.exists(configFile)) {
                throw new ScanException("Rules config not found: " + configFile);
            }
            return RulesConfig.load(configFile);
        }
        Path defaultConfig = target.resolve("sprig.yml");
        if (Files.exists(defaultConfig)) {
            return RulesConfig.load(defaultConfig);
        }
        return RulesConfig.empty();
    }
}
