package io.sprig.rule;

import io.sprig.model.Severity;
import io.sprig.scan.ScanException;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Per-project rule configuration from a {@code sprig.yml} file.
 *
 * <pre>{@code
 * rules:
 *   SPR-CONFIG-002:
 *     enabled: true
 *     severity: critical
 * secret-allowlist:
 *   - dev-password
 * }</pre>
 *
 * Severity overrides are applied to findings by the scan engine; disabled
 * rules are skipped; the secret allowlist feeds {@code HardcodedSecretRule}.
 */
public final class RulesConfig {

    public record RuleSettings(boolean enabled, Optional<Severity> severity) {
    }

    private static final RulesConfig EMPTY = new RulesConfig(Map.of(), Set.of());

    private final Map<String, RuleSettings> settings;
    private final Set<String> secretAllowlist;

    private RulesConfig(Map<String, RuleSettings> settings, Set<String> secretAllowlist) {
        this.settings = Map.copyOf(settings);
        this.secretAllowlist = Set.copyOf(secretAllowlist);
    }

    public static RulesConfig empty() {
        return EMPTY;
    }

    public static RulesConfig load(Path file) {
        LoaderOptions options = new LoaderOptions();
        options.setCodePointLimit(10_000_000);
        Yaml yaml = new Yaml(options);
        try (InputStream in = Files.newInputStream(file)) {
            return parse(yaml.load(in));
        } catch (IOException e) {
            throw new ScanException("Failed to read rules config " + file + ": " + e.getMessage(), e);
        }
    }

    private static RulesConfig parse(Object loaded) {
        Map<String, RuleSettings> settings = new LinkedHashMap<>();
        Set<String> allowlist = Set.of();
        if (loaded instanceof Map<?, ?> root) {
            if (root.get("rules") instanceof Map<?, ?> rules) {
                for (Map.Entry<?, ?> entry : rules.entrySet()) {
                    String id = String.valueOf(entry.getKey());
                    if (entry.getValue() instanceof Map<?, ?> settingsMap) {
                        boolean enabled = !Boolean.FALSE.equals(settingsMap.get("enabled"));
                        Optional<Severity> severity = severityOf(settingsMap.get("severity"));
                        settings.put(id, new RuleSettings(enabled, severity));
                    }
                }
            }
            if (root.get("secret-allowlist") instanceof Iterable<?> list) {
                allowlist = new HashSet<>();
                for (Object item : list) {
                    allowlist.add(String.valueOf(item));
                }
            }
        }
        return new RulesConfig(settings, allowlist);
    }

    private static Optional<Severity> severityOf(Object value) {
        if (value instanceof String s) {
            try {
                return Optional.of(Severity.valueOf(s.trim().toUpperCase(Locale.ROOT)));
            } catch (IllegalArgumentException e) {
                return Optional.empty();
            }
        }
        return Optional.empty();
    }

    public boolean isEmpty() {
        return settings.isEmpty() && secretAllowlist.isEmpty();
    }

    public boolean isRuleEnabled(String ruleId) {
        RuleSettings s = settings.get(ruleId);
        return s == null || s.enabled();
    }

    public Optional<Severity> severityOverride(String ruleId) {
        RuleSettings s = settings.get(ruleId);
        return s == null ? Optional.empty() : s.severity();
    }

    public Set<String> secretAllowlist() {
        return secretAllowlist;
    }
}
