package io.sprig.rule;

import io.sprig.model.Severity;
import io.sprig.scan.ScanException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;

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
 * custom-rules:
 *   - id: ACME-CONFIG-001
 *     severity: high
 *     description: Internal debug endpoints are switched on.
 *     property: acme.debug.enabled
 *     equals: "true"
 * }</pre>
 *
 * Severity overrides are applied to findings by the scan engine; disabled rules are skipped; the
 * secret allowlist feeds {@code HardcodedSecretRule}; custom rules become {@link
 * DeclarativeConfigRule}s. A malformed custom rule is an error rather than a skipped entry, so a
 * typo cannot silently turn a rule off.
 */
public final class RulesConfig {

    public record RuleSettings(boolean enabled, Optional<Severity> severity) {}

    private static final RulesConfig EMPTY = new RulesConfig(Map.of(), Set.of(), List.of());

    private static final Set<String> CUSTOM_RULE_KEYS =
            Set.of(
                    "id",
                    "name",
                    "severity",
                    "description",
                    "remediation",
                    "property",
                    "equals",
                    "contains",
                    "present");

    private static final Pattern CUSTOM_RULE_ID = Pattern.compile("[A-Z][A-Z0-9]*(-[A-Z0-9]+)+");

    private final Map<String, RuleSettings> settings;
    private final Set<String> secretAllowlist;
    private final List<DeclarativeConfigRule> customRules;

    private RulesConfig(
            Map<String, RuleSettings> settings,
            Set<String> secretAllowlist,
            List<DeclarativeConfigRule> customRules) {
        this.settings = Map.copyOf(settings);
        this.secretAllowlist = Set.copyOf(secretAllowlist);
        this.customRules = List.copyOf(customRules);
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
            throw new ScanException(
                    "Failed to read rules config " + file + ": " + e.getMessage(), e);
        }
    }

    private static RulesConfig parse(Object loaded) {
        Map<String, RuleSettings> settings = new LinkedHashMap<>();
        Set<String> allowlist = Set.of();
        List<DeclarativeConfigRule> customRules = new ArrayList<>();
        if (loaded instanceof Map<?, ?> root) {
            Object custom = root.get("custom-rules");
            if (custom != null) {
                if (!(custom instanceof List<?> list)) {
                    throw new ScanException("custom-rules must be a list of rules");
                }
                for (int i = 0; i < list.size(); i++) {
                    customRules.add(customRule(list.get(i), i + 1));
                }
            }
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
        return new RulesConfig(settings, allowlist, customRules);
    }

    private static DeclarativeConfigRule customRule(Object item, int position) {
        String entry = "custom-rules entry " + position;
        if (!(item instanceof Map<?, ?> map)) {
            throw new ScanException(entry + " must be a mapping of keys to values");
        }
        for (Object key : map.keySet()) {
            if (!CUSTOM_RULE_KEYS.contains(String.valueOf(key))) {
                String hint =
                        "matches".equals(key) ? "; regular expressions are not supported" : "";
                throw new ScanException(entry + " has unknown key '" + key + "'" + hint);
            }
        }
        String id = required(map, "id", entry);
        String rule = "custom rule " + id;
        if (!CUSTOM_RULE_ID.matcher(id).matches()) {
            throw new ScanException(
                    rule
                            + ": id must be upper-case letters and digits in dash-separated parts,"
                            + " such as ACME-CONFIG-001");
        }
        if (id.startsWith("SPR-")) {
            throw new ScanException(
                    rule + ": ids starting with SPR- are reserved for built-in rules");
        }
        Severity severity =
                severityOf(required(map, "severity", rule))
                        .orElseThrow(
                                () ->
                                        new ScanException(
                                                rule
                                                        + ": severity must be one of info, low,"
                                                        + " medium, high, critical"));
        String description = required(map, "description", rule);
        String property = required(map, "property", rule);
        String name =
                map.get("name") == null
                        ? id.toLowerCase(Locale.ROOT)
                        : String.valueOf(map.get("name")).trim();
        String remediation =
                map.get("remediation") == null ? "" : String.valueOf(map.get("remediation")).trim();

        List<String> matchers =
                Stream.of("equals", "contains", "present").filter(map::containsKey).toList();
        if (matchers.size() != 1) {
            throw new ScanException(rule + ": set exactly one of equals, contains or present");
        }
        String matcher = matchers.get(0);
        Object value = map.get(matcher);
        if ("present".equals(matcher)) {
            if (!Boolean.TRUE.equals(value)) {
                throw new ScanException(rule + ": present must be true");
            }
            return new DeclarativeConfigRule(
                    id,
                    name,
                    severity,
                    description,
                    remediation,
                    property,
                    DeclarativeConfigRule.Match.PRESENT,
                    "");
        }
        if (value == null || String.valueOf(value).isBlank()) {
            throw new ScanException(rule + ": " + matcher + " needs a value");
        }
        DeclarativeConfigRule.Match match =
                "equals".equals(matcher)
                        ? DeclarativeConfigRule.Match.EQUALS
                        : DeclarativeConfigRule.Match.CONTAINS;
        return new DeclarativeConfigRule(
                id,
                name,
                severity,
                description,
                remediation,
                property,
                match,
                String.valueOf(value).trim());
    }

    private static String required(Map<?, ?> map, String key, String where) {
        Object value = map.get(key);
        if (value == null || String.valueOf(value).isBlank()) {
            throw new ScanException(where + ": '" + key + "' is required");
        }
        return String.valueOf(value).trim();
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
        return settings.isEmpty() && secretAllowlist.isEmpty() && customRules.isEmpty();
    }

    /** The rules defined under {@code custom-rules}, in file order. */
    public List<DeclarativeConfigRule> customRules() {
        return customRules;
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
