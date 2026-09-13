package io.sprig.rule;

import io.sprig.model.ScanOptions;
import io.sprig.rule.rules.BuiltInRules;
import io.sprig.scan.ScanException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.ServiceLoader;

/**
 * Index of all available rules. Loads rules via {@link ServiceLoader} so the set can be extended
 * without modifying core classes; falls back to the built-in rules when no service registration
 * exists.
 */
public final class RuleRegistry {

    private final List<Rule> rules;

    private RuleRegistry(List<Rule> rules) {
        this.rules = List.copyOf(rules);
    }

    public static RuleRegistry load() {
        List<Rule> loaded = new ArrayList<>();
        for (Rule rule : ServiceLoader.load(Rule.class)) {
            loaded.add(rule);
        }
        if (loaded.isEmpty()) {
            loaded.addAll(BuiltInRules.all());
        }
        return new RuleRegistry(loaded);
    }

    public static RuleRegistry of(List<Rule> rules) {
        return new RuleRegistry(rules);
    }

    public List<Rule> all() {
        return rules;
    }

    public Optional<Rule> byId(String id) {
        return rules.stream().filter(r -> r.id().equals(id)).findFirst();
    }

    /**
     * This registry plus {@code extra}, for rules defined at scan time such as the custom rules in
     * a {@code sprig.yml}. An id that is already registered is an error, never a silent
     * replacement.
     */
    public RuleRegistry with(List<? extends Rule> extra) {
        if (extra.isEmpty()) {
            return this;
        }
        List<Rule> combined = new ArrayList<>(rules);
        for (Rule rule : extra) {
            if (combined.stream().anyMatch(existing -> existing.id().equals(rule.id()))) {
                throw new ScanException("Rule id " + rule.id() + " is already defined");
            }
            combined.add(rule);
        }
        return new RuleRegistry(combined);
    }

    /**
     * Rules to run for the given options: honors {@code --include-rule} and {@code --exclude-rule},
     * then returns them sorted by id for determinism.
     */
    public List<Rule> enabled(ScanOptions options) {
        return rules.stream()
                .filter(
                        r ->
                                options.includeRules().isEmpty()
                                        || options.includeRules().contains(r.id()))
                .filter(r -> !options.excludeRules().contains(r.id()))
                .sorted(Comparator.comparing(Rule::id))
                .toList();
    }
}
