package io.sprig.rule.rules;

import io.sprig.model.FindingCollector;
import io.sprig.model.Severity;
import io.sprig.rule.Rule;
import io.sprig.rule.RuleContext;
import io.sprig.rule.RuleKind;
import io.sprig.scan.ConfigEntry;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * SPR-CONFIG-001 — Actuator exposes a sensitive endpoint. The infamous {@code
 * management.endpoints.web.exposure.include: "*"} leaks environment variables and heap dumps;
 * {@code env} and {@code heapdump} alone are just as dangerous.
 */
public final class ActuatorExposureRule implements Rule {

    private static final String KEY = "management.endpoints.web.exposure.include";

    private static final Set<String> SENSITIVE = Set.of("*", "env", "heapdump", "shutdown");

    @Override
    public String id() {
        return "SPR-CONFIG-001";
    }

    @Override
    public String name() {
        return "actuator-exposure";
    }

    @Override
    public String description() {
        return "Spring Boot Actuator exposes sensitive endpoint(s): *, env, heapdump, or shutdown.";
    }

    @Override
    public String remediation() {
        return "Limit management.endpoints.web.exposure.include to safe endpoints (health, info) or expose management over a non-public port with authentication.";
    }

    @Override
    public Severity severity() {
        return Severity.HIGH;
    }

    @Override
    public Set<String> tags() {
        return Set.of("actuator", "info-exposure", "config");
    }

    @Override
    public RuleKind kind() {
        return RuleKind.CONFIG;
    }

    @Override
    public Set<String> configKeys() {
        return Set.of(KEY);
    }

    @Override
    public boolean appliesTo(RuleContext ctx) {
        return ctx.config() != null && !ctx.config().isEmpty();
    }

    @Override
    public void analyze(RuleContext ctx, FindingCollector findings) {
        for (ConfigEntry entry : ctx.config().allEntries()) {
            if (!KEY.equals(entry.key())) {
                continue;
            }
            List<String> exposed = new ArrayList<>();
            for (String token : tokens(entry.asString())) {
                if (SENSITIVE.contains(token) && !exposed.contains(token)) {
                    exposed.add(token);
                }
            }
            if (!exposed.isEmpty()) {
                findings.add(
                        this,
                        entry.source(),
                        entry.line(),
                        "Actuator endpoint(s) exposed: " + String.join(", ", exposed) + ".",
                        entry.key());
            }
        }
    }

    private static List<String> tokens(String value) {
        List<String> out = new ArrayList<>();
        if (value == null) {
            return out;
        }
        for (String t : value.split(",")) {
            String token = t.trim().toLowerCase(Locale.ROOT);
            if (!token.isEmpty()) {
                out.add(token);
            }
        }
        return out;
    }
}
