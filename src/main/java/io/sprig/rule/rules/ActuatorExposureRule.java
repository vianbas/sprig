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
 * management.endpoints.web.exposure.include: "*"} serves {@code env}, {@code configprops}, {@code
 * beans} and {@code mappings} on every version measured, and {@code /actuator/env} alone is enough
 * to hand over credentials.
 *
 * <p>{@code shutdown} used to be in this list and is not a token this rule can act on. Exposure
 * never reaches it: {@code POST /actuator/shutdown} answered 404 under {@code include: "*"} on Boot
 * 2.3.12, 3.3.13 and 3.5.16 alike, because the endpoint is switched off by default in every
 * release. It takes a second property to open, which is SPR-CONFIG-006's subject.
 *
 * <p>{@code heapdump} stays, and what it means depends on the version. Through Boot 3.3 exposure
 * alone serves a real HPROF. From 3.4 the access gate holds it at 404 until something opens it, so
 * on those versions this finding marks the exposure rather than the disclosure.
 */
public final class ActuatorExposureRule implements Rule {

    private static final String KEY = "management.endpoints.web.exposure.include";

    private static final Set<String> SENSITIVE = Set.of("*", "env", "heapdump");

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
        return "Spring Boot Actuator exposes sensitive endpoint(s): *, env, or heapdump.";
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
