package io.sprig.rule.rules;

import io.sprig.model.FindingCollector;
import io.sprig.model.Severity;
import io.sprig.rule.Rule;
import io.sprig.rule.RuleContext;
import io.sprig.rule.RuleKind;
import io.sprig.scan.ConfigEntry;
import java.nio.file.Path;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * SPR-CONFIG-006 — an Actuator endpoint that Spring Boot disables by default has been switched back
 * on and exposed over HTTP. {@code shutdown} stops the application; {@code heapdump} returns a
 * HPROF of the live process, which contains every credential and session token in memory.
 *
 * <p>Both halves are required, and that is the whole point of this rule. Exposure alone never
 * reaches either endpoint: measured on Boot 2.3.12, 3.3.13 and 3.5.16, {@code exposure.include:
 * "*"} leaves {@code POST /actuator/shutdown} at 404. Access alone never reaches them either: with
 * {@code exposure.include: health,info}, setting {@code
 * management.endpoint.shutdown.access=unrestricted} leaves it at 404. Name the endpoint in the
 * exposure list <em>and</em> open the gate, and the same request returns 200 and the process exits.
 *
 * <p>Boot spells the gate two ways and honours both on current versions. {@code
 * management.endpoint.<id>.enabled} was honoured on 2.3.12, 3.3.13 and 3.5.16 alike. {@code
 * management.endpoint.<id>.access} arrived in 3.4 and is inert before it. Since sprig never reads
 * the project's Boot version, it reports either spelling and leaves the version question to
 * docs/rules/SPR-CONFIG-006.md.
 */
public final class ActuatorEndpointAccessRule implements Rule {

    /** The exposure list. An endpoint absent from it is unreachable whatever its access says. */
    private static final String EXPOSURE = "management.endpoints.web.exposure.include";

    private static final String ACCESS_DEFAULT = "management.endpoints.access.default";
    private static final String MAX_PERMITTED = "management.endpoints.access.max-permitted";
    private static final String ENABLED_BY_DEFAULT = "management.endpoints.enabled-by-default";

    /**
     * The endpoints Boot ships switched off, and the access level each one needs before it answers.
     * {@code shutdown} is a POST, so read-only access leaves it at 404; {@code heapdump} is a GET
     * and read-only is enough to serve it.
     */
    private static final Map<String, Boolean> GATED_ENDPOINTS =
            Map.of("shutdown", Boolean.TRUE, "heapdump", Boolean.FALSE);

    private static final Set<String> CONFIG_KEYS =
            Stream.concat(
                            Stream.of(EXPOSURE, ACCESS_DEFAULT, MAX_PERMITTED, ENABLED_BY_DEFAULT),
                            GATED_ENDPOINTS.keySet().stream()
                                    .flatMap(
                                            id ->
                                                    Stream.of(
                                                            "management.endpoint." + id + ".access",
                                                            "management.endpoint."
                                                                    + id
                                                                    + ".enabled")))
                    .collect(Collectors.toUnmodifiableSet());

    @Override
    public String id() {
        return "SPR-CONFIG-006";
    }

    @Override
    public String name() {
        return "actuator-endpoint-access";
    }

    @Override
    public String description() {
        return "An Actuator endpoint disabled by default (shutdown, heapdump) is both exposed over HTTP and switched back on.";
    }

    @Override
    public String remediation() {
        return "Remove the endpoint from management.endpoints.web.exposure.include, or set management.endpoint.<id>.access=none (Boot 3.4+) or management.endpoint.<id>.enabled=false. If the endpoint is genuinely needed, put management on a separate port behind authentication.";
    }

    @Override
    public Severity severity() {
        return Severity.CRITICAL;
    }

    @Override
    public Set<String> tags() {
        return Set.of("actuator", "config");
    }

    @Override
    public RuleKind kind() {
        return RuleKind.CONFIG;
    }

    @Override
    public Set<String> configKeys() {
        return CONFIG_KEYS;
    }

    @Override
    public boolean appliesTo(RuleContext ctx) {
        return ctx.config() != null && !ctx.config().isEmpty();
    }

    @Override
    public void analyze(RuleContext ctx, FindingCollector findings) {
        for (Path file : ctx.config().files()) {
            Map<String, ConfigEntry> entries = ctx.config().entriesFor(file);
            ConfigEntry exposure = entries.get(EXPOSURE);
            if (exposure == null) {
                continue;
            }
            List<String> exposed = tokens(exposure.asString());
            for (Map.Entry<String, Boolean> gated : GATED_ENDPOINTS.entrySet()) {
                String id = gated.getKey();
                if (!exposed.contains("*") && !exposed.contains(id)) {
                    continue;
                }
                ConfigEntry opener = openerFor(entries, id, gated.getValue());
                if (opener != null) {
                    findings.add(
                            this,
                            opener.source(),
                            opener.line(),
                            "Actuator '"
                                    + id
                                    + "' is exposed over HTTP and switched on by "
                                    + opener.key()
                                    + "="
                                    + opener.asString()
                                    + ". "
                                    + effect(id),
                            opener.key());
                }
            }
        }
    }

    /**
     * The property that opens {@code id}, or null if nothing does. Returns the entry rather than a
     * boolean so the finding can point at the line a reader has to change.
     */
    private static ConfigEntry openerFor(
            Map<String, ConfigEntry> entries, String id, boolean needsWrite) {
        if (capped(entries, needsWrite)) {
            return null;
        }
        ConfigEntry access = entries.get("management.endpoint." + id + ".access");
        ConfigEntry enabled = entries.get("management.endpoint." + id + ".enabled");
        if (access != null || enabled != null) {
            // An explicit per-endpoint setting decides on its own: access=none beats a blanket
            // access.default=unrestricted, which is measured behaviour on 3.5.16.
            if (enabled != null && isTrue(enabled.asString())) {
                return enabled;
            }
            if (access != null && grants(access.asString(), needsWrite)) {
                return access;
            }
            return null;
        }
        ConfigEntry blanketEnabled = entries.get(ENABLED_BY_DEFAULT);
        if (blanketEnabled != null && isTrue(blanketEnabled.asString())) {
            return blanketEnabled;
        }
        ConfigEntry blanketAccess = entries.get(ACCESS_DEFAULT);
        if (blanketAccess != null && grants(blanketAccess.asString(), needsWrite)) {
            return blanketAccess;
        }
        return null;
    }

    /**
     * Whether {@code management.endpoints.access.max-permitted} caps the endpoint below what it
     * needs. Measured on 3.5.16: {@code read-only} takes shutdown back to 404 while heapdump, a
     * GET, still returns a real HPROF, and the cap holds against the legacy {@code enabled: true}
     * spelling too.
     *
     * <p>The cap is a 3.4+ property and does nothing before it, so on 3.3 a project that set both
     * {@code shutdown.enabled: true} and this cap would still be reachable while this rule stays
     * quiet. That is accepted rather than fixed: writing a 3.4-only property into a pre-3.4 project
     * is a configuration that does nothing on its own terms, and treating the cap as inert would
     * put a CRITICAL finding on every correctly capped 3.4+ project instead.
     */
    private static boolean capped(Map<String, ConfigEntry> entries, boolean needsWrite) {
        ConfigEntry max = entries.get(MAX_PERMITTED);
        return max != null && !grants(max.asString(), needsWrite);
    }

    /** Whether an access level reaches the endpoint. {@code none} never does. */
    private static boolean grants(String value, boolean needsWrite) {
        if (value == null) {
            return false;
        }
        String level = value.trim().toLowerCase(Locale.ROOT);
        return needsWrite
                ? level.equals("unrestricted")
                : level.equals("unrestricted") || level.equals("read-only");
    }

    private static boolean isTrue(String value) {
        return value != null && value.trim().toLowerCase(Locale.ROOT).equals("true");
    }

    private static String effect(String id) {
        return id.equals("shutdown")
                ? "POST /actuator/shutdown stops the application."
                : "GET /actuator/heapdump returns a dump of process memory, including credentials and session tokens.";
    }

    private static List<String> tokens(String value) {
        if (value == null) {
            return List.of();
        }
        return Stream.of(value.split(","))
                .map(t -> t.trim().toLowerCase(Locale.ROOT))
                .filter(t -> !t.isEmpty())
                .collect(Collectors.toList());
    }
}
