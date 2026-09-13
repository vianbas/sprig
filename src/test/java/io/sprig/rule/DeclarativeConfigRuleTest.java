package io.sprig.rule;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.tuple;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.sprig.cli.Cli;
import io.sprig.model.Finding;
import io.sprig.model.ScanOptions;
import io.sprig.model.ScanResult;
import io.sprig.model.Severity;
import io.sprig.report.SarifReporter;
import io.sprig.scan.ScanEngine;
import io.sprig.scan.ScanException;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Custom rules declared under {@code custom-rules} in {@code sprig.yml} (#28). */
class DeclarativeConfigRuleTest extends RuleTestBase {

    private static final Path FIXTURE = fixturesDir().resolve("custom-rules");

    @Test
    void reportsEachMatcherAtTheMatchingFileAndLine() {
        List<Finding> custom =
                customFindings(new ScanEngine().scan(FIXTURE, ScanOptions.defaults()));
        assertThat(custom)
                .extracting(
                        Finding::ruleId, Finding::severity, f -> f.file().toString(), Finding::line)
                .containsExactlyInAnyOrder(
                        tuple(
                                "ACME-CONFIG-001",
                                Severity.HIGH,
                                "src/main/resources/application.yml",
                                3),
                        tuple(
                                "ACME-CONFIG-002",
                                Severity.MEDIUM,
                                "src/main/resources/application.yml",
                                5),
                        tuple(
                                "ACME-CONFIG-003",
                                Severity.LOW,
                                "src/main/resources/application-dev.properties",
                                1));
    }

    @Test
    void findingMessagesNameThePropertyAndItsValue() {
        List<Finding> custom =
                customFindings(new ScanEngine().scan(FIXTURE, ScanOptions.defaults()));
        assertThat(custom)
                .extracting(Finding::message)
                .containsExactlyInAnyOrder(
                        "acme.debug.enabled=true: Internal debug endpoints are switched on.",
                        "acme.features=search,legacy-import: The legacy importer is enabled.",
                        "acme.legacy.console is set: The legacy admin console is configured.");
    }

    @Test
    void excludeRuleRemovesACustomRule() {
        ScanOptions options =
                new ScanOptions(Set.of(), Set.of("ACME-CONFIG-002"), null, List.of(), false, false);
        assertThat(customFindings(new ScanEngine().scan(FIXTURE, options)))
                .extracting(Finding::ruleId)
                .containsExactlyInAnyOrder("ACME-CONFIG-001", "ACME-CONFIG-003");
    }

    @Test
    void rulesSectionOverridesSeverityAndDisablesCustomRules(@TempDir Path tmp) throws IOException {
        Path project =
                project(
                        tmp,
                        rules(
                                        debugRule("ACME-CONFIG-001", "equals: \"true\""),
                                        debugRule("ACME-CONFIG-009", "present: true"))
                                + "rules:\n"
                                + "  ACME-CONFIG-001:\n"
                                + "    severity: critical\n"
                                + "  ACME-CONFIG-009:\n"
                                + "    enabled: false\n");
        assertThat(new ScanEngine().scan(project, ScanOptions.defaults()).findings())
                .extracting(Finding::ruleId, Finding::severity)
                .containsExactly(tuple("ACME-CONFIG-001", Severity.CRITICAL));
    }

    @Test
    void malformedCustomRulesStopTheScan(@TempDir Path tmp) throws IOException {
        assertRejected(tmp, "custom-rules: nope\n", "custom-rules must be a list");
        assertRejected(
                tmp,
                rules(
                        entry(
                                "severity: high",
                                "description: d",
                                "property: acme.debug.enabled",
                                "present: true")),
                "'id' is required");
        assertRejected(
                tmp, rules(debugRule("acme-1", "present: true")), "id must be upper-case letters");
        assertRejected(
                tmp,
                rules(debugRule("SPR-CONFIG-900", "present: true")),
                "reserved for built-in rules");
        assertRejected(
                tmp,
                rules(
                        entry(
                                "id: ACME-CONFIG-001",
                                "severity: urgent",
                                "description: d",
                                "property: acme.debug.enabled",
                                "present: true")),
                "severity must be one of");
        assertRejected(
                tmp,
                rules(
                        entry(
                                "id: ACME-CONFIG-001",
                                "severity: high",
                                "description: d",
                                "property: acme.debug.enabled")),
                "set exactly one of equals, contains or present");
        assertRejected(
                tmp,
                rules(
                        entry(
                                "id: ACME-CONFIG-001",
                                "severity: high",
                                "description: d",
                                "property: acme.debug.enabled",
                                "equals: \"true\"",
                                "present: true")),
                "set exactly one of equals, contains or present");
        assertRejected(
                tmp,
                rules(debugRule("ACME-CONFIG-001", "matches: \"tr.e\"")),
                "regular expressions are not supported");
        assertRejected(
                tmp, rules(debugRule("ACME-CONFIG-001", "present: false")), "present must be true");
        assertRejected(tmp, rules(debugRule("ACME-CONFIG-001", "equals:")), "equals needs a value");
        assertRejected(
                tmp,
                rules(
                        debugRule("ACME-CONFIG-001", "present: true"),
                        debugRule("ACME-CONFIG-001", "equals: \"true\"")),
                "Rule id ACME-CONFIG-001 is already defined");
    }

    @Test
    void customFindingsCountTowardsTheExitCode() {
        assertThat(Cli.commandLine().execute("scan", FIXTURE.toString())).isEqualTo(1);
        assertThat(
                        Cli.commandLine()
                                .execute(
                                        "scan",
                                        FIXTURE.toString(),
                                        "--exclude-rule",
                                        "ACME-CONFIG-001"))
                .isZero();
    }

    @Test
    void cliExitsTwoOnAMalformedCustomRule(@TempDir Path tmp) throws IOException {
        Path project = project(tmp, rules(debugRule("ACME-CONFIG-001", "matches: \"tr.e\"")));
        assertThat(Cli.commandLine().execute("scan", project.toString())).isEqualTo(2);
    }

    @Test
    void sarifOmitsHelpUriForCustomRulesOnly() throws IOException {
        ScanResult result = new ScanEngine().scan(FIXTURE, ScanOptions.defaults());
        StringWriter out = new StringWriter();
        new SarifReporter().write(result, result.rules(), new PrintWriter(out));
        JsonNode rules =
                new ObjectMapper().readTree(out.toString()).at("/runs/0/tool/driver/rules");
        int custom = 0;
        for (JsonNode rule : rules) {
            String id = rule.get("id").asText();
            if (id.startsWith("ACME-")) {
                custom++;
                assertThat(rule.has("helpUri")).as(id).isFalse();
            } else {
                assertThat(rule.get("helpUri").asText()).isEqualTo(Rule.DOCS_URI + id + ".md");
            }
        }
        assertThat(custom).isEqualTo(3);
    }

    private static List<Finding> customFindings(ScanResult result) {
        return result.findings().stream().filter(f -> f.ruleId().startsWith("ACME-")).toList();
    }

    private static void assertRejected(Path tmp, String sprigYml, String message)
            throws IOException {
        Path project = project(tmp, sprigYml);
        assertThatThrownBy(() -> new ScanEngine().scan(project, ScanOptions.defaults()))
                .isInstanceOf(ScanException.class)
                .hasMessageContaining(message);
    }

    private static Path project(Path tmp, String sprigYml) throws IOException {
        Path project = Files.createTempDirectory(tmp, "project");
        Path resources = Files.createDirectories(project.resolve("src/main/resources"));
        Files.writeString(resources.resolve("application.properties"), "acme.debug.enabled=true\n");
        Files.writeString(project.resolve("sprig.yml"), sprigYml);
        return project;
    }

    private static String rules(String... entries) {
        return "custom-rules:\n" + String.join("", entries);
    }

    private static String entry(String... lines) {
        StringBuilder yaml = new StringBuilder();
        for (int i = 0; i < lines.length; i++) {
            yaml.append(i == 0 ? "  - " : "    ").append(lines[i]).append('\n');
        }
        return yaml.toString();
    }

    private static String debugRule(String id, String matcher) {
        return entry(
                "id: " + id,
                "severity: high",
                "description: Debug is on.",
                "property: acme.debug.enabled",
                matcher);
    }
}
