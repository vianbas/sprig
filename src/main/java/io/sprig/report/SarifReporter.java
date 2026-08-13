package io.sprig.report;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.sprig.Versions;
import io.sprig.model.Finding;
import io.sprig.model.ScanResult;
import io.sprig.model.Severity;
import io.sprig.rule.Rule;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * SARIF 2.1.0 report compatible with GitHub code scanning. Result URIs are relative to the scanned
 * root (run {@code sprig scan .} from the repo root in CI); the rule table lists every enabled rule
 * so {@code ruleIndex} stays stable.
 */
public final class SarifReporter implements Reporter {

    private static final String SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json";
    private static final String INFORMATION_URI = "https://github.com/vianbas/sprig";
    private static final String DOCS_URI = INFORMATION_URI + "/blob/main/docs/rules/";

    private final ObjectMapper mapper = new ObjectMapper();

    @Override
    public void write(ScanResult result, List<Rule> rules, PrintWriter out) {
        ObjectNode root = mapper.createObjectNode();
        root.put("$schema", SCHEMA);
        root.put("version", "2.1.0");

        ArrayNode runs = root.putArray("runs");
        ObjectNode run = runs.addObject();

        ObjectNode driver = run.putObject("tool").putObject("driver");
        driver.put("name", "sprig");
        driver.put("version", Versions.version());
        driver.put("informationUri", INFORMATION_URI);

        Map<String, Integer> ruleIndex = new HashMap<>();
        ArrayNode rulesNode = driver.putArray("rules");
        for (int i = 0; i < rules.size(); i++) {
            Rule rule = rules.get(i);
            ruleIndex.put(rule.id(), i);
            ObjectNode r = rulesNode.addObject();
            r.put("id", rule.id());
            r.put("name", rule.name());
            r.putObject("shortDescription").put("text", rule.description());
            r.putObject("fullDescription").put("text", rule.description());
            r.putObject("help").put("text", rule.remediation());
            r.put("helpUri", DOCS_URI + rule.id() + ".md");
            ObjectNode props = r.putObject("properties");
            ArrayNode tags = props.putArray("tags");
            rule.tags().stream().sorted().forEach(tags::add);
            props.put("precision", "high");
            props.put("security-severity", String.valueOf(securitySeverity(rule.severity())));
        }

        ArrayNode results = run.putArray("results");
        for (Finding f : result.findings()) {
            ObjectNode res = results.addObject();
            res.put("ruleId", f.ruleId());
            res.put("ruleIndex", ruleIndex.getOrDefault(f.ruleId(), 0));
            res.put("level", level(f.severity()));
            res.putObject("message").put("text", f.message());

            String uri = uriOf(f.file().toString());
            int line = f.line() > 0 ? f.line() : 1;

            ObjectNode physical =
                    res.putArray("locations").addObject().putObject("physicalLocation");
            physical.putObject("artifactLocation").put("uri", uri);
            ObjectNode region = physical.putObject("region");
            region.put("startLine", line);
            if (f.column() > 0) {
                region.put("startColumn", f.column());
            }

            res.putObject("partialFingerprints")
                    .put("primaryLocationLineHash", lineHash(f.ruleId(), uri, line));
        }

        try {
            mapper.writerWithDefaultPrettyPrinter().writeValue(out, root);
        } catch (IOException e) {
            throw new ReportException("Failed to write SARIF report: " + e.getMessage(), e);
        }
    }

    private static String level(Severity severity) {
        return switch (severity) {
            case CRITICAL, HIGH -> "error";
            case MEDIUM -> "warning";
            case LOW, INFO -> "note";
        };
    }

    private static double securitySeverity(Severity severity) {
        return switch (severity) {
            case CRITICAL -> 9.0;
            case HIGH -> 7.0;
            case MEDIUM -> 5.0;
            case LOW -> 3.0;
            case INFO -> 1.0;
        };
    }

    private static String uriOf(String file) {
        return file.replace('\\', '/').replace(" ", "%20");
    }

    private static String lineHash(String ruleId, String uri, int line) {
        return "sha256:" + sha256Hex(ruleId + "|" + uri + "|" + line);
    }

    private static String sha256Hex(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] bytes = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : bytes) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
