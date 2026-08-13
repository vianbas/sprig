package io.sprig.report;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.sprig.Versions;
import io.sprig.model.Finding;
import io.sprig.model.ScanResult;
import io.sprig.rule.Rule;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Path;
import java.util.List;

/** Machine-readable JSON report. Byte-stable for a given scan (golden-test friendly). */
public final class JsonReporter implements Reporter {

    private final ObjectMapper mapper = new ObjectMapper();

    @Override
    public void write(ScanResult result, List<Rule> rules, PrintWriter out) {
        ObjectNode root = mapper.createObjectNode();
        root.put("tool", "sprig");
        root.put("version", Versions.version());

        ObjectNode scan = root.putObject("scan");
        scan.put("root", relativeRoot(result.projectRoot()));
        scan.put("javaFiles", result.javaFiles());
        scan.put("configFiles", result.configFiles());

        ArrayNode findings = root.putArray("findings");
        for (Finding f : result.findings()) {
            ObjectNode fn = findings.addObject();
            fn.put("ruleId", f.ruleId());
            fn.put("severity", f.severity().label());
            fn.put("message", f.message());
            fn.put("file", f.file().toString());
            fn.put("line", f.line());
            fn.put("column", f.column());
            fn.put("propertyPath", f.propertyPath());
            fn.put("remediation", f.remediation());
        }

        try {
            mapper.writerWithDefaultPrettyPrinter().writeValue(out, root);
        } catch (IOException e) {
            throw new ReportException("Failed to write JSON report: " + e.getMessage(), e);
        }
    }

    /** Root expressed relative to the working directory, so output is stable across machines. */
    static String relativeRoot(Path projectRoot) {
        Path cwd = Path.of("").toAbsolutePath().normalize();
        Path root = projectRoot.toAbsolutePath().normalize();
        try {
            String s = cwd.relativize(root).toString();
            return s.isEmpty() ? "." : s;
        } catch (IllegalArgumentException e) {
            return root.toString();
        }
    }
}
