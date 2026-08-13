package io.sprig.report;

import io.sprig.model.ScanOptions;
import io.sprig.model.ScanResult;
import io.sprig.rule.Rule;
import io.sprig.rule.RuleRegistry;
import io.sprig.scan.ScanEngine;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** Shared helpers for reporter tests: scan demo-app, render, and compare goldens. */
abstract class ReporterTestBase {

    protected static Path demoApp() {
        return Path.of("src", "test", "resources", "fixtures", "demo-app").toAbsolutePath();
    }

    protected static ScanResult scanDemo() {
        return new ScanEngine().scan(demoApp(), ScanOptions.defaults());
    }

    protected static List<Rule> rules() {
        return RuleRegistry.load().enabled(ScanOptions.defaults());
    }

    protected static String render(Reporter reporter) {
        StringWriter sw = new StringWriter();
        PrintWriter pw = new PrintWriter(sw);
        reporter.write(scanDemo(), rules(), pw);
        pw.flush();
        return sw.toString();
    }

    protected static void assertGolden(String name, String actual) throws Exception {
        Path golden = Path.of("src", "test", "resources", "golden").toAbsolutePath().resolve(name);
        if (Boolean.getBoolean("updateGoldens")) {
            Files.createDirectories(golden.getParent());
            Files.writeString(golden, actual, StandardCharsets.UTF_8);
        } else {
            if (!Files.exists(golden)) {
                throw new AssertionError("Missing golden file " + golden + " — run with -DupdateGoldens=true");
            }
            assertThat(actual).isEqualTo(Files.readString(golden, StandardCharsets.UTF_8));
        }
    }
}
