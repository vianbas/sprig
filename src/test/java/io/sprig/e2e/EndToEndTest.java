package io.sprig.e2e;

import static org.assertj.core.api.Assertions.assertThat;

import io.sprig.cli.Cli;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** End-to-end: invoke the real CLI (in-process) and assert exit codes and output. */
class EndToEndTest {

    private static Path fixture(String name) {
        return Path.of("src", "test", "resources", "fixtures").toAbsolutePath().resolve(name);
    }

    private static Result run(String... args) {
        ByteArrayOutputStream outBuffer = new ByteArrayOutputStream();
        ByteArrayOutputStream errBuffer = new ByteArrayOutputStream();
        PrintStream originalOut = System.out;
        PrintStream originalErr = System.err;
        System.setOut(new PrintStream(outBuffer, true, StandardCharsets.UTF_8));
        System.setErr(new PrintStream(errBuffer, true, StandardCharsets.UTF_8));
        try {
            int code = Cli.commandLine().execute(args);
            return new Result(
                    code,
                    outBuffer.toString(StandardCharsets.UTF_8),
                    errBuffer.toString(StandardCharsets.UTF_8));
        } finally {
            System.setOut(originalOut);
            System.setErr(originalErr);
        }
    }

    @Test
    void demoAppExitsOneAndReportsAllRules() {
        Result r = run("scan", fixture("demo-app").toString());
        assertThat(r.code()).isEqualTo(1);
        for (String id :
                Set.of(
                        "SPR-CONFIG-001",
                        "SPR-CONFIG-002",
                        "SPR-CONFIG-003",
                        "SPR-CONFIG-004",
                        "SPR-CONFIG-005",
                        "SPR-CORS-001",
                        "SPR-SRC-002",
                        "SPR-SRC-003",
                        "SPR-SRC-004",
                        "SPR-SRC-005")) {
            assertThat(r.out()).contains(id);
        }
    }

    @Test
    void secureAppExitsZero() {
        assertThat(run("scan", fixture("secure-app").toString()).code()).isZero();
    }

    @Test
    void failOnThresholdControlsExitCode() {
        Path demo = fixture("demo-app");
        assertThat(run("scan", demo.toString(), "--fail-on", "CRITICAL").code()).isZero();
        assertThat(run("scan", demo.toString(), "--fail-on", "LOW").code()).isEqualTo(1);
    }

    @Test
    void nonexistentTargetExitsTwo() {
        assertThat(run("scan", "does/not/exist").code()).isEqualTo(2);
    }

    @Test
    void writesSarifReportFile(@TempDir Path tmp) throws Exception {
        Path out = tmp.resolve("out.sarif");
        Result r =
                run(
                        "scan",
                        fixture("demo-app").toString(),
                        "--output",
                        "sarif",
                        "--output-file",
                        out.toString());
        assertThat(r.code()).isEqualTo(1);
        String content = Files.readString(out);
        assertThat(content).contains("\"version\" : \"2.1.0\"");
        assertThat(content).contains("\"runs\"");
    }

    @Test
    void excludeRuleRemovesItsFindings() {
        Result r = run("scan", fixture("demo-app").toString(), "--exclude-rule", "SPR-CONFIG-002");
        assertThat(r.out()).doesNotContain("SPR-CONFIG-002");
        assertThat(r.out()).contains("SPR-CORS-001");
    }

    @Test
    void versionAndListRulesWork() {
        assertThat(run("version").out()).startsWith("sprig ");
        assertThat(run("list-rules").out()).contains("SPR-CORS-001");
    }

    @Test
    void severityOverrideViaConfigChangesExitCode(@TempDir Path tmp) throws Exception {
        Path cfg = tmp.resolve("sprig.yml");
        Files.writeString(cfg, "rules:\n  SPR-CONFIG-005:\n    severity: critical\n");
        // SPR-CONFIG-005 is LOW in demo-app; overridden to CRITICAL, so --fail-on CRITICAL now
        // trips.
        Result r =
                run(
                        "scan",
                        fixture("demo-app").toString(),
                        "--config",
                        cfg.toString(),
                        "--fail-on",
                        "CRITICAL");
        assertThat(r.code()).isEqualTo(1);
    }

    private record Result(int code, String out, String err) {}
}
