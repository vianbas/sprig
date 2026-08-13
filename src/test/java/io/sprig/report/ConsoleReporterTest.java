package io.sprig.report;

import io.sprig.model.Finding;
import io.sprig.model.ScanResult;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ConsoleReporterTest extends ReporterTestBase {

    @Test
    void printsEveryFindingAndSummary() {
        ScanResult result = scanDemo();
        String out = render(new ConsoleReporter(false));
        for (Finding f : result.findings()) {
            assertThat(out).contains(f.ruleId() + " [" + f.severity().name() + "]");
            assertThat(out).contains(f.file().toString() + ":" + f.line());
        }
        assertThat(out).contains("Checked 5 Java file(s), 1 config file(s)");
        assertThat(out).contains("Found 11 finding(s)");
    }

    @Test
    void quietPrintsOnlySummary() {
        String out = render(new ConsoleReporter(true));
        assertThat(out).doesNotContain("[HIGH]");
        assertThat(out).contains("Found 11 finding(s)");
    }
}
