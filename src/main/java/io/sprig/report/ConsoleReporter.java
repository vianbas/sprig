package io.sprig.report;

import io.sprig.model.Finding;
import io.sprig.model.ScanResult;
import io.sprig.model.Severity;
import io.sprig.rule.Rule;
import java.io.PrintWriter;
import java.util.List;

/**
 * Human-readable terminal reporter. Colors are disabled when not attached to a TTY or NO_COLOR is
 * set.
 */
public final class ConsoleReporter implements Reporter {

    private static final String RESET = "[0m";

    private final boolean quiet;

    public ConsoleReporter(boolean quiet) {
        this.quiet = quiet;
    }

    @Override
    public void write(ScanResult result, List<Rule> rules, PrintWriter out) {
        boolean color = colorEnabled();
        if (!quiet) {
            for (Finding f : result.findings()) {
                out.println(format(f, color));
            }
            if (!result.findings().isEmpty()) {
                out.println();
            }
        }
        out.println(summary(result));
    }

    private static String format(Finding f, boolean color) {
        StringBuilder sb = new StringBuilder();
        sb.append(f.ruleId()).append(' ');
        if (color) {
            sb.append(colorize(f.severity()));
        }
        sb.append('[').append(f.severity().name()).append(']');
        if (color) {
            sb.append(RESET);
        }
        sb.append(' ').append(f.file()).append(':').append(f.line());
        sb.append("  ").append(f.message());
        return sb.toString();
    }

    private static String summary(ScanResult r) {
        StringBuilder sb = new StringBuilder();
        sb.append("Checked ")
                .append(r.javaFiles())
                .append(" Java file(s), ")
                .append(r.configFiles())
                .append(" config file(s) in ")
                .append(r.durationMs())
                .append(" ms. Found ")
                .append(r.findings().size())
                .append(" finding(s)");
        for (Severity s : Severity.values()) {
            long n = r.countBy(s);
            if (n > 0) {
                sb.append(", ").append(n).append(' ').append(s.label());
            }
        }
        sb.append('.');
        return sb.toString();
    }

    private static boolean colorEnabled() {
        return System.console() != null && System.getenv("NO_COLOR") == null;
    }

    private static String colorize(Severity s) {
        return switch (s) {
            case CRITICAL, HIGH -> "[31m"; // red
            case MEDIUM -> "[33m"; // yellow
            case LOW -> "[36m"; // cyan
            case INFO -> "[32m"; // green
        };
    }
}
