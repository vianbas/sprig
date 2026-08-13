package io.sprig.report;

/** Creates the reporter for the requested format. */
public final class ReporterFactory {

    private ReporterFactory() {
    }

    public static Reporter create(ReportFormat format, boolean quiet) {
        return switch (format) {
            case CONSOLE -> new ConsoleReporter(quiet);
            case JSON -> new JsonReporter();
            case SARIF -> new SarifReporter();
        };
    }
}
