package io.sprig.report;

/** Supported report output formats. */
public enum ReportFormat {
    /** ANSI-colored, human-readable terminal output. */
    CONSOLE,
    /** Machine-readable JSON. */
    JSON,
    /** SARIF 2.1.0, for GitHub code scanning / CI. */
    SARIF
}
