package io.sprig.report;

/** A fatal error while rendering a report (e.g. writer failure). */
public final class ReportException extends RuntimeException {

    public ReportException(String message) {
        super(message);
    }

    public ReportException(String message, Throwable cause) {
        super(message, cause);
    }
}
