package io.sprig.cli;

/** Process exit codes. This contract is CI-facing and must stay stable. */
public final class ExitCodes {

    /** No findings at or above the fail threshold. */
    public static final int OK = 0;

    /** Findings at or above the fail threshold were found. */
    public static final int FINDINGS = 1;

    /** Operational error (bad path, unreadable file, unsupported option). */
    public static final int ERROR = 2;

    private ExitCodes() {}
}
