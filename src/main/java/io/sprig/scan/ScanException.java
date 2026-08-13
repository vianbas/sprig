package io.sprig.scan;

/** A fatal, user-facing error during a scan (bad path, unreadable file, ...). */
public final class ScanException extends RuntimeException {

    public ScanException(String message) {
        super(message);
    }

    public ScanException(String message, Throwable cause) {
        super(message, cause);
    }
}
