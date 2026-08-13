package io.sprig.model;

/**
 * Severity of a security finding. The ordinal is used as the ranking so that {@code
 * isAtLeast(other)} works as expected.
 */
public enum Severity {
    INFO,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL;

    /** Whether this severity is at least as severe as {@code other}. */
    public boolean isAtLeast(Severity other) {
        return this.ordinal() >= other.ordinal();
    }

    /** A lowercase label used in reports. */
    public String label() {
        return name().toLowerCase();
    }
}
