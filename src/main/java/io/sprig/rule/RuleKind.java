package io.sprig.rule;

/** What a rule inspects. */
public enum RuleKind {
    /** Analyzes Java source code (annotations, method chains, types). */
    SOURCE,
    /** Analyzes Spring configuration files (application.yml / application.properties). */
    CONFIG,
    /** Inspects both. */
    HYBRID
}
