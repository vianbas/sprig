package io.sprig.rule;

import io.sprig.model.FindingCollector;
import io.sprig.model.Severity;

import java.util.Set;

/**
 * Presents a rule with its {@code sprig.yml}-overridden severity instead of
 * its compiled-in default. Used to build the rule list handed to reporters
 * (e.g. the SARIF rule catalog's {@code security-severity}) so it matches
 * the severity actually used for findings, which {@link
 * io.sprig.scan.ScanEngine} computes separately per finding.
 *
 * <p>Not used to run {@link #analyze}: rule implementations report findings
 * via {@code findings.add(this, ...)}, so wrapping a rule does not change
 * the severity its own findings are collected with.
 */
public final class SeverityOverriddenRule implements Rule {

    private final Rule delegate;
    private final Severity severity;

    public SeverityOverriddenRule(Rule delegate, Severity severity) {
        this.delegate = delegate;
        this.severity = severity;
    }

    @Override
    public String id() {
        return delegate.id();
    }

    @Override
    public String name() {
        return delegate.name();
    }

    @Override
    public String description() {
        return delegate.description();
    }

    @Override
    public String remediation() {
        return delegate.remediation();
    }

    @Override
    public Severity severity() {
        return severity;
    }

    @Override
    public Set<String> tags() {
        return delegate.tags();
    }

    @Override
    public RuleKind kind() {
        return delegate.kind();
    }

    @Override
    public boolean appliesTo(RuleContext ctx) {
        return delegate.appliesTo(ctx);
    }

    @Override
    public void analyze(RuleContext ctx, FindingCollector findings) {
        delegate.analyze(ctx, findings);
    }
}
