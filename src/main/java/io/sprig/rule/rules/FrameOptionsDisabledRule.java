package io.sprig.rule.rules;

import io.sprig.model.FindingCollector;
import io.sprig.model.Severity;
import io.sprig.rule.Rule;
import io.sprig.rule.RuleContext;
import io.sprig.rule.RuleKind;
import io.sprig.scan.CallChain;
import io.sprig.scan.SpringContext;
import java.util.Set;

/**
 * SPR-SRC-005 — {@code headers().frameOptions().disable()} removes clickjacking protection (the
 * X-Frame-Options header). Handles both the direct style and the Boot 3 lambda style.
 */
public final class FrameOptionsDisabledRule implements Rule {

    @Override
    public String id() {
        return "SPR-SRC-005";
    }

    @Override
    public String name() {
        return "frame-options-disabled";
    }

    @Override
    public String description() {
        return "headers().frameOptions() is disabled, removing clickjacking protection.";
    }

    @Override
    public String remediation() {
        return "Keep frameOptions() at its default (DENY) or set SAMEORIGIN if the app must be framed by itself.";
    }

    @Override
    public Severity severity() {
        return Severity.MEDIUM;
    }

    @Override
    public Set<String> tags() {
        return Set.of("headers", "clickjacking", "source");
    }

    @Override
    public RuleKind kind() {
        return RuleKind.SOURCE;
    }

    @Override
    public boolean appliesTo(RuleContext ctx) {
        return ctx.spring() != null;
    }

    @Override
    public void analyze(RuleContext ctx, FindingCollector findings) {
        for (SpringContext.MethodDecl m : ctx.spring().methodsReturning("SecurityFilterChain")) {
            if (m.body().isEmpty()) {
                continue;
            }
            if (CallChain.of(m.body().get()).disableCalledOnFrameOptions()) {
                findings.add(
                        this,
                        m.file(),
                        m.line(),
                        "headers().frameOptions() is disabled: clickjacking protection removed.",
                        "");
            }
        }
    }
}
