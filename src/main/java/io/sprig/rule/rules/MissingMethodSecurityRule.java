package io.sprig.rule.rules;

import io.sprig.model.FindingCollector;
import io.sprig.model.Severity;
import io.sprig.rule.Rule;
import io.sprig.rule.RuleContext;
import io.sprig.rule.RuleKind;
import io.sprig.scan.SpringContext;

import java.util.Set;

/**
 * SPR-SRC-004 — {@code @EnableWebSecurity} is used together with method
 * security annotations ({@code @PreAuthorize}, {@code @Secured},
 * {@code @RolesAllowed}) but method security is never enabled via
 * {@code @EnableMethodSecurity} (or the legacy
 * {@code @EnableGlobalMethodSecurity}). The annotations are silently ignored,
 * so the authorization checks they promise never run.
 */
public final class MissingMethodSecurityRule implements Rule {

    private static final String ENABLE_WEB_SECURITY = "org.springframework.security.config.annotation.web.configuration.EnableWebSecurity";
    private static final String ENABLE_METHOD_SECURITY = "org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity";
    private static final String ENABLE_GLOBAL_METHOD_SECURITY = "org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity";
    private static final String PRE_AUTHORIZE = "org.springframework.security.access.prepost.PreAuthorize";
    private static final String SECURED = "org.springframework.security.access.annotation.Secured";
    private static final String ROLES_ALLOWED_JAKARTA = "jakarta.annotation.security.RolesAllowed";
    private static final String ROLES_ALLOWED_JAVAX = "javax.annotation.security.RolesAllowed";

    @Override
    public String id() {
        return "SPR-SRC-004";
    }

    @Override
    public String name() {
        return "missing-method-security";
    }

    @Override
    public String description() {
        return "@EnableWebSecurity without @EnableMethodSecurity: method security annotations such as @PreAuthorize are not enforced.";
    }

    @Override
    public String remediation() {
        return "Add @EnableMethodSecurity (or @EnableGlobalMethodSecurity) to a @Configuration class to activate method-level authorization.";
    }

    @Override
    public Severity severity() {
        return Severity.MEDIUM;
    }

    @Override
    public Set<String> tags() {
        return Set.of("auth", "source");
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
        SpringContext spring = ctx.spring();
        boolean usesMethodAnnotations = spring.usesAnnotation(PRE_AUTHORIZE)
                || spring.usesAnnotation(SECURED)
                || spring.usesAnnotation(ROLES_ALLOWED_JAKARTA)
                || spring.usesAnnotation(ROLES_ALLOWED_JAVAX);
        boolean methodSecurityEnabled = spring.usesAnnotation(ENABLE_METHOD_SECURITY)
                || spring.usesAnnotation(ENABLE_GLOBAL_METHOD_SECURITY);
        if (!usesMethodAnnotations || methodSecurityEnabled) {
            return;
        }
        for (SpringContext.ResolvedAnnotation anno : spring.findAnnotations(ENABLE_WEB_SECURITY)) {
            findings.add(this, anno.file(), anno.line(),
                    "@EnableWebSecurity without @EnableMethodSecurity: @PreAuthorize/@Secured method annotations are not enforced.", "");
        }
    }
}
