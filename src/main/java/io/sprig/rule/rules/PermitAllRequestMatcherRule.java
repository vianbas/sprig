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
 * SPR-SRC-003 — a {@code SecurityFilterChain} calls {@code anyRequest().permitAll()} while no
 * authentication mechanism is configured. Every endpoint becomes public. The {@code .anyRequest()}
 * scope is required so path-scoped {@code requestMatchers(...).permitAll()} is not flagged.
 */
public final class PermitAllRequestMatcherRule implements Rule {

    private static final Set<String> AUTH_MECHANISMS =
            Set.of(
                    "httpBasic",
                    "formLogin",
                    "oauth2Login",
                    "oauth2ResourceServer",
                    "saml2Login",
                    "openidLogin",
                    "rememberMe",
                    "jwt",
                    "addFilter",
                    "addFilterBefore",
                    "addFilterAfter",
                    "addFilterAt",
                    "authenticationProvider",
                    "userDetailsService");

    @Override
    public String id() {
        return "SPR-SRC-003";
    }

    @Override
    public String name() {
        return "permit-all-request-matcher";
    }

    @Override
    public String description() {
        return "SecurityFilterChain permits every request via anyRequest().permitAll() with no authentication mechanism.";
    }

    @Override
    public String remediation() {
        return "Replace .anyRequest().permitAll() with .anyRequest().authenticated() (or a role-based rule) and add an authentication mechanism such as httpBasic, formLogin, or oauth2ResourceServer.";
    }

    @Override
    public Severity severity() {
        return Severity.HIGH;
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
        for (SpringContext.MethodDecl m : ctx.spring().methodsReturning("SecurityFilterChain")) {
            if (m.body().isEmpty()) {
                continue;
            }
            CallChain chain = CallChain.of(m.body().get());
            boolean permitAll = chain.hasCallOn("permitAll", "anyRequest");
            boolean authenticated = chain.hasCallOn("authenticated", "anyRequest");
            if (permitAll && !authenticated && !chain.containsAny(AUTH_MECHANISMS)) {
                findings.add(
                        this,
                        m.file(),
                        m.line(),
                        "SecurityFilterChain permits every request via .anyRequest().permitAll() with no authentication mechanism.",
                        "");
            }
        }
    }
}
