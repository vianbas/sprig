package io.sprig.rule.rules;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.github.javaparser.ast.expr.StringLiteralExpr;
import io.sprig.model.FindingCollector;
import io.sprig.model.Severity;
import io.sprig.rule.Rule;
import io.sprig.rule.RuleContext;
import io.sprig.rule.RuleKind;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * SPR-SRC-002 — use of {@code NoOpPasswordEncoder} or a {@code {noop}} password. NoOp does not hash
 * passwords: any stored password is compared as plaintext, so a database leak exposes credentials
 * directly.
 */
public final class NoOpPasswordEncoderRule implements Rule {

    @Override
    public String id() {
        return "SPR-SRC-002";
    }

    @Override
    public String name() {
        return "noop-password-encoder";
    }

    @Override
    public String description() {
        return "NoOpPasswordEncoder or a {noop} password stores passwords as plaintext.";
    }

    @Override
    public String remediation() {
        return "Use a strong hashing encoder such as BCryptPasswordEncoder (or DelegatingPasswordEncoder with bcrypt) and re-hash stored passwords.";
    }

    @Override
    public Severity severity() {
        return Severity.HIGH;
    }

    @Override
    public Set<String> tags() {
        return Set.of("auth", "password", "source");
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
        for (var entry : ctx.spring().units().entrySet()) {
            Path file = entry.getKey();
            CompilationUnit cu = entry.getValue();
            Set<Integer> lines = new LinkedHashSet<>();

            for (ObjectCreationExpr creation : cu.findAll(ObjectCreationExpr.class)) {
                if ("NoOpPasswordEncoder".equals(creation.getType().asString())) {
                    lines.add(lineOf(creation));
                }
            }
            for (MethodCallExpr call : cu.findAll(MethodCallExpr.class)) {
                if ("getInstance".equals(call.getNameAsString())
                        && call.getScope()
                                .map(s -> s.toString().endsWith("NoOpPasswordEncoder"))
                                .orElse(false)) {
                    lines.add(lineOf(call));
                }
            }
            for (MethodDeclaration method : cu.findAll(MethodDeclaration.class)) {
                if ("NoOpPasswordEncoder".equals(method.getType().asString())) {
                    lines.add(lineOf(method));
                }
            }
            for (StringLiteralExpr literal : cu.findAll(StringLiteralExpr.class)) {
                if (literal.getValue().startsWith("{noop}")) {
                    lines.add(lineOf(literal));
                }
            }

            for (int line : lines) {
                findings.add(
                        this,
                        file,
                        line,
                        "Insecure password handling: NoOpPasswordEncoder or {noop} plaintext password used.",
                        "");
            }
        }
    }

    private static int lineOf(Node node) {
        return node.getBegin().map(pos -> pos.line).orElse(0);
    }
}
