package io.sprig.scan;

import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.LambdaExpr;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.NameExpr;
import com.github.javaparser.ast.stmt.BlockStmt;
import java.util.List;
import java.util.Set;

/**
 * A lightweight view over the method-call chains in a method body, used by rules that reason about
 * {@code SecurityFilterChain} configuration lambdas.
 */
public final class CallChain {

    private final List<MethodCallExpr> calls;

    private CallChain(List<MethodCallExpr> calls) {
        this.calls = calls;
    }

    public static CallChain of(BlockStmt body) {
        return new CallChain(body.findAll(MethodCallExpr.class));
    }

    public boolean containsName(String name) {
        return calls.stream().anyMatch(c -> c.getNameAsString().equals(name));
    }

    public boolean containsAny(Set<String> names) {
        return calls.stream().anyMatch(c -> names.contains(c.getNameAsString()));
    }

    /**
     * Whether a call named {@code name} has a scope chain that includes a call named {@code
     * scopeBase}.
     */
    public boolean hasCallOn(String name, String scopeBase) {
        for (MethodCallExpr call : calls) {
            if (call.getNameAsString().equals(name) && scopeChainContainsCall(call, scopeBase)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Detects {@code frameOptions().disable()} in the direct style ({@code
     * headers(...).frameOptions().disable()}) or the lambda style ({@code headers(h ->
     * h.frameOptions(fo -> fo.disable()))}). Scoped specifically so a plain {@code csrf(csrf ->
     * csrf.disable())} is not a false positive.
     */
    public boolean disableCalledOnFrameOptions() {
        for (MethodCallExpr call : calls) {
            if ("disable".equals(call.getNameAsString())
                    && scopeChainContainsCall(call, "frameOptions")) {
                return true;
            }
        }
        for (MethodCallExpr call : calls) {
            if (!"frameOptions".equals(call.getNameAsString())) {
                continue;
            }
            for (Expression arg : call.getArguments()) {
                if (arg instanceof LambdaExpr lambda && lambdaContainsCall(lambda, "disable")) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean lambdaContainsCall(LambdaExpr lambda, String name) {
        return lambda.getBody() != null
                && lambda.getBody().findAll(MethodCallExpr.class).stream()
                        .anyMatch(c -> c.getNameAsString().equals(name));
    }

    private static boolean scopeChainContainsCall(MethodCallExpr call, String baseName) {
        Expression scope = call.getScope().orElse(null);
        while (scope != null) {
            if (scope instanceof MethodCallExpr inner) {
                if (inner.getNameAsString().equals(baseName)) {
                    return true;
                }
                scope = inner.getScope().orElse(null);
            } else if (scope instanceof NameExpr nameExpr) {
                if (nameExpr.getNameAsString().equals(baseName)) {
                    return true;
                }
                scope = null;
            } else {
                scope = null;
            }
        }
        return false;
    }
}
