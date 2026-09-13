package io.sprig.scan;

import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.expr.ConditionalExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.LambdaExpr;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.NameExpr;
import com.github.javaparser.ast.stmt.BlockStmt;
import com.github.javaparser.ast.stmt.IfStmt;
import com.github.javaparser.ast.stmt.SwitchEntry;
import java.util.List;
import java.util.Set;

/**
 * A lightweight view over the method-call chains in a method body, used by rules that reason about
 * {@code SecurityFilterChain} and {@code SecurityWebFilterChain} configuration lambdas.
 */
public final class CallChain {

    private final BlockStmt body;
    private final List<MethodCallExpr> calls;

    private CallChain(BlockStmt body) {
        this.body = body;
        this.calls = body.findAll(MethodCallExpr.class);
    }

    public static CallChain of(BlockStmt body) {
        return new CallChain(body);
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
     *
     * <p>A {@code disable()} that runs only inside an {@code if}, a ternary or a {@code switch}
     * case is not reported: frame options stay on until that condition holds, so reporting it would
     * claim the header is gone from an app that may send it by default.
     */
    public boolean disableCalledOnFrameOptions() {
        for (MethodCallExpr call : calls) {
            if ("disable".equals(call.getNameAsString())
                    && scopeChainContainsCall(call, "frameOptions")
                    && !isConditional(call)) {
                return true;
            }
        }
        for (MethodCallExpr call : calls) {
            if (!"frameOptions".equals(call.getNameAsString())) {
                continue;
            }
            for (Expression arg : call.getArguments()) {
                if (arg instanceof LambdaExpr lambda
                        && lambdaCallsUnconditionally(lambda, "disable")) {
                    return true;
                }
            }
        }
        return false;
    }

    private boolean lambdaCallsUnconditionally(LambdaExpr lambda, String name) {
        return lambda.getBody() != null
                && lambda.getBody().findAll(MethodCallExpr.class).stream()
                        .anyMatch(c -> c.getNameAsString().equals(name) && !isConditional(c));
    }

    /** Whether a branch sits between {@code node} and the method body it was found in. */
    private boolean isConditional(Node node) {
        Node current = node.getParentNode().orElse(null);
        while (current != null && current != body) {
            if (current instanceof IfStmt
                    || current instanceof ConditionalExpr
                    || current instanceof SwitchEntry) {
                return true;
            }
            current = current.getParentNode().orElse(null);
        }
        return false;
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
