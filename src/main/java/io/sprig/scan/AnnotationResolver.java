package io.sprig.scan;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.ImportDeclaration;
import com.github.javaparser.ast.NodeList;
import com.github.javaparser.ast.expr.AnnotationExpr;
import com.github.javaparser.ast.expr.ArrayInitializerExpr;
import com.github.javaparser.ast.expr.BooleanLiteralExpr;
import com.github.javaparser.ast.expr.CharLiteralExpr;
import com.github.javaparser.ast.expr.DoubleLiteralExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.IntegerLiteralExpr;
import com.github.javaparser.ast.expr.LongLiteralExpr;
import com.github.javaparser.ast.expr.MemberValuePair;
import com.github.javaparser.ast.expr.NormalAnnotationExpr;
import com.github.javaparser.ast.expr.NullLiteralExpr;
import com.github.javaparser.ast.expr.StringLiteralExpr;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Resolves annotation fully-qualified names without a project classpath.
 *
 * <p>We deliberately never call symbol resolution ({@code expr.resolve()}):
 * it needs the project's compiled classpath, which a static linter does not
 * have. Instead, the FQN is derived from the import table:
 * <ol>
 *   <li>already fully-qualified names are matched directly;</li>
 *   <li>an explicit import whose simple name equals the annotation wins;</li>
 *   <li>a wildcard import is accepted only when it names a known Spring package.</li>
 * </ol>
 * Code that uses an annotation without importing it would not compile in a real
 * project, so skipping those is sound and kills most false positives.
 */
public final class AnnotationResolver {

    /** Simple annotation name → candidate fully-qualified names. */
    private static final Map<String, List<String>> KNOWN_FQNS = Map.ofEntries(
            Map.entry("CrossOrigin", List.of("org.springframework.web.bind.annotation.CrossOrigin")),
            Map.entry("EnableWebSecurity", List.of("org.springframework.security.config.annotation.web.configuration.EnableWebSecurity")),
            Map.entry("EnableMethodSecurity", List.of("org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity")),
            Map.entry("EnableGlobalMethodSecurity", List.of("org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity")),
            Map.entry("PreAuthorize", List.of("org.springframework.security.access.prepost.PreAuthorize")),
            Map.entry("Secured", List.of("org.springframework.security.access.annotation.Secured")),
            Map.entry("RolesAllowed", List.of("jakarta.annotation.security.RolesAllowed", "javax.annotation.security.RolesAllowed")),
            Map.entry("Configuration", List.of("org.springframework.context.annotation.Configuration")),
            Map.entry("Bean", List.of("org.springframework.context.annotation.Bean")),
            Map.entry("RestController", List.of("org.springframework.web.bind.annotation.RestController")),
            Map.entry("Controller", List.of("org.springframework.stereotype.Controller")),
            Map.entry("RequestMapping", List.of("org.springframework.web.bind.annotation.RequestMapping")),
            Map.entry("GetMapping", List.of("org.springframework.web.bind.annotation.GetMapping")),
            Map.entry("PostMapping", List.of("org.springframework.web.bind.annotation.PostMapping")),
            Map.entry("PutMapping", List.of("org.springframework.web.bind.annotation.PutMapping")),
            Map.entry("DeleteMapping", List.of("org.springframework.web.bind.annotation.DeleteMapping")));

    private AnnotationResolver() {
    }

    public static Optional<String> resolveFqn(AnnotationExpr expr, CompilationUnit cu) {
        String name = expr.getName().asString();
        if (name.contains(".")) {
            return Optional.of(name);
        }

        for (ImportDeclaration imp : cu.getImports()) {
            if (imp.isAsterisk() || imp.isStatic()) {
                continue;
            }
            if (imp.getName().getIdentifier().equals(name)) {
                return Optional.of(imp.getNameAsString());
            }
        }

        for (ImportDeclaration imp : cu.getImports()) {
            if (!imp.isAsterisk() || imp.isStatic()) {
                continue;
            }
            String pkg = imp.getNameAsString();
            for (String candidate : KNOWN_FQNS.getOrDefault(name, List.of())) {
                if (candidate.substring(0, candidate.lastIndexOf('.')).equals(pkg)) {
                    return Optional.of(candidate);
                }
            }
        }

        return Optional.empty();
    }

    /** Reads a string-valued member of an annotation, e.g. {@code allowCredentials}. */
    public static Optional<String> stringArg(AnnotationExpr expr, String name) {
        for (MemberValuePair pair : pairs(expr)) {
            if (pair.getNameAsString().equals(name)) {
                return Optional.of(literalToString(pair.getValue()));
            }
        }
        return Optional.empty();
    }

    /** Reads a boolean-valued member; {@code "true"}/{@code true} → {@code true}, absent → {@code false}. */
    public static boolean boolArg(AnnotationExpr expr, String name) {
        return stringArg(expr, name).map(s -> Boolean.parseBoolean(s.trim())).orElse(false);
    }

    /** Reads a string-array member (or single string) such as {@code origins}. */
    public static List<String> stringListArg(AnnotationExpr expr, String name) {
        for (MemberValuePair pair : pairs(expr)) {
            if (pair.getNameAsString().equals(name)) {
                Expression value = pair.getValue();
                if (value instanceof ArrayInitializerExpr array) {
                    return array.getValues().stream().map(AnnotationResolver::literalToString).toList();
                }
                return List.of(literalToString(value));
            }
        }
        return List.of();
    }

    private static List<MemberValuePair> pairs(AnnotationExpr expr) {
        if (expr instanceof NormalAnnotationExpr normal) {
            NodeList<MemberValuePair> pairs = normal.getPairs();
            return pairs == null ? List.of() : List.copyOf(pairs);
        }
        return List.of();
    }

    static String literalToString(Expression e) {
        if (e instanceof StringLiteralExpr s) {
            return s.asString();
        }
        if (e instanceof BooleanLiteralExpr b) {
            return String.valueOf(b.getValue());
        }
        if (e instanceof CharLiteralExpr c) {
            return String.valueOf(c.getValue());
        }
        if (e instanceof IntegerLiteralExpr i) {
            return i.asNumber().toString();
        }
        if (e instanceof LongLiteralExpr l) {
            return l.asNumber().toString();
        }
        if (e instanceof DoubleLiteralExpr d) {
            return String.valueOf(d.asDouble());
        }
        if (e instanceof NullLiteralExpr) {
            return "null";
        }
        return e.toString();
    }
}
