package io.sprig.scan;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.NodeList;
import com.github.javaparser.ast.body.BodyDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.TypeDeclaration;
import com.github.javaparser.ast.expr.AnnotationExpr;
import com.github.javaparser.ast.stmt.BlockStmt;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The aggregated, cross-file model of all parsed Java sources. Rules read this rather than parsing
 * files themselves; {@link #units()} additionally exposes the raw ASTs for expression-level rules.
 */
public final class SpringContext {

    public record ResolvedAnnotation(String fqn, AnnotationExpr expr, Path file, int line) {}

    public record MethodDecl(
            String name,
            String returnTypeSimple,
            Path file,
            int line,
            List<ResolvedAnnotation> annotations,
            Optional<BlockStmt> body) {}

    public record ParsedClass(
            String packageName,
            String simpleName,
            String fqn,
            Path sourceFile,
            List<ResolvedAnnotation> classAnnotations,
            List<MethodDecl> methods) {}

    private final Map<Path, CompilationUnit> units;
    private final List<ParsedClass> classes;
    private final List<ResolvedAnnotation> annotations;
    private final int skippedFiles;

    private SpringContext(
            Map<Path, CompilationUnit> units,
            List<ParsedClass> classes,
            List<ResolvedAnnotation> annotations,
            int skippedFiles) {
        this.units = units;
        this.classes = classes;
        this.annotations = annotations;
        this.skippedFiles = skippedFiles;
    }

    public static SpringContext build(Map<Path, CompilationUnit> units, int skippedFiles) {
        List<ParsedClass> classes = new ArrayList<>();
        List<ResolvedAnnotation> annotations = new ArrayList<>();
        for (Map.Entry<Path, CompilationUnit> entry : units.entrySet()) {
            Path file = entry.getKey();
            CompilationUnit cu = entry.getValue();
            for (TypeDeclaration<?> td : topAndNestedTypes(cu)) {
                ParsedClass pc = toParsedClass(td, cu, file);
                classes.add(pc);
                annotations.addAll(pc.classAnnotations());
                for (MethodDecl m : pc.methods()) {
                    annotations.addAll(m.annotations());
                }
            }
        }
        return new SpringContext(units, classes, annotations, skippedFiles);
    }

    /** Raw parsed ASTs, keyed by source file. */
    public Map<Path, CompilationUnit> units() {
        return units;
    }

    public List<ParsedClass> classes() {
        return List.copyOf(classes);
    }

    public List<ResolvedAnnotation> annotations() {
        return List.copyOf(annotations);
    }

    public int skippedFiles() {
        return skippedFiles;
    }

    public boolean isSpringProject() {
        return !annotations.isEmpty()
                || classes.stream()
                        .anyMatch(
                                c ->
                                        c.methods().stream()
                                                .anyMatch(
                                                        m ->
                                                                "SecurityFilterChain"
                                                                        .equals(
                                                                                m
                                                                                        .returnTypeSimple())));
    }

    public boolean usesAnnotation(String fqn) {
        return annotations.stream().anyMatch(a -> a.fqn().equals(fqn));
    }

    public List<ResolvedAnnotation> findAnnotations(String fqn) {
        return annotations.stream().filter(a -> a.fqn().equals(fqn)).toList();
    }

    public List<MethodDecl> methodsReturning(String simpleName) {
        return classes.stream()
                .flatMap(c -> c.methods().stream())
                .filter(m -> m.returnTypeSimple().equals(simpleName))
                .toList();
    }

    private static List<TypeDeclaration<?>> topAndNestedTypes(CompilationUnit cu) {
        List<TypeDeclaration<?>> out = new ArrayList<>();
        for (TypeDeclaration<?> td : cu.getTypes()) {
            collectTypes(td, out);
        }
        return out;
    }

    private static void collectTypes(TypeDeclaration<?> td, List<TypeDeclaration<?>> out) {
        out.add(td);
        for (BodyDeclaration<?> member : td.getMembers()) {
            if (member instanceof TypeDeclaration<?> nested) {
                collectTypes(nested, out);
            }
        }
    }

    private static ParsedClass toParsedClass(TypeDeclaration<?> td, CompilationUnit cu, Path file) {
        String pkg = cu.getPackageDeclaration().map(pd -> pd.getNameAsString()).orElse("");
        String simple = td.getNameAsString();
        String fqn = pkg.isEmpty() ? simple : pkg + "." + simple;
        List<ResolvedAnnotation> classAnnos = resolveAll(td.getAnnotations(), cu, file);
        List<MethodDecl> methods =
                td.getMethods().stream().map(m -> toMethodDecl(m, cu, file)).toList();
        return new ParsedClass(pkg, simple, fqn, file, classAnnos, methods);
    }

    private static MethodDecl toMethodDecl(MethodDeclaration m, CompilationUnit cu, Path file) {
        List<ResolvedAnnotation> annos = resolveAll(m.getAnnotations(), cu, file);
        int line = m.getBegin().map(pos -> pos.line).orElse(0);
        return new MethodDecl(
                m.getNameAsString(), m.getType().asString(), file, line, annos, m.getBody());
    }

    private static List<ResolvedAnnotation> resolveAll(
            NodeList<AnnotationExpr> annos, CompilationUnit cu, Path file) {
        List<ResolvedAnnotation> out = new ArrayList<>();
        for (AnnotationExpr a : annos) {
            AnnotationResolver.resolveFqn(a, cu)
                    .ifPresent(
                            fqn -> {
                                int line = a.getBegin().map(pos -> pos.line).orElse(0);
                                out.add(new ResolvedAnnotation(fqn, a, file, line));
                            });
        }
        return List.copyOf(out);
    }
}
