package io.sprig.rule.rules;

import com.github.javaparser.ast.expr.AnnotationExpr;
import io.sprig.model.FindingCollector;
import io.sprig.model.Severity;
import io.sprig.rule.Rule;
import io.sprig.rule.RuleContext;
import io.sprig.rule.RuleKind;
import io.sprig.scan.AnnotationResolver;
import io.sprig.scan.SpringContext;
import java.util.List;
import java.util.Set;

/**
 * SPR-CORS-001 — {@code @CrossOrigin(origins="*")} combined with {@code allowCredentials=true}. Per
 * Spring's own guidance, wildcard origins must never be combined with credentials: the browser
 * would accept requests from any origin while cookies are sent, enabling credential theft.
 */
public final class CorsWildcardCredentialsRule implements Rule {

    private static final String CROSS_ORIGIN =
            "org.springframework.web.bind.annotation.CrossOrigin";

    @Override
    public String id() {
        return "SPR-CORS-001";
    }

    @Override
    public String name() {
        return "cors-wildcard-credentials";
    }

    @Override
    public String description() {
        return "@CrossOrigin with origins=\"*\" and allowCredentials=\"true\" allows any origin to send credentialed requests.";
    }

    @Override
    public String remediation() {
        return "Restrict origins to an explicit allowlist (never '*') and keep allowCredentials=true only with specific origins.";
    }

    @Override
    public Severity severity() {
        return Severity.HIGH;
    }

    @Override
    public Set<String> tags() {
        return Set.of("cors", "source");
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
        for (SpringContext.ResolvedAnnotation anno : ctx.spring().findAnnotations(CROSS_ORIGIN)) {
            AnnotationExpr expr = anno.expr();
            List<String> origins = AnnotationResolver.stringListArg(expr, "origins");
            List<String> originPatterns = AnnotationResolver.stringListArg(expr, "originPatterns");
            boolean credentials = AnnotationResolver.boolArg(expr, "allowCredentials");
            boolean explicitWildcard = origins.contains("*");
            // Spring's own default: if neither origins nor originPatterns is set, all
            // origins are allowed (see CrossOrigin javadoc). originPatterns() being set
            // overrides that default, so it must be absent too for the implicit case.
            boolean implicitWildcard = origins.isEmpty() && originPatterns.isEmpty();
            if ((explicitWildcard || implicitWildcard) && credentials) {
                String detail =
                        explicitWildcard
                                ? "origins=*"
                                : "no origins restriction (Spring defaults to allowing all origins)";
                findings.add(
                        this,
                        anno.file(),
                        anno.line(),
                        "Cross-origin configured with " + detail + " and allowCredentials=true.",
                        "");
            }
        }
    }
}
