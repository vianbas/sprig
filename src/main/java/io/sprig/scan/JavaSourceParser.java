package io.sprig.scan;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParseResult;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ast.CompilationUnit;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Parses Java sources with a per-instance {@link JavaParser} (never the static one, whose global
 * configuration is mutable and racy). Files that fail to parse are skipped and counted — a linter
 * must never crash on a target project.
 */
public final class JavaSourceParser {

    private final JavaParser parser;

    public JavaSourceParser() {
        this.parser =
                new JavaParser(
                        new ParserConfiguration()
                                .setLanguageLevel(ParserConfiguration.LanguageLevel.JAVA_21)
                                .setCharacterEncoding(StandardCharsets.UTF_8));
    }

    public static SpringContext parseAll(List<Path> files) {
        return new JavaSourceParser().parse(files);
    }

    public SpringContext parse(List<Path> files) {
        Map<Path, CompilationUnit> units = new LinkedHashMap<>();
        int skipped = 0;
        for (Path file : files) {
            try {
                ParseResult<CompilationUnit> result = parser.parse(file);
                if (result.isSuccessful() && result.getResult().isPresent()) {
                    units.put(file, result.getResult().get());
                } else {
                    skipped++;
                }
            } catch (IOException e) {
                skipped++;
            }
        }
        return SpringContext.build(units, skipped);
    }
}
