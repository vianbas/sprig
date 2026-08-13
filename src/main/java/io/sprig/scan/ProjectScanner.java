package io.sprig.scan;

import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Set;

/**
 * Walks a project directory and collects Java sources plus Spring
 * configuration files. Directory names that are always build/ignored output
 * are skipped entirely.
 */
public final class ProjectScanner {

    private static final Set<String> SKIP_DIRS = Set.of(
            "build", "target", ".gradle", ".git", "node_modules", ".idea", "out", "bin", "dist", ".tools");

    private ProjectScanner() {
    }

    public static ProjectFiles discover(Path root, List<String> excludePaths) {
        List<Path> java = new ArrayList<>();
        List<Path> config = new ArrayList<>();
        List<PathMatcher> excludes = excludePaths.stream()
                .map(pattern -> root.getFileSystem().getPathMatcher("glob:" + pattern))
                .toList();

        try {
            Files.walkFileTree(root, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                    if (!dir.equals(root)) {
                        String name = dir.getFileName().toString();
                        if (SKIP_DIRS.contains(name) || matchesAny(excludes, dir)) {
                            return FileVisitResult.SKIP_SUBTREE;
                        }
                    }
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                    String name = file.getFileName().toString();
                    if (name.endsWith(".java")) {
                        java.add(file);
                    } else if (isConfigFile(name)) {
                        config.add(file);
                    }
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException e) {
            throw new ScanException("Failed to scan " + root + ": " + e.getMessage(), e);
        }

        java.sort(Comparator.comparing(Path::toString));
        config.sort(Comparator.comparing(Path::toString));
        return new ProjectFiles(java, config);
    }

    private static boolean matchesAny(List<PathMatcher> matchers, Path path) {
        for (PathMatcher matcher : matchers) {
            if (matcher.matches(path)) {
                return true;
            }
        }
        return false;
    }

    static boolean isConfigFile(String name) {
        if (name.equals("application.yml") || name.equals("application.yaml") || name.equals("application.properties")) {
            return true;
        }
        if (name.equals("bootstrap.yml") || name.equals("bootstrap.yaml") || name.equals("bootstrap.properties")) {
            return true;
        }
        return name.startsWith("application-")
                && (name.endsWith(".yml") || name.endsWith(".yaml") || name.endsWith(".properties"));
    }
}
