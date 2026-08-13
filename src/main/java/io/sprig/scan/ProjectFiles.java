package io.sprig.scan;

import java.nio.file.Path;
import java.util.List;

/** The files discovered by {@link ProjectScanner}, sorted deterministically. */
public record ProjectFiles(List<Path> javaFiles, List<Path> configFiles) {
}
