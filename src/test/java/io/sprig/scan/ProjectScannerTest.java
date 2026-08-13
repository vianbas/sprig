package io.sprig.scan;

import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class ProjectScannerTest {

    @Test
    void recognizesConfigFileNames() {
        assertThat(ProjectScanner.isConfigFile("application.yml")).isTrue();
        assertThat(ProjectScanner.isConfigFile("application.yaml")).isTrue();
        assertThat(ProjectScanner.isConfigFile("application.properties")).isTrue();
        assertThat(ProjectScanner.isConfigFile("application-prod.properties")).isTrue();
        assertThat(ProjectScanner.isConfigFile("bootstrap.yaml")).isTrue();
        assertThat(ProjectScanner.isConfigFile("README.md")).isFalse();
        assertThat(ProjectScanner.isConfigFile("pom.xml")).isFalse();
    }

    @Test
    void discoversJavaFilesAndSkipsBuildDirs() {
        Path fixtures = Path.of("src", "test", "resources", "fixtures").toAbsolutePath();
        ProjectFiles files = ProjectScanner.discover(fixtures, List.of());
        assertThat(files.javaFiles())
                .anyMatch(p -> p.toString().endsWith("cors-misconfig/src/main/java/demo/CorsController.java"));
        assertThat(files.javaFiles())
                .anyMatch(p -> p.toString().endsWith("secure-app/src/main/java/demo/SecurityConfig.java"));
    }

    /**
     * The scan root is not always absolute — the CLI's default target is the
     * relative path "." — so exclude-path matching must be independent of
     * how the caller specified {@code root}. Regression test for a bug where
     * the pattern was matched against the raw walked path (which carries
     * whatever prefix {@code root} was given), so a natural-looking pattern
     * like "src/test/resources/fixtures/**" silently excluded nothing at all
     * when root was "." instead of an absolute path.
     */
    @Test
    void excludePathMatchesRelativeToRootRegardlessOfHowRootWasSpecified() {
        Path fixtures = Path.of("src", "test", "resources", "fixtures");
        List<String> exclude = List.of("cors-misconfig/**");

        ProjectFiles fromRelativeRoot = ProjectScanner.discover(fixtures, exclude);
        assertThat(fromRelativeRoot.javaFiles())
                .noneMatch(p -> p.toString().contains("cors-misconfig"));
        assertThat(fromRelativeRoot.javaFiles())
                .anyMatch(p -> p.toString().endsWith("secure-app/src/main/java/demo/SecurityConfig.java"));

        ProjectFiles fromAbsoluteRoot = ProjectScanner.discover(fixtures.toAbsolutePath(), exclude);
        assertThat(fromAbsoluteRoot.javaFiles())
                .noneMatch(p -> p.toString().contains("cors-misconfig"));
        assertThat(fromAbsoluteRoot.javaFiles())
                .anyMatch(p -> p.toString().endsWith("secure-app/src/main/java/demo/SecurityConfig.java"));
    }

    @Test
    void excludePathWithoutWildcardPrefixStillWorks() {
        Path fixtures = Path.of("src", "test", "resources", "fixtures").toAbsolutePath();
        ProjectFiles files = ProjectScanner.discover(fixtures, List.of("secure-app"));
        assertThat(files.javaFiles()).noneMatch(p -> p.toString().contains("secure-app"));
        assertThat(files.javaFiles())
                .anyMatch(p -> p.toString().endsWith("cors-misconfig/src/main/java/demo/CorsController.java"));
    }
}
