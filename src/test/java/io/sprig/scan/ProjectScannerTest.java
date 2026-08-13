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
}
