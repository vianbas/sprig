package io.sprig.scan;

import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class YamlNodeVisitorTest {

    @Test
    void flattensNestedMappingsWithLineNumbers() {
        String yaml = "spring:\n  datasource:\n    url: jdbc:postgresql://localhost\n    password: secret\n";
        Map<String, ConfigEntry> map = YamlNodeVisitor.parseContent(yaml, Path.of("application.yml"));

        ConfigEntry url = map.get("spring.datasource.url");
        assertThat(url).isNotNull();
        assertThat(url.asString()).isEqualTo("jdbc:postgresql://localhost");
        assertThat(url.line()).isEqualTo(3);

        ConfigEntry password = map.get("spring.datasource.password");
        assertThat(password.asString()).isEqualTo("secret");
        assertThat(password.line()).isEqualTo(4);
    }

    @Test
    void preservesBooleanAndQuotedValuesAsStrings() {
        Map<String, ConfigEntry> map = YamlNodeVisitor.parseContent("flag: true\nflag2: \"false\"\n", Path.of("a.yml"));
        assertThat(map.get("flag").asString()).isEqualTo("true");
        assertThat(map.get("flag2").asString()).isEqualTo("false");
    }

    @Test
    void flattensSequencesIntoCommaJoinedString() {
        Map<String, ConfigEntry> map = YamlNodeVisitor.parseContent("include:\n  - \"*\"\n  - health\n", Path.of("a.yml"));
        ConfigEntry include = map.get("include");
        assertThat(include).isNotNull();
        assertThat(include.asString()).isEqualTo("*,health");
    }

    @Test
    void keepsPlaceholdersAsIs() {
        Map<String, ConfigEntry> map = YamlNodeVisitor.parseContent("password: ${DB_PASSWORD}\n", Path.of("a.yml"));
        assertThat(map.get("password").asString()).isEqualTo("${DB_PASSWORD}");
        assertThat(map.get("password").isPlaceholder()).isTrue();
    }

    @Test
    void handlesEmptyValues() {
        Map<String, ConfigEntry> map = YamlNodeVisitor.parseContent("key:\n", Path.of("a.yml"));
        assertThat(map.get("key").asString()).isEmpty();
    }
}
