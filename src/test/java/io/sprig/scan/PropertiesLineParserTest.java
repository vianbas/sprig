package io.sprig.scan;

import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class PropertiesLineParserTest {

    @Test
    void parsesKeyValuePairsWithLineNumbers() {
        String props = "server.port = 8080\nspring.datasource.url=jdbc:mysql://localhost:3306/db\n";
        Map<String, ConfigEntry> map = PropertiesLineParser.parseContent(props, Path.of("application.properties"));

        assertThat(map.get("server.port").asString()).isEqualTo("8080");
        assertThat(map.get("server.port").line()).isEqualTo(1);
        assertThat(map.get("spring.datasource.url").asString()).isEqualTo("jdbc:mysql://localhost:3306/db");
        assertThat(map.get("spring.datasource.url").line()).isEqualTo(2);
    }

    @Test
    void handlesContinuationLines() {
        String props = "key=part1\\\npart2\n";
        Map<String, ConfigEntry> map = PropertiesLineParser.parseContent(props, Path.of("a.properties"));
        assertThat(map.get("key").asString()).isEqualTo("part1part2");
        assertThat(map.get("key").line()).isEqualTo(1);
    }

    @Test
    void skipsCommentsAndBlanks() {
        String props = "# comment\n\n! another\nserver.port=8080\n";
        Map<String, ConfigEntry> map = PropertiesLineParser.parseContent(props, Path.of("a.properties"));
        assertThat(map).containsOnlyKeys("server.port");
    }

    @Test
    void unescapesDelimitersInKeys() {
        String props = "my\\:key=value\n";
        Map<String, ConfigEntry> map = PropertiesLineParser.parseContent(props, Path.of("a.properties"));
        assertThat(map.get("my:key").asString()).isEqualTo("value");
    }
}
