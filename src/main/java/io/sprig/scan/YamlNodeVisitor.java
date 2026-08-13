package io.sprig.scan;

import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.error.Mark;
import org.yaml.snakeyaml.nodes.MappingNode;
import org.yaml.snakeyaml.nodes.Node;
import org.yaml.snakeyaml.nodes.NodeTuple;
import org.yaml.snakeyaml.nodes.ScalarNode;
import org.yaml.snakeyaml.nodes.SequenceNode;

/**
 * Flattens a YAML configuration file into dotted keys while preserving accurate source lines. Uses
 * SnakeYAML's low-level {@link Yaml#composeAll} node API (not the bean mapping) so every entry
 * carries its physical line.
 */
public final class YamlNodeVisitor {

    /** Upper bound on input code points, guards against YAML-bomb expansion. */
    private static final int CODE_POINT_LIMIT = 10_000_000;

    private YamlNodeVisitor() {}

    public static Map<String, ConfigEntry> parse(Path file) {
        try (Reader reader = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
            return parseContent(reader, file);
        } catch (IOException e) {
            throw new ScanException("Failed to read " + file + ": " + e.getMessage(), e);
        }
    }

    public static Map<String, ConfigEntry> parseContent(String content, Path source) {
        return parseContent(new StringReader(content), source);
    }

    private static Map<String, ConfigEntry> parseContent(Reader reader, Path source) {
        LoaderOptions options = new LoaderOptions();
        options.setCodePointLimit(CODE_POINT_LIMIT);

        Map<String, ConfigEntry> out = new LinkedHashMap<>();
        Yaml yaml = new Yaml(options);
        for (Node document : yaml.composeAll(reader)) {
            if (document instanceof MappingNode mapping) {
                walkMapping(mapping, "", out, source);
            }
        }
        return out;
    }

    private static void walkMapping(
            MappingNode mapping, String prefix, Map<String, ConfigEntry> out, Path source) {
        for (NodeTuple tuple : mapping.getValue()) {
            String key = keyScalar(tuple.getKeyNode());
            if (key == null) {
                continue;
            }
            String fullKey = prefix.isEmpty() ? key : prefix + "." + key;
            walkValue(tuple.getValueNode(), fullKey, out, source);
        }
    }

    private static void walkValue(
            Node valueNode, String fullKey, Map<String, ConfigEntry> out, Path source) {
        if (valueNode instanceof MappingNode nested) {
            walkMapping(nested, fullKey, out, source);
        } else if (valueNode instanceof SequenceNode sequence) {
            List<String> items = new ArrayList<>();
            for (Node item : sequence.getValue()) {
                if (item instanceof ScalarNode scalar) {
                    String value = scalar.getValue();
                    items.add(value == null ? "" : value);
                }
            }
            out.put(
                    fullKey,
                    new ConfigEntry(
                            fullKey, items, String.join(",", items), source, lineOf(sequence)));
        } else if (valueNode instanceof ScalarNode scalar) {
            String value = scalar.getValue();
            String asString = value == null ? "" : value;
            out.put(fullKey, new ConfigEntry(fullKey, value, asString, source, lineOf(scalar)));
        }
    }

    private static String keyScalar(Node node) {
        if (node instanceof ScalarNode scalar) {
            return scalar.getValue();
        }
        return null;
    }

    private static int lineOf(Node node) {
        Mark mark = node.getStartMark();
        return mark != null ? mark.getLine() + 1 : 0;
    }
}
