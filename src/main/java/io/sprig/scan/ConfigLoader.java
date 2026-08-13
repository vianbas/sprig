package io.sprig.scan;

import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.yaml.snakeyaml.error.YAMLException;

/** Loads all discovered configuration files into a per-file {@link ConfigModel}. */
public final class ConfigLoader {

    private ConfigLoader() {}

    public static ConfigModel load(List<Path> files) {
        Map<Path, Map<String, ConfigEntry>> perFile = new LinkedHashMap<>();
        for (Path file : files) {
            try {
                Map<String, ConfigEntry> entries = parse(file);
                if (!entries.isEmpty()) {
                    perFile.put(file, entries);
                }
            } catch (YAMLException e) {
                // Malformed YAML: skip the file. A misconfigured app would not boot anyway.
            }
        }
        return new ConfigModel(perFile);
    }

    private static Map<String, ConfigEntry> parse(Path file) {
        String name = file.getFileName().toString();
        if (name.endsWith(".properties")) {
            return PropertiesLineParser.parse(file);
        }
        return YamlNodeVisitor.parse(file);
    }
}
