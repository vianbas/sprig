package io.sprig.scan;

import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Flattened, per-file configuration model. Base and profile files are kept
 * separate (never merged) so every finding points at the exact file and line
 * that contains the misconfiguration.
 */
public final class ConfigModel {

    private static final ConfigModel EMPTY = new ConfigModel(Map.of());

    private final Map<Path, Map<String, ConfigEntry>> perFile;

    public ConfigModel(Map<Path, Map<String, ConfigEntry>> perFile) {
        Map<Path, Map<String, ConfigEntry>> copy = new LinkedHashMap<>();
        perFile.forEach((path, entries) -> copy.put(path, Map.copyOf(entries)));
        this.perFile = Map.copyOf(copy);
    }

    public static ConfigModel empty() {
        return EMPTY;
    }

    public boolean isEmpty() {
        return perFile.isEmpty();
    }

    public Set<Path> files() {
        return perFile.keySet();
    }

    public Map<String, ConfigEntry> entriesFor(Path file) {
        return perFile.getOrDefault(file, Map.of());
    }

    /** All entries across all files. */
    public List<ConfigEntry> allEntries() {
        return perFile.values().stream()
                .flatMap(m -> m.values().stream())
                .collect(Collectors.toList());
    }

    /** All entries whose key exactly equals {@code key}, across all files. */
    public List<ConfigEntry> findAll(String key) {
        return perFile.values().stream()
                .map(m -> m.get(key))
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
    }

    /** The first present entry for any of {@code keys} (checked in order). */
    public List<ConfigEntry> findFirst(String... keys) {
        for (String key : keys) {
            List<ConfigEntry> entries = findAll(key);
            if (!entries.isEmpty()) {
                return entries;
            }
        }
        return List.of();
    }
}
