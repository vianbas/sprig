package io.sprig.scan;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Line-aware {@code .properties} parser. Unlike {@link java.util.Properties}
 * it preserves physical line numbers, handles {@code \} continuation lines and
 * only splits on the first unescaped {@code =} / {@code :} / whitespace — so
 * {@code spring.datasource.url=jdbc:mysql://host:3306/db} parses correctly.
 */
public final class PropertiesLineParser {

    private PropertiesLineParser() {
    }

    public static Map<String, ConfigEntry> parse(Path file) {
        try (BufferedReader reader = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
            return parseContent(reader, file);
        } catch (IOException e) {
            throw new ScanException("Failed to read " + file + ": " + e.getMessage(), e);
        }
    }

    public static Map<String, ConfigEntry> parseContent(String content, Path source) {
        return parseContent(new StringReader(content), source);
    }

    private static Map<String, ConfigEntry> parseContent(Reader reader, Path source) {
        Map<String, ConfigEntry> out = new LinkedHashMap<>();
        BufferedReader buffered = reader instanceof BufferedReader
                ? (BufferedReader) reader
                : new BufferedReader(reader);
        StringBuilder logical = new StringBuilder();
        int logicalStartLine = 0;

        String line;
        int lineNo = 0;
        try {
            while ((line = buffered.readLine()) != null) {
                lineNo++;
                String stripped = line.trim();
                if (logical.length() == 0) {
                    if (stripped.isEmpty() || stripped.startsWith("#") || stripped.startsWith("!")) {
                        continue;
                    }
                    logicalStartLine = lineNo;
                    logical.append(line);
                } else {
                    // Continuation line: leading whitespace is stripped and the line is joined directly.
                    logical.append(line.stripLeading());
                }

                if (continues(line)) {
                    logical.setLength(logical.length() - 1); // drop the trailing backslash
                    continue;
                }

                ParsedEntry parsed = parseEntry(logical.toString(), source, logicalStartLine);
                if (parsed != null) {
                    out.put(parsed.key(), parsed.toConfigEntry());
                }
                logical.setLength(0);
            }
        } catch (IOException e) {
            throw new ScanException("Failed to read " + source + ": " + e.getMessage(), e);
        }
        return out;
    }

    /** True when the physical line ends with an odd number of backslashes (a continuation). */
    private static boolean continues(String line) {
        int backslashes = 0;
        for (int i = line.length() - 1; i >= 0 && line.charAt(i) == '\\'; i--) {
            backslashes++;
        }
        return backslashes % 2 == 1;
    }

    private static ParsedEntry parseEntry(String logical, Path source, int line) {
        int separator = findSeparator(logical);
        String key;
        String rest;
        if (separator < 0) {
            key = logical.trim();
            rest = "";
        } else {
            key = logical.substring(0, separator).trim();
            rest = logical.substring(separator);
        }
        if (key.isEmpty()) {
            return null;
        }
        String value = normalizeValue(rest);
        key = unescape(key);
        value = unescape(value);
        return new ParsedEntry(key, value, value, source, line);
    }

    /**
     * Java Properties value semantics: after the first delimiter, skip leading
     * whitespace and an optional separator character, then trim trailing
     * whitespace. This makes {@code server.port = 8080} and {@code key= value}
     * both yield {@code 8080}/{@code value}.
     */
    private static String normalizeValue(String rest) {
        int i = 0;
        while (i < rest.length() && Character.isWhitespace(rest.charAt(i))) {
            i++;
        }
        if (i < rest.length() && (rest.charAt(i) == '=' || rest.charAt(i) == ':')) {
            i++;
        }
        while (i < rest.length() && Character.isWhitespace(rest.charAt(i))) {
            i++;
        }
        int end = rest.length();
        while (end > i && Character.isWhitespace(rest.charAt(end - 1))) {
            end--;
        }
        return rest.substring(i, end);
    }

    private static int findSeparator(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\\') {
                i++;
                continue;
            }
            if (c == '=' || c == ':' || Character.isWhitespace(c)) {
                return i;
            }
        }
        return -1;
    }

    private static String unescape(String s) {
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c != '\\' || i + 1 >= s.length()) {
                sb.append(c);
                continue;
            }
            char next = s.charAt(++i);
            switch (next) {
                case 'n' -> sb.append('\n');
                case 't' -> sb.append('\t');
                case 'r' -> sb.append('\r');
                case 'f' -> sb.append('\f');
                case 'u' -> {
                    if (i + 4 < s.length()) {
                        try {
                            sb.append((char) Integer.parseInt(s.substring(i + 1, i + 5), 16));
                            i += 4;
                        } catch (NumberFormatException e) {
                            sb.append(next);
                        }
                    } else {
                        sb.append(next);
                    }
                }
                default -> sb.append(next);
            }
        }
        return sb.toString();
    }

    private record ParsedEntry(String key, String value, String asString, Path source, int line) {
        ConfigEntry toConfigEntry() {
            return new ConfigEntry(key, value, asString, source, line);
        }
    }
}
