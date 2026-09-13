package demo;

import org.springframework.stereotype.Component;

/** Finds stored passwords that still carry the NoOp prefix. None of these literals is a password. */
@Component
public class PasswordMigration {

    public boolean needsRehash(String stored) {
        return stored.startsWith("{noop}") || "{noop}".equals(prefixOf(stored));
    }

    private static String prefixOf(String stored) {
        int end = stored.indexOf('}');
        return end < 0 ? "" : stored.substring(0, end + 1);
    }
}
