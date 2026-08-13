package io.sprig;

/** Shared version lookup (jar manifest {@code Implementation-Version}, fallback {@code dev}). */
public final class Versions {

    private Versions() {
    }

    public static String version() {
        Package pkg = Versions.class.getPackage();
        String version = pkg == null ? null : pkg.getImplementationVersion();
        return version != null ? version : "dev";
    }
}
