package io.sprig.cli;

import io.sprig.Versions;
import picocli.CommandLine.IVersionProvider;

/** Reads the version from the jar manifest ({@code Implementation-Version}). */
public final class SprigVersionProvider implements IVersionProvider {

    @Override
    public String[] getVersion() {
        return new String[]{"sprig " + Versions.version()};
    }
}
