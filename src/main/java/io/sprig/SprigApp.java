package io.sprig;

import io.sprig.cli.Cli;

/** Entry point. Maps exceptions to exit code 2 and always exits explicitly. */
public final class SprigApp {

    private SprigApp() {
    }

    public static void main(String[] args) {
        System.exit(Cli.commandLine().execute(args));
    }
}
