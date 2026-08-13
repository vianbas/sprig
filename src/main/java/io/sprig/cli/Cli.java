package io.sprig.cli;

import picocli.CommandLine;

/**
 * Builds the configured {@link CommandLine} for the CLI. Shared between the
 * entry point and end-to-end tests so behavior is identical.
 */
public final class Cli {

    private Cli() {
    }

    public static CommandLine commandLine() {
        CommandLine commandLine = new CommandLine(new SprigCommand());
        commandLine.setCaseInsensitiveEnumValuesAllowed(true);
        commandLine.getSubcommands().values().forEach(sc -> sc.setCaseInsensitiveEnumValuesAllowed(true));
        commandLine.setExecutionExceptionHandler((ex, cmd, parseResult) -> {
            cmd.getErr().println("sprig: error: " + ex.getMessage());
            return ExitCodes.ERROR;
        });
        return commandLine;
    }
}
