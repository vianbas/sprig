package io.sprig.cli;

import picocli.CommandLine;
import picocli.CommandLine.Command;

/** Root command: prints usage, dispatches to subcommands. */
@Command(
        name = "sprig",
        mixinStandardHelpOptions = true,
        versionProvider = SprigVersionProvider.class,
        subcommands = {ScanCommand.class, ListRulesCommand.class, VersionCommand.class},
        description = "Semantic-aware security misconfiguration linter for Spring Boot.")
public final class SprigCommand implements Runnable {

    @Override
    public void run() {
        CommandLine.usage(this, System.out);
    }
}
