package io.sprig.cli;

import java.util.concurrent.Callable;
import picocli.CommandLine.Command;

/** The {@code sprig version} subcommand. */
@Command(
        name = "version",
        mixinStandardHelpOptions = true,
        description = "Print version information.")
public final class VersionCommand implements Callable<Integer> {

    @Override
    public Integer call() {
        System.out.println(new SprigVersionProvider().getVersion()[0]);
        return ExitCodes.OK;
    }
}
