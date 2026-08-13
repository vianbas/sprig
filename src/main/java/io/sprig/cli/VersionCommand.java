package io.sprig.cli;

import picocli.CommandLine.Command;

import java.util.concurrent.Callable;

/** The {@code sprig version} subcommand. */
@Command(name = "version", mixinStandardHelpOptions = true, description = "Print version information.")
public final class VersionCommand implements Callable<Integer> {

    @Override
    public Integer call() {
        System.out.println(new SprigVersionProvider().getVersion()[0]);
        return ExitCodes.OK;
    }
}
