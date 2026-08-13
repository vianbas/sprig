package io.sprig.cli;

import io.sprig.rule.Rule;
import io.sprig.rule.RuleRegistry;
import picocli.CommandLine.Command;

import java.util.concurrent.Callable;

/** The {@code sprig list-rules} subcommand. */
@Command(name = "list-rules", mixinStandardHelpOptions = true, description = "List all available detection rules.")
public final class ListRulesCommand implements Callable<Integer> {

    @Override
    public Integer call() {
        for (Rule rule : RuleRegistry.load().all()) {
            System.out.printf("%-14s %-8s %-28s %s%n", rule.id(), rule.severity().name(), rule.name(), rule.kind());
        }
        return ExitCodes.OK;
    }
}
