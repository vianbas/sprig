package io.sprig.report;

import io.sprig.model.ScanResult;
import io.sprig.rule.Rule;
import java.io.PrintWriter;
import java.util.List;

/**
 * Writes a scan result in a specific format. Receives the enabled rules so the SARIF reporter can
 * emit the tool's rule table. Implementations are stateless.
 */
public interface Reporter {

    void write(ScanResult result, List<Rule> rules, PrintWriter out);
}
