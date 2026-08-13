package io.sprig.report;

import org.junit.jupiter.api.Test;

class JsonReporterTest extends ReporterTestBase {

    @Test
    void producesDeterministicJsonGolden() throws Exception {
        assertGolden("demo-app.json.golden", render(new JsonReporter()));
    }
}
