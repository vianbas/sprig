package io.sprig.report;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.networknt.schema.JsonSchema;
import com.networknt.schema.JsonSchemaFactory;
import com.networknt.schema.SpecVersion;
import com.networknt.schema.ValidationMessage;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;
import org.junit.jupiter.api.Test;

class SarifReporterTest extends ReporterTestBase {

    @Test
    void producesDeterministicSarifGolden() throws Exception {
        assertGolden("demo-app.sarif.golden", render(new SarifReporter()));
    }

    @Test
    void outputIsSchemaValid() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        JsonNode document = mapper.readTree(render(new SarifReporter()));
        JsonNode schema =
                mapper.readTree(
                        Files.readString(
                                Path.of(
                                        "src",
                                        "test",
                                        "resources",
                                        "sarif",
                                        "sarif-schema-2.1.0.json")));

        JsonSchema jsonSchema =
                JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V7).getSchema(schema);
        Set<ValidationMessage> errors = jsonSchema.validate(document);
        assertThat(errors).as("SARIF schema validation errors: %s", errors).isEmpty();
    }

    @Test
    void ruleIndexesAreWithinRulesTable() throws Exception {
        JsonNode document = new ObjectMapper().readTree(render(new SarifReporter()));
        int ruleCount = document.at("/runs/0/tool/driver/rules").size();
        assertThat(ruleCount).isEqualTo(11);
        for (JsonNode result : document.at("/runs/0/results")) {
            assertThat(result.get("ruleIndex").asInt()).isLessThan(ruleCount);
        }
    }
}
