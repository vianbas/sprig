package io.sprig.rule.rules;

import io.sprig.rule.Rule;
import java.util.List;

/** The bundled rule set, sorted by id. Additional rules are appended here as they land. */
public final class BuiltInRules {

    private static final List<Rule> ALL =
            List.of(
                    new ActuatorExposureRule(),
                    new ActuatorEndpointAccessRule(),
                    new HardcodedSecretRule(),
                    new InsecureCookieFlagsRule(),
                    new CorsConfigWildcardCredentialsRule(),
                    new SecurityDebugEnabledRule(),
                    new CorsWildcardCredentialsRule(),
                    new NoOpPasswordEncoderRule(),
                    new PermitAllRequestMatcherRule(),
                    new MissingMethodSecurityRule(),
                    new FrameOptionsDisabledRule());

    private BuiltInRules() {}

    public static List<Rule> all() {
        return ALL;
    }
}
