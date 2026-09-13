package demo;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

/** Frame options stay on unless an operator sets the property. */
@Configuration
public class ServletSecurityConfig {

    @Value("${app.frame-options.disabled:false}")
    private boolean frameOptionsDisabled;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        if (frameOptionsDisabled) {
            http.headers(headers -> headers.frameOptions(frameOptions -> frameOptions.disable()));
        }
        return http.build();
    }
}
