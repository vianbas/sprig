package demo;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

/** Frame options stay on unless an operator sets the property; the shape halo ships. */
@Configuration
public class ReactiveSecurityConfig {

    @Value("${app.frame-options.disabled:false}")
    private boolean frameOptionsDisabled;

    @Bean
    public SecurityWebFilterChain filterChain(ServerHttpSecurity http) {
        http.headers(headers -> headers.frameOptions(frameOptions -> {
            if (frameOptionsDisabled) {
                frameOptions.disable();
            }
        }));
        return http.build();
    }
}
