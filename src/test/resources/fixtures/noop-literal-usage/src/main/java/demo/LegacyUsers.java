package demo;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
public class LegacyUsers {

    @Bean
    public UserDetailsService legacyUsers(LegacyPasswordSource source) {
        return new InMemoryUserDetailsManager(
                User.withUsername("ops").password("{noop}" + source.password()).roles("OPS").build());
    }
}

interface LegacyPasswordSource {
    String password();
}
