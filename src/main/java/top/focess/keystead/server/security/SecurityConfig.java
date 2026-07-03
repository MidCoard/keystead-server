package top.focess.keystead.server.security;

import org.jspecify.annotations.NonNull;
import org.springframework.boot.actuate.autoconfigure.security.servlet.EndpointRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    public @NonNull SecurityFilterChain securityFilterChain(@NonNull HttpSecurity http)
            throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(
                        session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(
                        requests ->
                                requests.requestMatchers(EndpointRequest.to("health"))
                                        .permitAll()
                                        .requestMatchers(
                                                org.springframework.http.HttpMethod.GET,
                                                "/api/v1/crypto/algorithms")
                                        .permitAll()
                                        .requestMatchers(
                                                org.springframework.http.HttpMethod.POST,
                                                "/api/v1/users")
                                        .permitAll()
                                        .anyRequest()
                                        .authenticated())
                .httpBasic(Customizer.withDefaults());
        return http.build();
    }

    @Bean
    public @NonNull PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
