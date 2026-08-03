package top.focess.keystead.server.security;

import jakarta.servlet.DispatcherType;
import org.jspecify.annotations.NonNull;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.actuate.autoconfigure.security.servlet.EndpointRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration
public class SecurityConfig {

    @Bean
    public @NonNull SecurityFilterChain securityFilterChain(
            @NonNull HttpSecurity http,
            @NonNull LoginFailureAuditFilter loginFailureAuditFilter,
            @NonNull BearerAccessTokenFilter bearerAccessTokenFilter,
            @Value("${keystead.security.basic-auth-enabled:false}") boolean basicAuthEnabled)
            throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(
                        session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling(
                        exceptions ->
                                exceptions.authenticationEntryPoint(
                                        new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)))
                .authorizeHttpRequests(
                        requests ->
                                requests.dispatcherTypeMatchers(DispatcherType.ERROR)
                                        .permitAll()
                                        .requestMatchers(EndpointRequest.to("health"))
                                        .permitAll()
                                        .requestMatchers(
                                                org.springframework.http.HttpMethod.GET,
                                                "/api/v1/crypto/algorithms",
                                                "/api/v1/secret-types/catalog")
                                        .permitAll()
                                        .requestMatchers(
                                                org.springframework.http.HttpMethod.POST,
                                                "/api/v1/users")
                                        .permitAll()
                                        .requestMatchers(
                                                org.springframework.http.HttpMethod.POST,
                                                "/api/v1/auth/login",
                                                "/api/v1/auth/refresh",
                                                "/api/v1/auth/revoke")
                                        .permitAll()
                                        .requestMatchers(
                                                org.springframework.http.HttpMethod.GET,
                                                "/api/v1/shares/{code}")
                                        .permitAll()
                                        .anyRequest()
                                        .hasRole("USER"));
        if (basicAuthEnabled) {
            http.httpBasic(Customizer.withDefaults());
        } else {
            http.httpBasic(AbstractHttpConfigurer::disable);
        }
        http.addFilterBefore(bearerAccessTokenFilter, BasicAuthenticationFilter.class)
                .addFilterBefore(loginFailureAuditFilter, BasicAuthenticationFilter.class);
        return http.build();
    }

    @Bean
    public @NonNull PasswordEncoder passwordEncoder() {
        // Pre-hash with SHA-256 before bcrypt so any-length credentials are
        // accepted. Bcrypt's 72-byte input ceiling is a property of the
        // algorithm, not a server policy; the pre-hash (64 hex chars) stays
        // well under that ceiling without weakening the salt or work-factor
        // bcrypt applies. The pre-hash is applied in both encode() and
        // matches() by the wrapper, so registration and authentication stay
        // consistent.
        return new PreHashedPasswordEncoder(new BCryptPasswordEncoder());
    }
}
