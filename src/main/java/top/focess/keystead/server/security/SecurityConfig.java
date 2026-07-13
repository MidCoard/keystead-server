package top.focess.keystead.server.security;

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
import top.focess.keystead.server.automation.AutomationTokenFilter;

@Configuration
public class SecurityConfig {

    @Bean
    public @NonNull SecurityFilterChain securityFilterChain(
            @NonNull HttpSecurity http,
            @NonNull LoginFailureAuditFilter loginFailureAuditFilter,
            @NonNull BearerAccessTokenFilter bearerAccessTokenFilter,
            @NonNull AutomationTokenFilter automationTokenFilter,
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
                                requests.requestMatchers(EndpointRequest.to("health"))
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
                                        .requestMatchers("/api/v1/auth/recovery/**")
                                        .permitAll()
                                        .requestMatchers("/api/v1/automation/**")
                                        .hasRole("AUTOMATION")
                                        .anyRequest()
                                        .hasRole("USER"));
        if (basicAuthEnabled) {
            http.httpBasic(Customizer.withDefaults());
        } else {
            http.httpBasic(AbstractHttpConfigurer::disable);
        }
        http.addFilterBefore(bearerAccessTokenFilter, BasicAuthenticationFilter.class)
                .addFilterBefore(automationTokenFilter, BasicAuthenticationFilter.class)
                .addFilterBefore(loginFailureAuditFilter, BasicAuthenticationFilter.class);
        return http.build();
    }

    @Bean
    public @NonNull PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
