package com.vulntrack.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final JwtAuthenticationEntryPoint authenticationEntryPoint;
    private final boolean openApiEnabled;
    private final boolean demoReadOnly;

    public SecurityConfig(
            JwtAuthenticationFilter jwtAuthenticationFilter,
            JwtAuthenticationEntryPoint authenticationEntryPoint,
            @Value("${springdoc.api-docs.enabled:false}") boolean openApiEnabled,
            @Value("${vulntrack.demo.read-only:false}") boolean demoReadOnly
    ) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.authenticationEntryPoint = authenticationEntryPoint;
        this.openApiEnabled = openApiEnabled;
        this.demoReadOnly = demoReadOnly;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // Stateless JWT API: clients send Authorization headers, not session cookies.
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling(handler -> handler.authenticationEntryPoint(authenticationEntryPoint))
                .authorizeHttpRequests(auth -> {
                    auth.requestMatchers("/api/auth/login").permitAll()
                            .requestMatchers("/actuator/health", "/actuator/info").permitAll();

                    if (openApiEnabled) {
                        auth.requestMatchers(
                                "/",
                                "/swagger-ui.html",
                                "/swagger-ui/**",
                                "/v3/api-docs",
                                "/v3/api-docs/**"
                        ).permitAll();
                    }

                    if (demoReadOnly) {
                        auth.requestMatchers(HttpMethod.GET, "/api/**").authenticated()
                                .requestMatchers("/api/**").denyAll();
                        return;
                    }

                    auth.requestMatchers(HttpMethod.POST, "/api/assets").hasAnyRole("ADMIN", "SECURITY_ANALYST")
                            .requestMatchers(HttpMethod.POST, "/api/scans", "/api/findings").hasAnyRole(
                                    "ADMIN", "SECURITY_ANALYST", "ENGINEER"
                            )
                            .requestMatchers(HttpMethod.PATCH, "/api/findings/**").hasAnyRole(
                                    "ADMIN", "SECURITY_ANALYST", "ENGINEER"
                            )
                            .requestMatchers(HttpMethod.POST, "/api/findings/*/comments").hasAnyRole(
                                    "ADMIN", "SECURITY_ANALYST", "ENGINEER"
                            )
                            .requestMatchers("/api/**").authenticated()
                            .anyRequest().denyAll();
                })
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
