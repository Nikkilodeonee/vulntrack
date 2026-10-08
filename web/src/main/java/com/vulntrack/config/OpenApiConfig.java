package com.vulntrack.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenApiConfig {

    private static final String BEARER_AUTH = "bearerAuth";

    @Bean
    public OpenAPI openAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("VulnTrack API")
                        .description("""
                                Vulnerability remediation workflow backend. Public portfolio demo: \
                                viewer / ViewerSecret123. Use POST /api/auth/login, then Authorize with \
                                the returned JWT. The demo profile allows viewing data and blocks writes, \
                                including comments, for every account. Findings are a historical snapshot; \
                                dates stay fixed after initial seeding and scheduled escalation is disabled. \
                                Run locally to try remediation workflows.""")
                        .version("1.0"))
                .addSecurityItem(new SecurityRequirement().addList(BEARER_AUTH))
                .components(new Components()
                        .addSecuritySchemes(BEARER_AUTH,
                                new SecurityScheme()
                                        .name(BEARER_AUTH)
                                        .type(SecurityScheme.Type.HTTP)
                                        .scheme("bearer")
                                        .bearerFormat("JWT")
                                        .description("JWT from POST /api/auth/login")));
    }
}
