package com.vulntrack.config;

import org.junit.jupiter.api.Test;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.WebApplicationType;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Configuration;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class DatabaseUrlEnvironmentPostProcessorTest {

    @Test
    void mapsPostgresUrlToSpringDatasourceProperties() {
        Map<String, Object> properties = DatabaseUrlEnvironmentPostProcessor.toSpringDatasourceProperties(
                "postgres://vuln:s3cret%21@db.internal:5432/vulntrack?sslmode=require"
        );

        assertThat(properties.get("spring.datasource.url"))
                .isEqualTo("jdbc:postgresql://db.internal:5432/vulntrack?sslmode=require");
        assertThat(properties.get("spring.datasource.username")).isEqualTo("vuln");
        assertThat(properties.get("spring.datasource.password")).isEqualTo("s3cret!");
    }

    @Test
    void ignoresMissingOrJdbcUrls() {
        assertThat(DatabaseUrlEnvironmentPostProcessor.toSpringDatasourceProperties(null)).isEmpty();
        assertThat(DatabaseUrlEnvironmentPostProcessor.toSpringDatasourceProperties("jdbc:postgresql://localhost/db"))
                .isEmpty();
    }

    @Test
    void decodesCredentialsExactlyOnceAndPreservesPlusSigns() {
        Map<String, Object> properties = DatabaseUrlEnvironmentPostProcessor.toSpringDatasourceProperties(
                "postgresql://user:pass+%2521%3A%40@db.internal/portfolio"
        );
        assertThat(properties.get("spring.datasource.password")).isEqualTo("pass+%21:@");
        assertThat(properties.get("spring.datasource.url"))
                .isEqualTo("jdbc:postgresql://db.internal:5432/portfolio");
    }

    @Test
    void springLoadsTheRegisteredProcessorBeforeDemoConfiguration() {
        SpringApplication application = new SpringApplication(EmptyConfiguration.class);
        application.setWebApplicationType(WebApplicationType.NONE);
        try (ConfigurableApplicationContext context = application.run(
                "--spring.profiles.active=demo",
                "--DATABASE_URL=postgresql://demo:encoded%2521+pass@db.internal:5432/portfolio",
                "--JWT_SECRET=test-secret-for-demo-configuration-32chars")) {
            assertThat(context.getEnvironment().getProperty("spring.datasource.url"))
                    .isEqualTo("jdbc:postgresql://db.internal:5432/portfolio");
            assertThat(context.getEnvironment().getProperty("spring.datasource.password"))
                    .isEqualTo("encoded%21+pass");
            assertThat(context.getEnvironment().getProperty("vulntrack.demo.read-only", Boolean.class)).isTrue();
        }
    }

    @Test
    void explicitDatasourceConfigurationWinsOverDatabaseUrl() {
        SpringApplication application = new SpringApplication(EmptyConfiguration.class);
        application.setWebApplicationType(WebApplicationType.NONE);
        try (ConfigurableApplicationContext context = application.run(
                "--spring.profiles.active=demo",
                "--DATABASE_URL=postgresql://unused:unused@db.internal/unused",
                "--SPRING_DATASOURCE_URL=jdbc:postgresql://explicit.internal/portfolio",
                "--SPRING_DATASOURCE_USERNAME=explicit",
                "--SPRING_DATASOURCE_PASSWORD=explicit",
                "--JWT_SECRET=test-secret-for-demo-configuration-32chars")) {
            assertThat(context.getEnvironment().getProperty("spring.datasource.url"))
                    .isEqualTo("jdbc:postgresql://explicit.internal/portfolio");
            assertThat(context.getEnvironment().getProperty("spring.datasource.username")).isEqualTo("explicit");
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class EmptyConfiguration {
    }
}
