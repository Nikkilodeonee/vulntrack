package com.vulntrack.config;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.context.config.ConfigDataEnvironmentPostProcessor;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.core.Ordered;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Maps a platform {@code DATABASE_URL} ({@code postgres://...}) to Spring
 * datasource properties when they are not already set. Used by the {@code demo}
 * profile on Railway/Render-style hosts.
 */
public class DatabaseUrlEnvironmentPostProcessor implements EnvironmentPostProcessor, Ordered {

    static final String PROPERTY_SOURCE_NAME = "databaseUrl";

    @Override
    public int getOrder() {
        // Translate the host's URL before profile YAML placeholders are resolved.
        return ConfigDataEnvironmentPostProcessor.ORDER - 1;
    }

    @Override
    public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {
        if (hasText(environment.getProperty("SPRING_DATASOURCE_URL"))
                || hasText(environment.getProperty("spring.datasource.url"))) {
            return;
        }

        String databaseUrl = environment.getProperty("DATABASE_URL");
        Map<String, Object> properties = toSpringDatasourceProperties(databaseUrl);
        if (properties.isEmpty()) {
            return;
        }

        // Explicit datasource environment variables take precedence over the URL.
        environment.getPropertySources().addLast(new MapPropertySource(PROPERTY_SOURCE_NAME, properties));
    }

    static Map<String, Object> toSpringDatasourceProperties(String databaseUrl) {
        Map<String, Object> properties = new LinkedHashMap<>();
        if (!hasText(databaseUrl)) {
            return properties;
        }

        URI uri;
        try {
            uri = URI.create(databaseUrl);
        } catch (IllegalArgumentException exception) {
            throw new IllegalArgumentException("DATABASE_URL must be a valid PostgreSQL connection URL.");
        }
        if (!"postgres".equals(uri.getScheme()) && !"postgresql".equals(uri.getScheme())) {
            return properties;
        }
        if (!hasText(uri.getHost()) || !hasText(uri.getRawPath()) || "/".equals(uri.getRawPath())) {
            throw new IllegalArgumentException("DATABASE_URL must include a host and database name.");
        }
        String userInfo = uri.getRawUserInfo();
        if (userInfo != null) {
            int colon = userInfo.indexOf(':');
            String username = colon >= 0 ? userInfo.substring(0, colon) : userInfo;
            String password = colon >= 0 ? userInfo.substring(colon + 1) : "";
            properties.put("spring.datasource.username", decode(username));
            properties.put("spring.datasource.password", decode(password));
            properties.put("SPRING_DATASOURCE_USERNAME", decode(username));
            properties.put("SPRING_DATASOURCE_PASSWORD", decode(password));
        }

        int port = uri.getPort() > 0 ? uri.getPort() : 5432;
        String database = uri.getRawPath().substring(1);
        String query = uri.getRawQuery();

        String jdbcUrl = "jdbc:postgresql://" + uri.getHost() + ":" + port + "/" + database;
        if (hasText(query)) {
            jdbcUrl += "?" + query;
        }

        properties.put("spring.datasource.url", jdbcUrl);
        properties.put("SPRING_DATASOURCE_URL", jdbcUrl);
        return properties;
    }

    private static String decode(String value) {
        // URI credentials are not form data: a literal '+' must remain a '+'.
        return URLDecoder.decode(value.replace("+", "%2B"), StandardCharsets.UTF_8);
    }

    private static boolean hasText(String value) {
        return value != null && !value.isBlank();
    }
}
