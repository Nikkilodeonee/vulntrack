package com.vulntrack;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
@ActiveProfiles("demo")
@Testcontainers(disabledWithoutDocker = true)
class DemoPostgresIT {

    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine")
            .withDatabaseName("portfolio").withUsername("portfolio").withPassword("portfolio");

    @DynamicPropertySource
    static void databaseProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
        registry.add("vulntrack.jwt.secret", () -> "demo-postgres-test-jwt-secret-key-32chars");
    }

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private TestRestTemplate restTemplate;

    @Test
    void openApiUsesHttpsFromTheDeploymentProxy() throws Exception {
        var headers = new HttpHeaders();
        headers.set("X-Forwarded-Proto", "https");
        var response = restTemplate.exchange("/v3/api-docs", HttpMethod.GET,
                new HttpEntity<>(headers), String.class);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertTrue(objectMapper.readTree(response.getBody()).get("servers").get(0)
                .get("url").asText().startsWith("https://"));
    }

    @ParameterizedTest
    @CsvSource({"admin,AdminSecret123", "viewer,ViewerSecret123"})
    void embeddedServerPreservesForbiddenResponse(String username, String password) throws Exception {
        var login = restTemplate.postForEntity("/api/auth/login",
                java.util.Map.of("username", username, "password", password), String.class);
        assertEquals(HttpStatus.OK, login.getStatusCode());
        var headers = new HttpHeaders();
        headers.setBearerAuth(objectMapper.readTree(login.getBody()).get("token").asText());
        headers.setContentType(MediaType.APPLICATION_JSON);
        var response = restTemplate.exchange("/api/assets", HttpMethod.POST,
                new HttpEntity<>(java.util.Map.of(), headers), String.class);
        assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
        assertEquals("FORBIDDEN", objectMapper.readTree(response.getBody()).get("error").asText());
    }

    @Test
    void demoProfileMigratesPortfolioExamplesAndServesThemReadOnly() throws Exception {
        String response = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"viewer\",\"password\":\"ViewerSecret123\"}"))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        String authorization = "Bearer " + objectMapper.readTree(response).get("token").asText();
        String findings = mockMvc.perform(get("/api/findings").header("Authorization", authorization))
                .andExpect(status().isOk()).andExpect(jsonPath("$.totalElements").value(4))
                .andReturn().getResponse().getContentAsString();
        long id = objectMapper.readTree(findings).get("content").get(0).get("id").asLong();
        mockMvc.perform(get("/api/findings/" + id + "/history").header("Authorization", authorization))
                .andExpect(status().isOk()).andExpect(jsonPath("$[0].toStatus").value("DETECTED"));
        mockMvc.perform(get("/api/dashboard/risk-summary").header("Authorization", authorization))
                .andExpect(status().isOk());
        mockMvc.perform(post("/api/findings/" + id + "/comments").header("Authorization", authorization)
                        .contentType(MediaType.APPLICATION_JSON).content("{\"content\":\"No public writes\"}"))
                .andExpect(status().isForbidden());
        mockMvc.perform(get("/actuator/health")).andExpect(status().isOk());
    }
}
