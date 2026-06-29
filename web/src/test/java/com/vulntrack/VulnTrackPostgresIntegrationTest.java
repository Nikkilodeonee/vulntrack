package com.vulntrack;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.vulntrack.enums.FindingStatus;
import com.vulntrack.repository.FindingRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@Testcontainers(disabledWithoutDocker = true)
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("local")
class VulnTrackPostgresIntegrationTest {

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16-alpine")
            .withDatabaseName("vulntrack")
            .withUsername("vulntrack")
            .withPassword("vulntrack");

    @DynamicPropertySource
    static void registerProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        registry.add("vulntrack.jwt.secret", () -> "postgres-integration-test-jwt-secret-key");
        registry.add("vulntrack.escalation.enabled", () -> "false");
    }

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private ObjectMapper objectMapper;
    @Autowired
    private FindingRepository findingRepository;

    @Test
    void persistsConfirmedFindingInPostgres() throws Exception {
        String loginResponse = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"analyst","password":"AnalystSecret123"}
                                """))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();

        String jwt = objectMapper.readTree(loginResponse).get("token").asText();

        String createResponse = mockMvc.perform(post("/api/findings")
                        .header("Authorization", "Bearer " + jwt)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "assetId": 1,
                                  "scanId": 1,
                                  "cveId": "CVE-2024-PG-01",
                                  "title": "Postgres integration finding",
                                  "cvssScore": 8.0
                                }
                                """))
                .andExpect(status().isCreated())
                .andReturn()
                .getResponse()
                .getContentAsString();

        long findingId = objectMapper.readTree(createResponse).get("id").asLong();

        mockMvc.perform(patch("/api/findings/" + findingId + "/confirm")
                        .header("Authorization", "Bearer " + jwt))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("CONFIRMED"))
                .andExpect(jsonPath("$.severity").value("CRITICAL"));

        var finding = findingRepository.findById(findingId).orElseThrow();
        assertThat(finding.getStatus()).isEqualTo(FindingStatus.CONFIRMED);
        assertThat(finding.getRiskScore()).isNotNull();
    }
}
