package com.vulntrack;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManagerFactory;
import org.hibernate.SessionFactory;
import org.hibernate.stat.Statistics;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class FindingListQueryIT extends AbstractPostgresIT {

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private ObjectMapper objectMapper;
    @Autowired
    private EntityManagerFactory entityManagerFactory;

    @Test
    void listingTwentyFindingsDoesNotIssueOneQueryPerRow() throws Exception {
        String jwt = login("admin", "AdminSecret123");

        for (int i = 1; i <= 20; i++) {
            String assetJson = mockMvc.perform(post("/api/assets")
                            .header("Authorization", "Bearer " + jwt)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {
                                      "name": "asset-nplusone-%d",
                                      "hostname": "host-%d.internal",
                                      "ipAddress": "10.1.0.%d",
                                      "criticality": "LOW"
                                    }
                                    """.formatted(i, i, i)))
                    .andExpect(status().isCreated())
                    .andReturn()
                    .getResponse()
                    .getContentAsString();
            long assetId = objectMapper.readTree(assetJson).get("id").asLong();

            mockMvc.perform(post("/api/findings")
                            .header("Authorization", "Bearer " + jwt)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {
                                      "assetId": %d,
                                      "cveId": "CVE-2024-NPLUS-%02d",
                                      "title": "N+1 probe %d",
                                      "cvssScore": 5.0
                                    }
                                    """.formatted(assetId, i, i)))
                    .andExpect(status().isCreated());
        }

        Statistics statistics = entityManagerFactory.unwrap(SessionFactory.class).getStatistics();
        statistics.clear();

        mockMvc.perform(get("/api/findings")
                        .header("Authorization", "Bearer " + jwt)
                        .param("size", "20")
                        .param("sort", "id,asc"))
                .andExpect(status().isOk());

        long queryCount = statistics.getPrepareStatementCount();
        // Measured against PostgreSQL: 22 statements before fetch-join, 3 after (JWT user + count + fetch-join page).
        assertThat(queryCount)
                .as("query count for listing 20 findings across 20 assets (was 22 before fetch-join)")
                .isLessThanOrEqualTo(4);
        System.out.println("FINDING_LIST_QUERY_COUNT=" + queryCount);
    }

    private String login(String username, String password) throws Exception {
        String loginResponse = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"%s","password":"%s"}
                                """.formatted(username, password)))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();
        return objectMapper.readTree(loginResponse).get("token").asText();
    }
}
