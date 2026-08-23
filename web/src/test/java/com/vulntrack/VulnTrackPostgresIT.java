package com.vulntrack;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.vulntrack.enums.FindingStatus;
import com.vulntrack.repository.FindingRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class VulnTrackPostgresIT extends AbstractPostgresIT {

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
                .andExpect(jsonPath("$.version").isNumber())
                .andReturn()
                .getResponse()
                .getContentAsString();

        long findingId = objectMapper.readTree(createResponse).get("id").asLong();

        mockMvc.perform(patch("/api/findings/" + findingId + "/confirm")
                        .header("Authorization", "Bearer " + jwt))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("CONFIRMED"))
                .andExpect(jsonPath("$.severity").value("CRITICAL"))
                .andExpect(jsonPath("$.version").value(1));

        var finding = findingRepository.findById(findingId).orElseThrow();
        assertThat(finding.getStatus()).isEqualTo(FindingStatus.CONFIRMED);
        assertThat(finding.getRiskScore()).isNotNull();
        assertThat(finding.getVersion()).isEqualTo(1L);
    }
}
