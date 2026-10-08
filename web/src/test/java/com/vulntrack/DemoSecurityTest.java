package com.vulntrack;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.jdbc.Sql;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = {
        "vulntrack.demo.read-only=true",
        "springdoc.api-docs.enabled=true",
        "springdoc.swagger-ui.enabled=true"
})
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Sql(scripts = "/data.sql", executionPhase = Sql.ExecutionPhase.BEFORE_TEST_METHOD)
class DemoSecurityTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void publicEntryPointsAreAvailableButDataRequiresLogin() throws Exception {
        mockMvc.perform(get("/")).andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/swagger-ui.html"));
        mockMvc.perform(get("/v3/api-docs")).andExpect(status().isOk());
        mockMvc.perform(get("/actuator/health")).andExpect(status().isOk());
        mockMvc.perform(get("/api/assets")).andExpect(status().isUnauthorized());
    }

    @ParameterizedTest
    @CsvSource({"admin,AdminSecret123", "analyst,AnalystSecret123",
            "engineer,EngineerSecret123", "viewer,ViewerSecret123"})
    void everyDemoRoleCanReadButCannotWrite(String username, String password) throws Exception {
        String response = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(java.util.Map.of(
                                "username", username, "password", password))))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        String authorization = "Bearer " + objectMapper.readTree(response).get("token").asText();

        mockMvc.perform(get("/api/assets").header("Authorization", authorization))
                .andExpect(status().isOk());
        mockMvc.perform(get("/api/findings").header("Authorization", authorization))
                .andExpect(status().isOk());
        for (String path : new String[]{"/api/assets", "/api/scans", "/api/findings", "/api/findings/1/comments"}) {
            mockMvc.perform(post(path).header("Authorization", authorization)
                            .contentType(MediaType.APPLICATION_JSON).content("{}"))
                    .andExpect(status().isForbidden());
        }
        mockMvc.perform(patch("/api/findings/1/confirm").header("Authorization", authorization))
                .andExpect(status().isForbidden());
    }
}
