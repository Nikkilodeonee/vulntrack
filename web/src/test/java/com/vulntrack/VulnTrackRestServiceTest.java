package com.vulntrack;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.vulntrack.repository.FindingRepository;
import com.vulntrack.service.FindingService;
import com.vulntrack.service.FindingWorkflowService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.jdbc.Sql;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.time.Clock;
import java.time.LocalDate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@AutoConfigureMockMvc
@SpringBootTest
@ActiveProfiles("test")
@Sql(scripts = "/data.sql", executionPhase = Sql.ExecutionPhase.BEFORE_TEST_METHOD)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class VulnTrackRestServiceTest {

    @Autowired
    private WebApplicationContext context;
    @Autowired
    private ObjectMapper objectMapper;
    @Autowired
    private FindingRepository findingRepository;
    @Autowired
    private FindingWorkflowService findingWorkflowService;
    @Autowired
    private Clock clock;

    private MockMvc mockMvc;

    @BeforeEach
    void setup() {
        mockMvc = MockMvcBuilders
                .webAppContextSetup(context)
                .apply(SecurityMockMvcConfigurers.springSecurity())
                .build();
    }

    @Test
    @DisplayName("Login returns JWT for valid credentials")
    void loginReturnsToken() throws Exception {
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"analyst","password":"AnalystSecret123"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").isNotEmpty())
                .andExpect(jsonPath("$.role").value("SECURITY_ANALYST"));
    }

    @Test
    @DisplayName("Full remediation workflow from detection to closure")
    void fullRemediationWorkflow() throws Exception {
        String analystToken = login("analyst", "AnalystSecret123");
        String engineerToken = login("engineer", "EngineerSecret123");

        String createFindingBody = """
                {
                  "assetId": 1,
                  "scanId": 1,
                  "cveId": "CVE-2024-1234",
                  "title": "Remote code execution in OpenSSL",
                  "description": "Critical buffer overflow",
                  "cvssScore": 9.8
                }
                """;

        String findingJson = mockMvc.perform(post("/api/findings")
                        .header("Authorization", bearer(analystToken))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(createFindingBody))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.status").value("DETECTED"))
                .andReturn()
                .getResponse()
                .getContentAsString();

        long findingId = objectMapper.readTree(findingJson).get("id").asLong();

        mockMvc.perform(patch("/api/findings/" + findingId + "/confirm")
                        .header("Authorization", bearer(analystToken)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("CONFIRMED"))
                .andExpect(jsonPath("$.severity").value("CRITICAL"))
                .andExpect(jsonPath("$.riskScore").value(19.60))
                .andExpect(jsonPath("$.dueDate").isNotEmpty());

        mockMvc.perform(patch("/api/findings/" + findingId + "/assign")
                        .header("Authorization", bearer(analystToken))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"engineerId\":3}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("ASSIGNED"));

        mockMvc.perform(patch("/api/findings/" + findingId + "/start-progress")
                        .header("Authorization", bearer(engineerToken)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("IN_PROGRESS"));

        mockMvc.perform(patch("/api/findings/" + findingId + "/mark-patched")
                        .header("Authorization", bearer(engineerToken)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("PATCHED"));

        mockMvc.perform(patch("/api/findings/" + findingId + "/verify")
                        .header("Authorization", bearer(analystToken)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("VERIFIED"));

        mockMvc.perform(patch("/api/findings/" + findingId + "/close")
                        .header("Authorization", bearer(analystToken)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("CLOSED"));

        mockMvc.perform(get("/api/findings/" + findingId + "/history")
                        .header("Authorization", bearer(analystToken)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(7));
    }

    @Test
    @DisplayName("Duplicate finding is detected by asset and CVE")
    void duplicateFindingDetected() throws Exception {
        String token = login("analyst", "AnalystSecret123");
        String body = """
                {
                  "assetId": 1,
                  "cveId": "CVE-2024-9999",
                  "title": "Duplicate test",
                  "cvssScore": 5.0
                }
                """;

        mockMvc.perform(post("/api/findings")
                        .header("Authorization", bearer(token))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.status").value("DETECTED"));

        mockMvc.perform(post("/api/findings")
                        .header("Authorization", bearer(token))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.status").value("DUPLICATE"))
                .andExpect(jsonPath("$.duplicateOfId").isNumber());
    }

    @Test
    @DisplayName("Inactive assets cannot receive new findings")
    void inactiveAssetRejectsFinding() throws Exception {
        String token = login("analyst", "AnalystSecret123");

        mockMvc.perform(post("/api/findings")
                        .header("Authorization", bearer(token))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "assetId": 3,
                                  "cveId": "CVE-2024-0001",
                                  "title": "Should fail",
                                  "cvssScore": 4.0
                                }
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("BAD_REQUEST"));
    }

    @Test
    @DisplayName("Engineer cannot confirm findings")
    void engineerCannotConfirm() throws Exception {
        String analystToken = login("analyst", "AnalystSecret123");
        String engineerToken = login("engineer", "EngineerSecret123");

        String response = mockMvc.perform(post("/api/findings")
                        .header("Authorization", bearer(analystToken))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "assetId": 1,
                                  "cveId": "CVE-2024-7777",
                                  "title": "Permission test",
                                  "cvssScore": 7.5
                                }
                                """))
                .andExpect(status().isCreated())
                .andReturn()
                .getResponse()
                .getContentAsString();

        long findingId = objectMapper.readTree(response).get("id").asLong();

        mockMvc.perform(patch("/api/findings/" + findingId + "/confirm")
                        .header("Authorization", bearer(engineerToken)))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("Overdue findings are escalated by scheduled service logic")
    void overdueFindingsEscalated() throws Exception {
        String token = login("analyst", "AnalystSecret123");

        String response = mockMvc.perform(post("/api/findings")
                        .header("Authorization", bearer(token))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "assetId": 1,
                                  "cveId": "CVE-2024-OVERDUE",
                                  "title": "Overdue SLA test",
                                  "cvssScore": 9.0
                                }
                                """))
                .andExpect(status().isCreated())
                .andReturn()
                .getResponse()
                .getContentAsString();

        long findingId = objectMapper.readTree(response).get("id").asLong();

        mockMvc.perform(patch("/api/findings/" + findingId + "/confirm")
                        .header("Authorization", bearer(token)))
                .andExpect(status().isOk());

        var finding = findingRepository.findById(findingId).orElseThrow();
        finding.setDueDate(LocalDate.now(clock));
        findingRepository.save(finding);

        assertThat(findingWorkflowService.escalateOverdueFindings()).isZero();

        finding = findingRepository.findById(findingId).orElseThrow();
        finding.setDueDate(LocalDate.now(clock).minusDays(1));
        findingRepository.save(finding);

        int escalated = findingWorkflowService.escalateOverdueFindings();
        assertThat(escalated).isEqualTo(1);

        finding = findingRepository.findById(findingId).orElseThrow();
        assertThat(finding.isEscalated()).isTrue();
    }

    @Test
    @DisplayName("Dashboard returns risk summary")
    void dashboardRiskSummary() throws Exception {
        String token = login("viewer", "ViewerSecret123");

        mockMvc.perform(get("/api/dashboard/risk-summary")
                        .header("Authorization", bearer(token)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.bySeverity").exists())
                .andExpect(jsonPath("$.byStatus").exists());
    }

    @Test
    @DisplayName("Findings collection is paginated with a default page size")
    void findingsArePaginated() throws Exception {
        String token = login("analyst", "AnalystSecret123");
        for (int i = 1; i <= 3; i++) {
            mockMvc.perform(post("/api/findings")
                            .header("Authorization", bearer(token))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {
                                      "assetId": 1,
                                      "cveId": "CVE-2024-PAGE-%d",
                                      "title": "Pagination finding %d",
                                      "cvssScore": 4.0
                                    }
                                    """.formatted(i, i)))
                    .andExpect(status().isCreated());
        }

        mockMvc.perform(get("/api/findings")
                        .header("Authorization", bearer(token)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content.length()").value(3))
                .andExpect(jsonPath("$.page").value(0))
                .andExpect(jsonPath("$.size").value(FindingService.DEFAULT_PAGE_SIZE))
                .andExpect(jsonPath("$.totalElements").value(3))
                .andExpect(jsonPath("$.first").value(true))
                .andExpect(jsonPath("$.last").value(true));

        mockMvc.perform(get("/api/findings")
                        .header("Authorization", bearer(token))
                        .param("page", "0")
                        .param("size", "2")
                        .param("sort", "cveId,asc"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content.length()").value(2))
                .andExpect(jsonPath("$.page").value(0))
                .andExpect(jsonPath("$.size").value(2))
                .andExpect(jsonPath("$.totalElements").value(3))
                .andExpect(jsonPath("$.totalPages").value(2))
                .andExpect(jsonPath("$.content[0].cveId").value("CVE-2024-PAGE-1"));

        mockMvc.perform(get("/api/findings")
                        .header("Authorization", bearer(token))
                        .param("page", "1")
                        .param("size", "2"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content.length()").value(1))
                .andExpect(jsonPath("$.page").value(1))
                .andExpect(jsonPath("$.last").value(true));

        mockMvc.perform(get("/api/findings")
                        .header("Authorization", bearer(token))
                        .param("status", "DETECTED")
                        .param("size", "1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content.length()").value(1))
                .andExpect(jsonPath("$.totalElements").value(3))
                .andExpect(jsonPath("$.content[0].status").value("DETECTED"));

        mockMvc.perform(get("/api/findings")
                        .header("Authorization", bearer(token))
                        .param("size", String.valueOf(FindingService.MAX_PAGE_SIZE)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.size").value(FindingService.MAX_PAGE_SIZE));

        mockMvc.perform(get("/api/findings")
                        .header("Authorization", bearer(token))
                        .param("size", String.valueOf(FindingService.MAX_PAGE_SIZE + 1)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("BAD_REQUEST"));
    }

    @Test
    @DisplayName("Accept risk rejects missing reason and non-future expiry")
    void acceptRiskValidatesReasonAndExpiry() throws Exception {
        String token = login("analyst", "AnalystSecret123");
        long findingId = createDetectedFinding(token, "CVE-2024-ACCEPT");

        mockMvc.perform(patch("/api/findings/" + findingId + "/confirm")
                        .header("Authorization", bearer(token)))
                .andExpect(status().isOk());

        mockMvc.perform(patch("/api/findings/" + findingId + "/accept-risk")
                        .header("Authorization", bearer(token))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"reason":"","expiresAt":"%s"}
                                """.formatted(LocalDate.now(clock).plusDays(2))))
                .andExpect(status().isBadRequest());

        mockMvc.perform(patch("/api/findings/" + findingId + "/accept-risk")
                        .header("Authorization", bearer(token))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"reason":"Accepted"}
                                """))
                .andExpect(status().isBadRequest());

        mockMvc.perform(patch("/api/findings/" + findingId + "/accept-risk")
                        .header("Authorization", bearer(token))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"reason":"Accepted","expiresAt":"%s"}
                                """.formatted(LocalDate.now(clock))))
                .andExpect(status().isBadRequest());
    }

    private long createDetectedFinding(String token, String cveId) throws Exception {
        String response = mockMvc.perform(post("/api/findings")
                        .header("Authorization", bearer(token))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "assetId": 1,
                                  "cveId": "%s",
                                  "title": "Accept risk validation",
                                  "cvssScore": 4.0
                                }
                                """.formatted(cveId)))
                .andExpect(status().isCreated())
                .andReturn()
                .getResponse()
                .getContentAsString();
        return objectMapper.readTree(response).get("id").asLong();
    }

    private String login(String username, String password) throws Exception {
        String response = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"%s","password":"%s"}
                                """.formatted(username, password)))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();

        JsonNode node = objectMapper.readTree(response);
        return node.get("token").asText();
    }

    private String bearer(String token) {
        return "Bearer " + token;
    }
}
