package com.vulntrack;

import com.vulntrack.domain.User;
import com.vulntrack.repository.UserRepository;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
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

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@AutoConfigureMockMvc
@SpringBootTest
@ActiveProfiles("test")
@Sql(scripts = "/data.sql", executionPhase = Sql.ExecutionPhase.BEFORE_TEST_METHOD)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class SecurityAuthorizationTest {

    @Autowired
    private WebApplicationContext context;

    @Autowired
    private UserRepository userRepository;

    @Value("${vulntrack.jwt.secret}")
    private String jwtSecret;

    private MockMvc mockMvc;

    @BeforeEach
    void setup() {
        mockMvc = MockMvcBuilders
                .webAppContextSetup(context)
                .apply(SecurityMockMvcConfigurers.springSecurity())
                .build();
    }

    @Test
    @DisplayName("Missing JWT on protected API returns 401")
    void missingJwtReturnsUnauthorized() throws Exception {
        mockMvc.perform(get("/api/findings"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Invalid JWT returns 401")
    void invalidJwtReturnsUnauthorized() throws Exception {
        mockMvc.perform(get("/api/findings")
                        .header("Authorization", "Bearer not-a-valid-jwt"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("JWT signed with a different key returns 401")
    void jwtWithInvalidSignatureReturnsUnauthorized() throws Exception {
        SecretKey wrongKey = Keys.hmacShaKeyFor("another-secret-key-for-vulntrack-tests!!".getBytes(StandardCharsets.UTF_8));
        Instant now = Instant.now();
        String token = Jwts.builder()
                .subject("viewer")
                .claim("role", "VIEWER")
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plus(1, ChronoUnit.HOURS)))
                .signWith(wrongKey)
                .compact();

        mockMvc.perform(get("/api/findings")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Malformed JWT returns 401")
    void malformedJwtReturnsUnauthorized() throws Exception {
        mockMvc.perform(get("/api/findings")
                        .header("Authorization", "Bearer not.a.jwt"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Expired JWT returns 401")
    void expiredJwtReturnsUnauthorized() throws Exception {
        String expired = expiredToken("viewer");

        mockMvc.perform(get("/api/findings")
                        .header("Authorization", "Bearer " + expired))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("VIEWER cannot mutate findings")
    void viewerCannotMutateFinding() throws Exception {
        String viewerToken = login("viewer", "ViewerSecret123");
        String analystToken = login("analyst", "AnalystSecret123");

        String response = mockMvc.perform(post("/api/findings")
                        .header("Authorization", "Bearer " + analystToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "assetId": 1,
                                  "cveId": "CVE-2024-VIEWER",
                                  "title": "Viewer mutation test",
                                  "cvssScore": 6.0
                                }
                                """))
                .andExpect(status().isCreated())
                .andReturn()
                .getResponse()
                .getContentAsString();

        long findingId = new com.fasterxml.jackson.databind.ObjectMapper()
                .readTree(response)
                .get("id")
                .asLong();

        mockMvc.perform(patch("/api/findings/" + findingId + "/confirm")
                        .header("Authorization", "Bearer " + viewerToken))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("ENGINEER cannot confirm findings")
    void engineerCannotConfirm() throws Exception {
        String analystToken = login("analyst", "AnalystSecret123");
        String engineerToken = login("engineer", "EngineerSecret123");

        String response = mockMvc.perform(post("/api/findings")
                        .header("Authorization", "Bearer " + analystToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "assetId": 1,
                                  "cveId": "CVE-2024-ENG",
                                  "title": "Engineer confirm test",
                                  "cvssScore": 7.0
                                }
                                """))
                .andExpect(status().isCreated())
                .andReturn()
                .getResponse()
                .getContentAsString();

        long findingId = new com.fasterxml.jackson.databind.ObjectMapper()
                .readTree(response)
                .get("id")
                .asLong();

        mockMvc.perform(patch("/api/findings/" + findingId + "/confirm")
                        .header("Authorization", "Bearer " + engineerToken))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("Unknown endpoint is not publicly accessible")
    void unknownEndpointIsDenied() throws Exception {
        mockMvc.perform(get("/totally-unknown-path"))
                .andExpect(status().isUnauthorized());

        String viewerToken = login("viewer", "ViewerSecret123");
        mockMvc.perform(get("/totally-unknown-path")
                        .header("Authorization", "Bearer " + viewerToken))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("Swagger UI is closed when OpenAPI is disabled")
    void swaggerIsNotPublicWhenDisabled() throws Exception {
        mockMvc.perform(get("/swagger-ui.html"))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(get("/v3/api-docs"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Previously issued JWT is rejected after the account is disabled")
    void disabledUserJwtIsRejected() throws Exception {
        String token = login("viewer", "ViewerSecret123");

        mockMvc.perform(get("/api/findings")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());

        User viewer = userRepository.findByUsername("viewer").orElseThrow();
        viewer.setEnabled(false);
        userRepository.save(viewer);

        mockMvc.perform(get("/api/findings")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized());
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

        return new com.fasterxml.jackson.databind.ObjectMapper()
                .readTree(response)
                .get("token")
                .asText();
    }

    private String expiredToken(String username) {
        SecretKey key = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
        Instant issued = Instant.now().minus(2, ChronoUnit.HOURS);
        Instant expired = Instant.now().minus(1, ChronoUnit.HOURS);
        return Jwts.builder()
                .subject(username)
                .claim("role", "VIEWER")
                .issuedAt(Date.from(issued))
                .expiration(Date.from(expired))
                .signWith(key)
                .compact();
    }
}
