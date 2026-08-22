package com.vulntrack;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.vulntrack.domain.Finding;
import com.vulntrack.domain.FindingHistory;
import com.vulntrack.domain.User;
import com.vulntrack.enums.FindingStatus;
import com.vulntrack.repository.FindingHistoryRepository;
import com.vulntrack.repository.FindingRepository;
import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityManagerFactory;
import jakarta.persistence.OptimisticLockException;
import org.hibernate.StaleObjectStateException;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.orm.ObjectOptimisticLockingFailureException;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class FindingConcurrencyIT extends AbstractPostgresIT {

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private ObjectMapper objectMapper;
    @Autowired
    private EntityManagerFactory entityManagerFactory;
    @Autowired
    private FindingRepository findingRepository;
    @Autowired
    private FindingHistoryRepository findingHistoryRepository;

    @Test
    void concurrentWorkflowUpdatesOnSameVersionProduceOneWinnerAnd409Loser() throws Exception {
        String jwt = loginAnalyst();
        long findingId = createFinding(jwt, "CVE-2024-LOCK-01", "Optimistic lock finding");

        EntityManager em1 = entityManagerFactory.createEntityManager();
        EntityManager em2 = entityManagerFactory.createEntityManager();
        try {
            em1.getTransaction().begin();
            em2.getTransaction().begin();

            Finding first = em1.find(Finding.class, findingId);
            Finding second = em2.find(Finding.class, findingId);
            assertThat(first.getVersion()).isEqualTo(second.getVersion());
            Long sharedVersion = first.getVersion();
            assertThat(sharedVersion).isNotNull();

            User analyst1 = em1.createQuery("select u from User u where u.username = :username", User.class)
                    .setParameter("username", "analyst")
                    .getSingleResult();
            User analyst2 = em2.createQuery("select u from User u where u.username = :username", User.class)
                    .setParameter("username", "analyst")
                    .getSingleResult();

            first.setStatus(FindingStatus.CONFIRMED);
            em1.persist(new FindingHistory(
                    first,
                    FindingStatus.DETECTED,
                    FindingStatus.CONFIRMED,
                    analyst1,
                    "Confirmed in first transaction."
            ));
            em1.flush();
            em1.getTransaction().commit();

            second.setStatus(FindingStatus.FALSE_POSITIVE);
            em2.persist(new FindingHistory(
                    second,
                    FindingStatus.DETECTED,
                    FindingStatus.FALSE_POSITIVE,
                    analyst2,
                    "False positive in stale transaction."
            ));

            boolean staleUpdateRejected = false;
            try {
                em2.flush();
                em2.getTransaction().commit();
            } catch (RuntimeException exception) {
                staleUpdateRejected = isOptimisticLockFailure(exception);
                if (em2.getTransaction().isActive()) {
                    em2.getTransaction().rollback();
                }
                if (!staleUpdateRejected) {
                    throw exception;
                }
            }

            assertThat(staleUpdateRejected).isTrue();
        } finally {
            if (em1.getTransaction().isActive()) {
                em1.getTransaction().rollback();
            }
            if (em2.getTransaction().isActive()) {
                em2.getTransaction().rollback();
            }
            em1.close();
            em2.close();
        }

        Finding persisted = findingRepository.findById(findingId).orElseThrow();
        assertThat(persisted.getStatus()).isEqualTo(FindingStatus.CONFIRMED);
        assertThat(persisted.getVersion()).isGreaterThan(0L);

        List<FindingHistory> history = findingHistoryRepository.findByFinding_IdOrderByChangedAtAsc(findingId);
        assertThat(history).extracting(FindingHistory::getToStatus)
                .contains(FindingStatus.DETECTED, FindingStatus.CONFIRMED)
                .doesNotContain(FindingStatus.FALSE_POSITIVE);
    }

    @Test
    void concurrentCanonicalImportsLeaveExactlyOneNonDuplicateFinding() throws Exception {
        String jwt = loginAnalyst();
        String body = """
                {
                  "assetId": 1,
                  "cveId": "CVE-2024-DUP-CONCURRENT",
                  "title": "Concurrent duplicate import",
                  "cvssScore": 5.0
                }
                """;

        CyclicBarrier start = new CyclicBarrier(2);
        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            Callable<MvcResult> importFinding = () -> {
                start.await(10, TimeUnit.SECONDS);
                return mockMvc.perform(post("/api/findings")
                                .header("Authorization", "Bearer " + jwt)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(body))
                        .andReturn();
            };

            Future<MvcResult> first = executor.submit(importFinding);
            Future<MvcResult> second = executor.submit(importFinding);
            MvcResult result1 = first.get(20, TimeUnit.SECONDS);
            MvcResult result2 = second.get(20, TimeUnit.SECONDS);

            int status1 = result1.getResponse().getStatus();
            int status2 = result2.getResponse().getStatus();
            assertThat(List.of(status1, status2)).allMatch(code -> code == 201 || code == 409);
            assertThat(List.of(status1, status2)).contains(201);

            long canonicalCount = findingRepository.findAll().stream()
                    .filter(finding -> "CVE-2024-DUP-CONCURRENT".equals(finding.getCveId()))
                    .filter(finding -> finding.getStatus() != FindingStatus.DUPLICATE)
                    .count();
            assertThat(canonicalCount).isEqualTo(1);

            if (status1 == 409 || status2 == 409) {
                String conflictBody = (status1 == 409 ? result1 : result2).getResponse().getContentAsString();
                JsonNode error = objectMapper.readTree(conflictBody);
                assertThat(error.get("error").asText()).isEqualTo("CONFLICT");
                assertThat(error.get("message").asText()).doesNotContain("PSQLException");
            }
        } finally {
            executor.shutdownNow();
        }
    }

    private String loginAnalyst() throws Exception {
        String loginResponse = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"analyst","password":"AnalystSecret123"}
                                """))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();
        return objectMapper.readTree(loginResponse).get("token").asText();
    }

    private long createFinding(String jwt, String cveId, String title) throws Exception {
        String createResponse = mockMvc.perform(post("/api/findings")
                        .header("Authorization", "Bearer " + jwt)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "assetId": 1,
                                  "cveId": "%s",
                                  "title": "%s",
                                  "cvssScore": 7.5
                                }
                                """.formatted(cveId, title)))
                .andExpect(status().isCreated())
                .andReturn()
                .getResponse()
                .getContentAsString();
        return objectMapper.readTree(createResponse).get("id").asLong();
    }

    private static boolean isOptimisticLockFailure(Throwable exception) {
        Throwable current = exception;
        while (current != null) {
            if (current instanceof OptimisticLockException
                    || current instanceof StaleObjectStateException
                    || current instanceof ObjectOptimisticLockingFailureException) {
                return true;
            }
            current = current.getCause();
        }
        return false;
    }
}
