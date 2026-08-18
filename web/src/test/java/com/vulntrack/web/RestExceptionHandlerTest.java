package com.vulntrack.web;

import com.vulntrack.domain.Finding;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.orm.ObjectOptimisticLockingFailureException;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class RestExceptionHandlerTest {

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(new ConflictProbeController())
                .setControllerAdvice(new RestExceptionHandler())
                .build();
    }

    @Test
    void optimisticLockFailureReturns409WithoutJpaDetails() throws Exception {
        mockMvc.perform(get("/probe/optimistic-lock"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error").value("CONFLICT"))
                .andExpect(jsonPath("$.message").value("The finding was updated by another request. Reload and retry."));
    }

    @Test
    void duplicateCanonicalIndexReturns409() throws Exception {
        mockMvc.perform(get("/probe/duplicate-index"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error").value("CONFLICT"))
                .andExpect(jsonPath("$.message").value("A finding for this asset and CVE already exists."));
    }

    @RestController
    static class ConflictProbeController {

        @GetMapping("/probe/optimistic-lock")
        void optimisticLock() {
            throw new ObjectOptimisticLockingFailureException(Finding.class, 1L);
        }

        @GetMapping("/probe/duplicate-index")
        void duplicateIndex() {
            throw new DataIntegrityViolationException(
                    "ERROR: duplicate key value violates unique constraint \"uq_finding_canonical_asset_cve\""
            );
        }
    }
}
