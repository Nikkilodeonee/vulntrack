package com.vulntrack;

import com.vulntrack.domain.Finding;
import com.vulntrack.dto.CreateFindingRequest;
import com.vulntrack.repository.AssetRepository;
import com.vulntrack.repository.FindingRepository;
import com.vulntrack.service.FindingConstraintViolations;
import com.vulntrack.service.FindingService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.JdbcTemplate;

import java.math.BigDecimal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class FindingConstraintIT extends AbstractPostgresIT {

    @Autowired
    private JdbcTemplate jdbcTemplate;
    @Autowired
    private FindingService findingService;
    @Autowired
    private FindingRepository findingRepository;
    @Autowired
    private AssetRepository assetRepository;

    @Test
    void actualPostgresUniqueViolationIsRecognizedByConstraintMetadata() {
        var asset = assetRepository.findById(1L).orElseThrow();
        findingRepository.saveAndFlush(new Finding(asset, null, "CVE-TEST-UNIQUE", "First", null, BigDecimal.ONE));

        assertThatThrownBy(() -> findingRepository.saveAndFlush(
                new Finding(asset, null, "CVE-TEST-UNIQUE", "Second", null, BigDecimal.ONE)))
                .isInstanceOf(DataIntegrityViolationException.class)
                .satisfies(exception -> assertThat(FindingConstraintViolations.isCanonicalDuplicate(exception)).isTrue());
    }

    @Test
    void serviceDoesNotDescribePostgresCheckViolationAsDuplicate() {
        var request = new CreateFindingRequest(1L, null, "CVE-TEST-CHECK", "Invalid score", null,
                new BigDecimal("10.01"));

        assertThatThrownBy(() -> findingService.createFinding(request, "analyst"))
                .isInstanceOf(DataIntegrityViolationException.class)
                .hasMessageContaining("chk_finding_cvss_score")
                .satisfies(exception -> assertThat(FindingConstraintViolations.isCanonicalDuplicate(exception)).isFalse());
        assertThat(jdbcTemplate.queryForObject("SELECT COUNT(*) FROM finding WHERE cve_id = 'CVE-TEST-CHECK'", Long.class))
                .isZero();
    }

    @Test
    void rejectsCvssScoreOutsideZeroToTen() {
        assertThatThrownBy(() -> jdbcTemplate.update("""
                        INSERT INTO finding (
                            asset_id, cve_id, title, cvss_score, status, escalated, created_at, updated_at, version
                        ) VALUES (1, 'CVE-2024-CVSS-BAD', 'Invalid CVSS', 10.01, 'DETECTED', FALSE, NOW(), NOW(), 0)
                        """))
                .hasMessageContaining("chk_finding_cvss_score");
    }

    @Test
    void rejectsEscalatedFindingWithoutTimestamp() {
        assertThatThrownBy(() -> jdbcTemplate.update("""
                        INSERT INTO finding (
                            asset_id, cve_id, title, cvss_score, status, escalated, escalated_at, created_at, updated_at, version
                        ) VALUES (1, 'CVE-2024-ESC-BAD', 'Invalid escalation', 5.00, 'DETECTED', TRUE, NULL, NOW(), NOW(), 0)
                        """))
                .hasMessageContaining("chk_finding_escalation_timestamp");
    }
}
