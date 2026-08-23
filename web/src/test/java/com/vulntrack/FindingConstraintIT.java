package com.vulntrack;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

class FindingConstraintIT extends AbstractPostgresIT {

    @Autowired
    private JdbcTemplate jdbcTemplate;

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
