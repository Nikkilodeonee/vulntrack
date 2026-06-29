package com.vulntrack.service;

import com.vulntrack.enums.AssetCriticality;
import com.vulntrack.enums.RiskSeverity;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.time.LocalDate;

import static org.assertj.core.api.Assertions.assertThat;

class RiskScoringServiceTest {

    private final RiskScoringService riskScoringService = new RiskScoringService();

    @Test
    void calculatesRiskScoreWithAssetCriticalityMultiplier() {
        BigDecimal score = riskScoringService.calculateRiskScore(
                BigDecimal.valueOf(9.8),
                AssetCriticality.CRITICAL
        );

        assertThat(score).isEqualByComparingTo("19.60");
        assertThat(riskScoringService.determineSeverity(score)).isEqualTo(RiskSeverity.CRITICAL);
    }

    @Test
    void assignsSlaDeadlinesBySeverity() {
        LocalDate today = LocalDate.of(2026, 6, 28);

        assertThat(riskScoringService.calculateDueDate(RiskSeverity.CRITICAL, today))
                .isEqualTo(today.plusDays(7));
        assertThat(riskScoringService.calculateDueDate(RiskSeverity.HIGH, today))
                .isEqualTo(today.plusDays(14));
        assertThat(riskScoringService.calculateDueDate(RiskSeverity.MEDIUM, today))
                .isEqualTo(today.plusDays(30));
        assertThat(riskScoringService.calculateDueDate(RiskSeverity.LOW, today))
                .isEqualTo(today.plusDays(90));
    }
}
