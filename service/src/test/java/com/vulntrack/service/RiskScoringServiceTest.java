package com.vulntrack.service;

import com.vulntrack.enums.AssetCriticality;
import com.vulntrack.enums.RiskSeverity;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

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

    @ParameterizedTest
    @CsvSource({
            "0.00, LOW",
            "3.99, LOW",
            "4.00, MEDIUM",
            "6.99, MEDIUM",
            "7.00, HIGH",
            "8.99, HIGH",
            "9.00, CRITICAL",
            "10.00, CRITICAL"
    })
    void classifiesRiskScoreAtCategoryBoundaries(String riskScore, RiskSeverity expected) {
        assertThat(riskScoringService.determineSeverity(new BigDecimal(riskScore))).isEqualTo(expected);
    }

    @ParameterizedTest
    @CsvSource({
            "0.00, LOW, LOW",
            "3.99, LOW, LOW",
            "4.00, LOW, MEDIUM",
            "10.00, LOW, CRITICAL"
    })
    void cvssBoundariesWithLowCriticalityMatchRiskCategories(
            String cvss,
            AssetCriticality criticality,
            RiskSeverity expected
    ) {
        BigDecimal riskScore = riskScoringService.calculateRiskScore(new BigDecimal(cvss), criticality);
        assertThat(riskScoringService.determineSeverity(riskScore)).isEqualTo(expected);
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

