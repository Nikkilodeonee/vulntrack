package com.vulntrack.service;

import com.vulntrack.enums.AssetCriticality;
import com.vulntrack.enums.RiskSeverity;
import org.springframework.stereotype.Component;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.time.LocalDate;

@Component
public class RiskScoringService {

    public BigDecimal calculateRiskScore(BigDecimal cvssScore, AssetCriticality criticality) {
        return cvssScore
                .multiply(BigDecimal.valueOf(criticality.getMultiplier()))
                .setScale(2, RoundingMode.HALF_UP);
    }

    public RiskSeverity determineSeverity(BigDecimal riskScore) {
        if (riskScore.compareTo(BigDecimal.valueOf(9.0)) >= 0) {
            return RiskSeverity.CRITICAL;
        }
        if (riskScore.compareTo(BigDecimal.valueOf(7.0)) >= 0) {
            return RiskSeverity.HIGH;
        }
        if (riskScore.compareTo(BigDecimal.valueOf(4.0)) >= 0) {
            return RiskSeverity.MEDIUM;
        }
        return RiskSeverity.LOW;
    }

    public LocalDate calculateDueDate(RiskSeverity severity, LocalDate fromDate) {
        return switch (severity) {
            case CRITICAL -> fromDate.plusDays(7);
            case HIGH -> fromDate.plusDays(14);
            case MEDIUM -> fromDate.plusDays(30);
            case LOW -> fromDate.plusDays(90);
        };
    }
}
