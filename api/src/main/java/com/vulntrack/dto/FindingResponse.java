package com.vulntrack.dto;

import com.vulntrack.enums.FindingStatus;
import com.vulntrack.enums.RiskSeverity;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.LocalDateTime;

public record FindingResponse(
        Long id,
        Long assetId,
        String assetName,
        Long scanId,
        String cveId,
        String title,
        String description,
        BigDecimal cvssScore,
        BigDecimal riskScore,
        RiskSeverity severity,
        FindingStatus status,
        LocalDate dueDate,
        String assignedEngineerUsername,
        String acceptedRiskReason,
        LocalDate acceptedRiskExpiresAt,
        boolean escalated,
        LocalDateTime escalatedAt,
        Long duplicateOfId,
        LocalDateTime createdAt,
        LocalDateTime updatedAt
) {
}
