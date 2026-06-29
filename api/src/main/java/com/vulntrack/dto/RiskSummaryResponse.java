package com.vulntrack.dto;

import java.util.Map;

public record RiskSummaryResponse(
        Map<String, Long> bySeverity,
        Map<String, Long> byStatus,
        long overdueCount,
        long escalatedCount
) {
}
