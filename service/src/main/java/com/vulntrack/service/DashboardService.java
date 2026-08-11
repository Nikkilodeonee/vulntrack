package com.vulntrack.service;

import com.vulntrack.dto.RiskSummaryResponse;
import com.vulntrack.enums.FindingStatus;
import com.vulntrack.enums.RiskSeverity;
import com.vulntrack.repository.FindingRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Service
public class DashboardService {

    private static final List<FindingStatus> TERMINAL_STATUSES = List.of(
            FindingStatus.CLOSED,
            FindingStatus.FALSE_POSITIVE,
            FindingStatus.ACCEPTED_RISK,
            FindingStatus.DUPLICATE
    );

    private final FindingRepository findingRepository;

    public DashboardService(FindingRepository findingRepository) {
        this.findingRepository = findingRepository;
    }

    @Transactional(readOnly = true)
    public RiskSummaryResponse getRiskSummary() {
        Map<String, Long> bySeverity = new LinkedHashMap<>();
        for (RiskSeverity severity : RiskSeverity.values()) {
            bySeverity.put(severity.name(), findingRepository.countBySeverity(severity));
        }

        Map<String, Long> byStatus = new LinkedHashMap<>();
        for (FindingStatus status : FindingStatus.values()) {
            byStatus.put(status.name(), findingRepository.countByStatus(status));
        }

        long overdueCount = findingRepository.findOverdueNotEscalated(LocalDate.now(), TERMINAL_STATUSES).size();
        long escalatedCount = findingRepository.countByEscalatedTrue();

        return new RiskSummaryResponse(bySeverity, byStatus, overdueCount, escalatedCount);
    }
}
