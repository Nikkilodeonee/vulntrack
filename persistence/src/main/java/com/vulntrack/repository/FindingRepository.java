package com.vulntrack.repository;

import com.vulntrack.domain.Finding;
import com.vulntrack.enums.FindingStatus;
import com.vulntrack.enums.RiskSeverity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDate;
import java.util.List;
import java.util.Optional;

public interface FindingRepository extends JpaRepository<Finding, Long>, JpaSpecificationExecutor<Finding> {

    Optional<Finding> findFirstByAsset_IdAndCveIdAndStatusNot(
            Long assetId,
            String cveId,
            FindingStatus excludedStatus
    );

    @Query("""
            select f from Finding f
            where f.dueDate < :today
              and f.escalated = false
              and f.status not in :terminalStatuses
            """)
    List<Finding> findOverdueNotEscalated(
            @Param("today") LocalDate today,
            @Param("terminalStatuses") List<FindingStatus> terminalStatuses
    );

    long countBySeverity(RiskSeverity severity);

    long countByStatus(FindingStatus status);

    long countByEscalatedTrue();
}
