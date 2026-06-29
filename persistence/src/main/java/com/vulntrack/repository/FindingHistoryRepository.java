package com.vulntrack.repository;

import com.vulntrack.domain.FindingHistory;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface FindingHistoryRepository extends JpaRepository<FindingHistory, Long> {

    List<FindingHistory> findByFinding_IdOrderByChangedAtAsc(Long findingId);
}
