package com.vulntrack.service;

import com.vulntrack.domain.Finding;
import com.vulntrack.domain.FindingHistory;
import com.vulntrack.enums.FindingStatus;
import com.vulntrack.domain.User;
import com.vulntrack.repository.FindingHistoryRepository;
import org.springframework.stereotype.Component;

@Component
public class FindingHistoryWriter {

    private final FindingHistoryRepository findingHistoryRepository;

    public FindingHistoryWriter(FindingHistoryRepository findingHistoryRepository) {
        this.findingHistoryRepository = findingHistoryRepository;
    }

    public void record(Finding finding, FindingStatus fromStatus, FindingStatus toStatus, User actor, String note) {
        findingHistoryRepository.save(new FindingHistory(finding, fromStatus, toStatus, actor, note));
    }
}
