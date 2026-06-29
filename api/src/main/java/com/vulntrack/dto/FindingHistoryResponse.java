package com.vulntrack.dto;

import com.vulntrack.enums.FindingStatus;
import com.vulntrack.enums.UserRole;

import java.time.LocalDateTime;

public record FindingHistoryResponse(
        Long id,
        FindingStatus fromStatus,
        FindingStatus toStatus,
        String changedByUsername,
        UserRole changedByRole,
        LocalDateTime changedAt,
        String note
) {
}
