package com.vulntrack.dto;

import com.vulntrack.enums.AssetCriticality;

import java.time.LocalDateTime;

public record AssetResponse(
        Long id,
        String name,
        String hostname,
        String ipAddress,
        AssetCriticality criticality,
        boolean active,
        LocalDateTime createdAt
) {
}
