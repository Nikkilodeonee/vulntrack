package com.vulntrack.dto;

import java.time.LocalDateTime;

public record ScanResponse(
        Long id,
        String name,
        String source,
        Long assetId,
        String assetName,
        LocalDateTime scannedAt
) {
}
