package com.vulntrack.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public record CreateScanRequest(
        @NotBlank String name,
        @NotBlank String source,
        @NotNull Long assetId
) {
}
