package com.vulntrack.dto;

import jakarta.validation.constraints.DecimalMax;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.math.BigDecimal;

public record CreateFindingRequest(
        @NotNull Long assetId,
        Long scanId,
        @NotBlank String cveId,
        @NotBlank String title,
        String description,
        @NotNull @DecimalMin("0.0") @DecimalMax("10.0") BigDecimal cvssScore
) {
}
