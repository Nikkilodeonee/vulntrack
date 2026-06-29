package com.vulntrack.dto;

import jakarta.validation.constraints.Future;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.time.LocalDate;

public record AcceptRiskRequest(
        @NotBlank String reason,
        @NotNull @Future LocalDate expiresAt
) {
}
