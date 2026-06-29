package com.vulntrack.dto;

import jakarta.validation.constraints.NotNull;

public record AssignFindingRequest(
        @NotNull Long engineerId
) {
}
