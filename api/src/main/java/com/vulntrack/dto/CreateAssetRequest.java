package com.vulntrack.dto;

import com.vulntrack.enums.AssetCriticality;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public record CreateAssetRequest(
        @NotBlank String name,
        String hostname,
        String ipAddress,
        @NotNull AssetCriticality criticality
) {
}
