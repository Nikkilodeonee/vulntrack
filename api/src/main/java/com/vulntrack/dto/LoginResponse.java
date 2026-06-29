package com.vulntrack.dto;

import com.vulntrack.enums.UserRole;

public record LoginResponse(
        String token,
        String tokenType,
        String username,
        UserRole role
) {
}
