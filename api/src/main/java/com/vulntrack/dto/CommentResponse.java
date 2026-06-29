package com.vulntrack.dto;

import java.time.LocalDateTime;

public record CommentResponse(
        Long id,
        String authorUsername,
        String content,
        LocalDateTime createdAt
) {
}
