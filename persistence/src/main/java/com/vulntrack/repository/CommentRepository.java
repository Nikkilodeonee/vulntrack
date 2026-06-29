package com.vulntrack.repository;

import com.vulntrack.domain.Comment;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface CommentRepository extends JpaRepository<Comment, Long> {

    List<Comment> findByFinding_IdOrderByCreatedAtAsc(Long findingId);
}
