package com.vulntrack.service;

import com.vulntrack.domain.Asset;
import com.vulntrack.domain.Comment;
import com.vulntrack.domain.Finding;
import com.vulntrack.domain.FindingHistory;
import com.vulntrack.domain.Scan;
import com.vulntrack.domain.User;
import com.vulntrack.dto.CommentResponse;
import com.vulntrack.dto.CreateCommentRequest;
import com.vulntrack.dto.CreateFindingRequest;
import com.vulntrack.dto.FindingHistoryResponse;
import com.vulntrack.dto.FindingResponse;
import com.vulntrack.enums.FindingStatus;
import com.vulntrack.enums.RiskSeverity;
import com.vulntrack.repository.AssetRepository;
import com.vulntrack.repository.CommentRepository;
import com.vulntrack.repository.FindingHistoryRepository;
import com.vulntrack.repository.FindingRepository;
import com.vulntrack.repository.ScanRepository;
import jakarta.persistence.criteria.Predicate;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.NoSuchElementException;

@Service
public class FindingService {

    private final AssetRepository assetRepository;
    private final ScanRepository scanRepository;
    private final FindingRepository findingRepository;
    private final FindingHistoryRepository findingHistoryRepository;
    private final CommentRepository commentRepository;
    private final AuthService authService;
    private final FindingHistoryWriter historyWriter;

    public FindingService(
            AssetRepository assetRepository,
            ScanRepository scanRepository,
            FindingRepository findingRepository,
            FindingHistoryRepository findingHistoryRepository,
            CommentRepository commentRepository,
            AuthService authService,
            FindingHistoryWriter historyWriter
    ) {
        this.assetRepository = assetRepository;
        this.scanRepository = scanRepository;
        this.findingRepository = findingRepository;
        this.findingHistoryRepository = findingHistoryRepository;
        this.commentRepository = commentRepository;
        this.authService = authService;
        this.historyWriter = historyWriter;
    }

    @Transactional
    public FindingResponse createFinding(CreateFindingRequest request, String actorUsername) {
        Asset asset = assetRepository.findById(request.assetId())
                .orElseThrow(() -> new NoSuchElementException("Asset not found."));

        if (!asset.isActive()) {
            throw new IllegalArgumentException("Inactive assets cannot receive new findings.");
        }

        Scan scan = null;
        if (request.scanId() != null) {
            scan = scanRepository.findById(request.scanId())
                    .orElseThrow(() -> new NoSuchElementException("Scan not found."));
            if (!scan.getAsset().getId().equals(asset.getId())) {
                throw new IllegalArgumentException("Scan does not belong to the specified asset.");
            }
        }

        User actor = authService.requireUser(actorUsername);
        Finding finding = new Finding(
                asset,
                scan,
                request.cveId(),
                request.title(),
                request.description(),
                request.cvssScore()
        );

        var existing = findingRepository.findFirstByAsset_IdAndCveIdAndStatusNot(
                asset.getId(),
                request.cveId(),
                FindingStatus.DUPLICATE
        );

        if (existing.isPresent()) {
            finding.setStatus(FindingStatus.DUPLICATE);
            finding.setDuplicateOf(existing.get());
            finding = findingRepository.save(finding);
            historyWriter.record(finding, null, FindingStatus.DUPLICATE, actor, "Duplicate of finding #" + existing.get().getId());
            return toFindingResponse(finding);
        }

        finding = findingRepository.save(finding);
        historyWriter.record(finding, null, FindingStatus.DETECTED, actor, "Finding imported from scan results.");
        return toFindingResponse(finding);
    }

    @Transactional(readOnly = true)
    public List<FindingResponse> getFindings(RiskSeverity severity, FindingStatus status) {
        Specification<Finding> spec = (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();
            if (severity != null) {
                predicates.add(cb.equal(root.get("severity"), severity));
            }
            if (status != null) {
                predicates.add(cb.equal(root.get("status"), status));
            }
            return cb.and(predicates.toArray(Predicate[]::new));
        };

        return findingRepository.findAll(spec).stream().map(this::toFindingResponse).toList();
    }

    @Transactional(readOnly = true)
    public FindingResponse getFinding(long id) {
        return toFindingResponse(requireFinding(id));
    }

    @Transactional(readOnly = true)
    public List<FindingHistoryResponse> getFindingHistory(long id) {
        requireFinding(id);
        return findingHistoryRepository.findByFinding_IdOrderByChangedAtAsc(id).stream()
                .map(this::toHistoryResponse)
                .toList();
    }

    @Transactional
    public CommentResponse addComment(long id, CreateCommentRequest request, String actorUsername) {
        Finding finding = requireFinding(id);
        User actor = authService.requireUser(actorUsername);
        Comment comment = commentRepository.save(new Comment(finding, actor, request.content()));
        return toCommentResponse(comment);
    }

    @Transactional(readOnly = true)
    public List<CommentResponse> getComments(long id) {
        requireFinding(id);
        return commentRepository.findByFinding_IdOrderByCreatedAtAsc(id).stream()
                .map(this::toCommentResponse)
                .toList();
    }

    Finding requireFinding(long id) {
        return findingRepository.findById(id)
                .orElseThrow(() -> new NoSuchElementException("Finding not found."));
    }

    FindingResponse toFindingResponse(Finding finding) {
        return new FindingResponse(
                finding.getId(),
                finding.getAsset().getId(),
                finding.getAsset().getName(),
                finding.getScan() != null ? finding.getScan().getId() : null,
                finding.getCveId(),
                finding.getTitle(),
                finding.getDescription(),
                finding.getCvssScore(),
                finding.getRiskScore(),
                finding.getSeverity(),
                finding.getStatus(),
                finding.getDueDate(),
                finding.getAssignedEngineer() != null ? finding.getAssignedEngineer().getUsername() : null,
                finding.getAcceptedRiskReason(),
                finding.getAcceptedRiskExpiresAt(),
                finding.isEscalated(),
                finding.getEscalatedAt(),
                finding.getDuplicateOf() != null ? finding.getDuplicateOf().getId() : null,
                finding.getCreatedAt(),
                finding.getUpdatedAt()
        );
    }

    private FindingHistoryResponse toHistoryResponse(FindingHistory history) {
        User changedBy = history.getChangedBy();
        return new FindingHistoryResponse(
                history.getId(),
                history.getFromStatus(),
                history.getToStatus(),
                changedBy != null ? changedBy.getUsername() : "system",
                changedBy != null ? changedBy.getRole() : null,
                history.getChangedAt(),
                history.getNote()
        );
    }

    private CommentResponse toCommentResponse(Comment comment) {
        return new CommentResponse(
                comment.getId(),
                comment.getAuthor().getUsername(),
                comment.getContent(),
                comment.getCreatedAt()
        );
    }
}
