package com.vulntrack.service;

import com.vulntrack.domain.*;
import com.vulntrack.dto.*;
import com.vulntrack.enums.*;
import com.vulntrack.repository.*;
import jakarta.persistence.criteria.Predicate;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;

@Service
public class VulnTrackService {

    private static final List<FindingStatus> TERMINAL_STATUSES = List.of(
            FindingStatus.CLOSED,
            FindingStatus.FALSE_POSITIVE,
            FindingStatus.ACCEPTED_RISK,
            FindingStatus.DUPLICATE
    );

    private final AssetRepository assetRepository;
    private final ScanRepository scanRepository;
    private final FindingRepository findingRepository;
    private final FindingHistoryRepository findingHistoryRepository;
    private final CommentRepository commentRepository;
    private final UserRepository userRepository;
    private final AuthService authService;
    private final RiskScoringService riskScoringService;
    private final FindingHistoryWriter historyWriter;

    public VulnTrackService(
            AssetRepository assetRepository,
            ScanRepository scanRepository,
            FindingRepository findingRepository,
            FindingHistoryRepository findingHistoryRepository,
            CommentRepository commentRepository,
            UserRepository userRepository,
            AuthService authService,
            RiskScoringService riskScoringService,
            FindingHistoryWriter historyWriter
    ) {
        this.assetRepository = assetRepository;
        this.scanRepository = scanRepository;
        this.findingRepository = findingRepository;
        this.findingHistoryRepository = findingHistoryRepository;
        this.commentRepository = commentRepository;
        this.userRepository = userRepository;
        this.authService = authService;
        this.riskScoringService = riskScoringService;
        this.historyWriter = historyWriter;
    }

    @Transactional
    public AssetResponse createAsset(CreateAssetRequest request) {
        Asset asset = assetRepository.save(new Asset(
                request.name(),
                request.hostname(),
                request.ipAddress(),
                request.criticality()
        ));
        return toAssetResponse(asset);
    }

    @Transactional(readOnly = true)
    public List<AssetResponse> getAssets() {
        return assetRepository.findAll().stream().map(this::toAssetResponse).toList();
    }

    @Transactional
    public ScanResponse createScan(CreateScanRequest request) {
        Asset asset = assetRepository.findById(request.assetId())
                .orElseThrow(() -> new NoSuchElementException("Asset not found."));

        if (!asset.isActive()) {
            throw new IllegalArgumentException("Inactive assets cannot receive scans.");
        }

        Scan scan = scanRepository.save(new Scan(request.name(), request.source(), asset));
        return toScanResponse(scan);
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

    @Transactional
    public FindingResponse confirmFinding(long id, String actorUsername) {
        User actor = requireSecurityAnalyst(actorUsername);
        Finding finding = requireFinding(id);
        assertStatus(finding, FindingStatus.DETECTED, "Only DETECTED findings can be confirmed.");

        applyRiskAndDueDate(finding);

        transition(finding, FindingStatus.CONFIRMED, actor, "Finding confirmed by security analyst.");
        return toFindingResponse(finding);
    }

    @Transactional
    public FindingResponse assignFinding(long id, AssignFindingRequest request, String actorUsername) {
        User actor = authService.requireUser(actorUsername);
        requireAssignPermission(actor);

        Finding finding = requireFinding(id);
        assertStatus(finding, FindingStatus.CONFIRMED, "Only CONFIRMED findings can be assigned.");

        User engineer = authService.requireEngineer(request.engineerId());
        finding.setAssignedEngineer(engineer);
        transition(finding, FindingStatus.ASSIGNED, actor, "Assigned to " + engineer.getUsername() + ".");
        return toFindingResponse(finding);
    }

    @Transactional
    public FindingResponse startProgress(long id, String actorUsername) {
        User actor = authService.requireUser(actorUsername);
        Finding finding = requireFinding(id);
        assertStatus(finding, FindingStatus.ASSIGNED, "Only ASSIGNED findings can move to IN_PROGRESS.");
        requireAssignedEngineer(finding, actor);

        transition(finding, FindingStatus.IN_PROGRESS, actor, "Remediation started.");
        return toFindingResponse(finding);
    }

    @Transactional
    public FindingResponse markPatched(long id, String actorUsername) {
        User actor = authService.requireUser(actorUsername);
        Finding finding = requireFinding(id);
        assertStatus(finding, FindingStatus.IN_PROGRESS, "Only IN_PROGRESS findings can be marked as patched.");
        requireAssignedEngineer(finding, actor);

        transition(finding, FindingStatus.PATCHED, actor, "Patch applied by assigned engineer.");
        return toFindingResponse(finding);
    }

    @Transactional
    public FindingResponse verifyFinding(long id, String actorUsername) {
        User actor = requireSecurityAnalyst(actorUsername);
        Finding finding = requireFinding(id);
        assertStatus(finding, FindingStatus.PATCHED, "Only PATCHED findings can be verified.");

        transition(finding, FindingStatus.VERIFIED, actor, "Fix verified by security analyst.");
        return toFindingResponse(finding);
    }

    @Transactional
    public FindingResponse closeFinding(long id, String actorUsername) {
        User actor = requireSecurityAnalyst(actorUsername);
        Finding finding = requireFinding(id);
        assertStatus(finding, FindingStatus.VERIFIED, "A finding cannot be closed unless it was verified.");

        transition(finding, FindingStatus.CLOSED, actor, "Finding closed.");
        return toFindingResponse(finding);
    }

    @Transactional
    public FindingResponse markFalsePositive(long id, String actorUsername) {
        User actor = requireSecurityAnalyst(actorUsername);
        Finding finding = requireFinding(id);

        if (finding.getStatus() != FindingStatus.DETECTED && finding.getStatus() != FindingStatus.CONFIRMED) {
            throw new InvalidStateTransitionException("Only DETECTED or CONFIRMED findings can be marked as false positive.");
        }

        transition(finding, FindingStatus.FALSE_POSITIVE, actor, "Marked as false positive.");
        return toFindingResponse(finding);
    }

    @Transactional
    public FindingResponse acceptRisk(long id, AcceptRiskRequest request, String actorUsername) {
        User actor = requireSecurityAnalyst(actorUsername);
        Finding finding = requireFinding(id);
        assertStatus(finding, FindingStatus.CONFIRMED, "Only CONFIRMED findings can be accepted as risk.");

        if (request.expiresAt().isBefore(LocalDate.now().plusDays(1))) {
            throw new IllegalArgumentException("Accepted risk expiration must be at least one day in the future.");
        }

        finding.setAcceptedRiskReason(request.reason());
        finding.setAcceptedRiskExpiresAt(request.expiresAt());
        transition(finding, FindingStatus.ACCEPTED_RISK, actor, "Risk accepted until " + request.expiresAt() + ".");
        return toFindingResponse(finding);
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

    @Transactional(readOnly = true)
    public RiskSummaryResponse getRiskSummary() {
        Map<String, Long> bySeverity = new LinkedHashMap<>();
        for (RiskSeverity severity : RiskSeverity.values()) {
            bySeverity.put(severity.name(), findingRepository.countBySeverity(severity));
        }

        Map<String, Long> byStatus = new LinkedHashMap<>();
        for (FindingStatus status : FindingStatus.values()) {
            byStatus.put(status.name(), findingRepository.countByStatus(status));
        }

        long overdueCount = findingRepository.findOverdueNotEscalated(LocalDate.now(), TERMINAL_STATUSES).size();
        long escalatedCount = findingRepository.countByEscalatedTrue();

        return new RiskSummaryResponse(bySeverity, byStatus, overdueCount, escalatedCount);
    }

    @Transactional
    public int escalateOverdueFindings() {
        List<Finding> overdueFindings = findingRepository.findOverdueNotEscalated(LocalDate.now(), TERMINAL_STATUSES);
        for (Finding finding : overdueFindings) {
            finding.setEscalated(true);
            finding.setEscalatedAt(LocalDateTime.now());
            findingRepository.save(finding);
            historyWriter.record(
                    finding,
                    finding.getStatus(),
                    finding.getStatus(),
                    null,
                    "Automatically escalated due to missed SLA deadline."
            );
        }
        return overdueFindings.size();
    }

    private void applyRiskAndDueDate(Finding finding) {
        var riskScore = riskScoringService.calculateRiskScore(
                finding.getCvssScore(),
                finding.getAsset().getCriticality()
        );
        RiskSeverity severity = riskScoringService.determineSeverity(riskScore);
        finding.setRiskScore(riskScore);
        finding.setSeverity(severity);
        finding.setDueDate(riskScoringService.calculateDueDate(severity, LocalDate.now()));
    }

    private void transition(Finding finding, FindingStatus toStatus, User actor, String note) {
        FindingStatus fromStatus = finding.getStatus();
        finding.setStatus(toStatus);
        findingRepository.save(finding);
        historyWriter.record(finding, fromStatus, toStatus, actor, note);
    }

    private Finding requireFinding(long id) {
        return findingRepository.findById(id)
                .orElseThrow(() -> new NoSuchElementException("Finding not found."));
    }

    private User requireSecurityAnalyst(String username) {
        User user = authService.requireUser(username);
        if (user.getRole() != UserRole.SECURITY_ANALYST && user.getRole() != UserRole.ADMIN) {
            throw new AccessDeniedException("Only security analysts can perform this action.");
        }
        return user;
    }

    private void requireAssignPermission(User actor) {
        if (actor.getRole() != UserRole.ADMIN
                && actor.getRole() != UserRole.SECURITY_ANALYST) {
            throw new AccessDeniedException("Only admins or security analysts can assign findings.");
        }
    }

    private void requireAssignedEngineer(Finding finding, User actor) {
        if (finding.getAssignedEngineer() == null
                || !finding.getAssignedEngineer().getId().equals(actor.getId())) {
            throw new AccessDeniedException("Only the assigned engineer can perform this action.");
        }
    }

    private void assertStatus(Finding finding, FindingStatus expected, String message) {
        if (finding.getStatus() != expected) {
            throw new InvalidStateTransitionException(message);
        }
    }

    private AssetResponse toAssetResponse(Asset asset) {
        return new AssetResponse(
                asset.getId(),
                asset.getName(),
                asset.getHostname(),
                asset.getIpAddress(),
                asset.getCriticality(),
                asset.isActive(),
                asset.getCreatedAt()
        );
    }

    private ScanResponse toScanResponse(Scan scan) {
        return new ScanResponse(
                scan.getId(),
                scan.getName(),
                scan.getSource(),
                scan.getAsset().getId(),
                scan.getAsset().getName(),
                scan.getScannedAt()
        );
    }

    private FindingResponse toFindingResponse(Finding finding) {
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
