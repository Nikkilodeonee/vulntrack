package com.vulntrack.service;

import com.vulntrack.domain.Finding;
import com.vulntrack.domain.User;
import com.vulntrack.dto.AcceptRiskRequest;
import com.vulntrack.dto.AssignFindingRequest;
import com.vulntrack.dto.FindingResponse;
import com.vulntrack.enums.FindingStatus;
import com.vulntrack.enums.RiskSeverity;
import com.vulntrack.enums.UserRole;
import com.vulntrack.repository.FindingRepository;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;

@Service
public class FindingWorkflowService {

    private static final List<FindingStatus> TERMINAL_STATUSES = List.of(
            FindingStatus.CLOSED,
            FindingStatus.FALSE_POSITIVE,
            FindingStatus.ACCEPTED_RISK,
            FindingStatus.DUPLICATE
    );

    private final FindingRepository findingRepository;
    private final AuthService authService;
    private final RiskScoringService riskScoringService;
    private final FindingHistoryWriter historyWriter;
    private final FindingService findingService;
    private final Clock clock;

    public FindingWorkflowService(
            FindingRepository findingRepository,
            AuthService authService,
            RiskScoringService riskScoringService,
            FindingHistoryWriter historyWriter,
            FindingService findingService,
            Clock clock
    ) {
        this.findingRepository = findingRepository;
        this.authService = authService;
        this.riskScoringService = riskScoringService;
        this.historyWriter = historyWriter;
        this.findingService = findingService;
        this.clock = clock;
    }

    @Transactional
    public FindingResponse confirmFinding(long id, String actorUsername) {
        User actor = requireSecurityAnalyst(actorUsername);
        Finding finding = findingService.requireFinding(id);
        assertStatus(finding, FindingStatus.DETECTED, "Only DETECTED findings can be confirmed.");

        applyRiskAndDueDate(finding);
        transition(finding, FindingStatus.CONFIRMED, actor, "Finding confirmed by security analyst.");
        return findingService.toFindingResponse(finding);
    }

    @Transactional
    public FindingResponse assignFinding(long id, AssignFindingRequest request, String actorUsername) {
        User actor = authService.requireUser(actorUsername);
        requireAssignPermission(actor);

        Finding finding = findingService.requireFinding(id);
        assertStatus(finding, FindingStatus.CONFIRMED, "Only CONFIRMED findings can be assigned.");

        User engineer = authService.requireEngineer(request.engineerId());
        finding.setAssignedEngineer(engineer);
        transition(finding, FindingStatus.ASSIGNED, actor, "Assigned to " + engineer.getUsername() + ".");
        return findingService.toFindingResponse(finding);
    }

    @Transactional
    public FindingResponse startProgress(long id, String actorUsername) {
        User actor = authService.requireUser(actorUsername);
        Finding finding = findingService.requireFinding(id);
        assertStatus(finding, FindingStatus.ASSIGNED, "Only ASSIGNED findings can move to IN_PROGRESS.");
        requireAssignedEngineer(finding, actor);

        transition(finding, FindingStatus.IN_PROGRESS, actor, "Remediation started.");
        return findingService.toFindingResponse(finding);
    }

    @Transactional
    public FindingResponse markPatched(long id, String actorUsername) {
        User actor = authService.requireUser(actorUsername);
        Finding finding = findingService.requireFinding(id);
        assertStatus(finding, FindingStatus.IN_PROGRESS, "Only IN_PROGRESS findings can be marked as patched.");
        requireAssignedEngineer(finding, actor);

        transition(finding, FindingStatus.PATCHED, actor, "Patch applied by assigned engineer.");
        return findingService.toFindingResponse(finding);
    }

    @Transactional
    public FindingResponse verifyFinding(long id, String actorUsername) {
        User actor = requireSecurityAnalyst(actorUsername);
        Finding finding = findingService.requireFinding(id);
        assertStatus(finding, FindingStatus.PATCHED, "Only PATCHED findings can be verified.");

        transition(finding, FindingStatus.VERIFIED, actor, "Fix verified by security analyst.");
        return findingService.toFindingResponse(finding);
    }

    @Transactional
    public FindingResponse closeFinding(long id, String actorUsername) {
        User actor = requireSecurityAnalyst(actorUsername);
        Finding finding = findingService.requireFinding(id);
        assertStatus(finding, FindingStatus.VERIFIED, "A finding cannot be closed unless it was verified.");

        transition(finding, FindingStatus.CLOSED, actor, "Finding closed.");
        return findingService.toFindingResponse(finding);
    }

    @Transactional
    public FindingResponse markFalsePositive(long id, String actorUsername) {
        User actor = requireSecurityAnalyst(actorUsername);
        Finding finding = findingService.requireFinding(id);

        if (finding.getStatus() != FindingStatus.DETECTED && finding.getStatus() != FindingStatus.CONFIRMED) {
            throw new InvalidStateTransitionException("Only DETECTED or CONFIRMED findings can be marked as false positive.");
        }

        transition(finding, FindingStatus.FALSE_POSITIVE, actor, "Marked as false positive.");
        return findingService.toFindingResponse(finding);
    }

    @Transactional
    public FindingResponse acceptRisk(long id, AcceptRiskRequest request, String actorUsername) {
        User actor = requireSecurityAnalyst(actorUsername);
        Finding finding = findingService.requireFinding(id);
        assertStatus(finding, FindingStatus.CONFIRMED, "Only CONFIRMED findings can be accepted as risk.");

        if (request.expiresAt().isBefore(LocalDate.now(clock).plusDays(1))) {
            throw new IllegalArgumentException("Accepted risk expiration must be at least one day in the future.");
        }

        finding.setAcceptedRiskReason(request.reason());
        finding.setAcceptedRiskExpiresAt(request.expiresAt());
        transition(finding, FindingStatus.ACCEPTED_RISK, actor, "Risk accepted until " + request.expiresAt() + ".");
        return findingService.toFindingResponse(finding);
    }

    @Transactional
    public int escalateOverdueFindings() {
        List<Finding> overdueFindings = findingRepository.findOverdueNotEscalated(LocalDate.now(clock), TERMINAL_STATUSES);
        for (Finding finding : overdueFindings) {
            finding.setEscalated(true);
            finding.setEscalatedAt(LocalDateTime.now(clock));
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
        finding.setDueDate(riskScoringService.calculateDueDate(severity, LocalDate.now(clock)));
    }

    private void transition(Finding finding, FindingStatus toStatus, User actor, String note) {
        FindingStatus fromStatus = finding.getStatus();
        finding.setStatus(toStatus);
        findingRepository.saveAndFlush(finding);
        historyWriter.record(finding, fromStatus, toStatus, actor, note);
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
}
