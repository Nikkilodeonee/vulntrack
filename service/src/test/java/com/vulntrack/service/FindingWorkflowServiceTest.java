package com.vulntrack.service;

import com.vulntrack.domain.Asset;
import com.vulntrack.domain.Finding;
import com.vulntrack.domain.User;
import com.vulntrack.dto.AcceptRiskRequest;
import com.vulntrack.dto.AssignFindingRequest;
import com.vulntrack.dto.FindingResponse;
import com.vulntrack.enums.AssetCriticality;
import com.vulntrack.enums.FindingStatus;
import com.vulntrack.enums.RiskSeverity;
import com.vulntrack.enums.UserRole;
import com.vulntrack.repository.FindingRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.test.util.ReflectionTestUtils;

import java.math.BigDecimal;
import java.time.Clock;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class FindingWorkflowServiceTest {

    @Mock
    private FindingRepository findingRepository;
    @Mock
    private AuthService authService;
    @Mock
    private FindingHistoryWriter historyWriter;
    @Mock
    private FindingService findingService;

    private final RiskScoringService riskScoringService = new RiskScoringService();
    private final Clock clock = Clock.fixed(Instant.parse("2026-06-28T12:00:00Z"), ZoneOffset.UTC);
    private final LocalDate today = LocalDate.of(2026, 6, 28);

    private FindingWorkflowService workflowService;

    @BeforeEach
    void setUp() {
        workflowService = new FindingWorkflowService(
                findingRepository,
                authService,
                riskScoringService,
                historyWriter,
                findingService,
                clock
        );
    }

    @Test
    @DisplayName("Confirming a DETECTED finding scores risk, sets SLA, and transitions to CONFIRMED")
    void confirmFindingAppliesRiskAndTransitions() {
        User analyst = user(10L, "analyst", UserRole.SECURITY_ANALYST);
        Finding finding = detectedFinding(1L, BigDecimal.valueOf(9.8), AssetCriticality.CRITICAL);
        FindingResponse response = stubResponse(finding);

        when(authService.requireUser("analyst")).thenReturn(analyst);
        when(findingService.requireFinding(1L)).thenReturn(finding);
        when(findingService.toFindingResponse(finding)).thenReturn(response);

        FindingResponse result = workflowService.confirmFinding(1L, "analyst");

        assertThat(result).isSameAs(response);
        assertThat(finding.getStatus()).isEqualTo(FindingStatus.CONFIRMED);
        assertThat(finding.getRiskScore()).isEqualByComparingTo("19.60");
        assertThat(finding.getSeverity()).isEqualTo(RiskSeverity.CRITICAL);
        assertThat(finding.getDueDate()).isEqualTo(today.plusDays(7));
        verify(findingRepository).saveAndFlush(finding);
        verify(historyWriter).record(
                eq(finding),
                eq(FindingStatus.DETECTED),
                eq(FindingStatus.CONFIRMED),
                eq(analyst),
                eq("Finding confirmed by security analyst.")
        );
    }

    @Test
    @DisplayName("Confirm rejects findings that are not DETECTED")
    void confirmFindingRejectsWrongStatus() {
        User analyst = user(10L, "analyst", UserRole.SECURITY_ANALYST);
        Finding finding = detectedFinding(1L, BigDecimal.valueOf(5.0), AssetCriticality.MEDIUM);
        finding.setStatus(FindingStatus.CONFIRMED);

        when(authService.requireUser("analyst")).thenReturn(analyst);
        when(findingService.requireFinding(1L)).thenReturn(finding);

        assertThatThrownBy(() -> workflowService.confirmFinding(1L, "analyst"))
                .isInstanceOf(InvalidStateTransitionException.class)
                .hasMessageContaining("Only DETECTED findings can be confirmed");

        verify(findingRepository, never()).save(any());
        verify(historyWriter, never()).record(any(), any(), any(), any(), any());
    }

    @Test
    @DisplayName("Confirm is denied for ENGINEER role")
    void confirmFindingDeniedForEngineer() {
        User engineer = user(20L, "engineer", UserRole.ENGINEER);
        when(authService.requireUser("engineer")).thenReturn(engineer);

        assertThatThrownBy(() -> workflowService.confirmFinding(1L, "engineer"))
                .isInstanceOf(AccessDeniedException.class)
                .hasMessageContaining("Only security analysts");

        verify(findingService, never()).requireFinding(any(Long.class));
    }

    @Test
    @DisplayName("Assigned engineer can mark IN_PROGRESS finding as patched")
    void markPatchedByAssignedEngineer() {
        User engineer = user(20L, "engineer", UserRole.ENGINEER);
        Finding finding = detectedFinding(2L, BigDecimal.valueOf(7.0), AssetCriticality.HIGH);
        finding.setStatus(FindingStatus.IN_PROGRESS);
        finding.setAssignedEngineer(engineer);
        FindingResponse response = stubResponse(finding);

        when(authService.requireUser("engineer")).thenReturn(engineer);
        when(findingService.requireFinding(2L)).thenReturn(finding);
        when(findingService.toFindingResponse(finding)).thenReturn(response);

        workflowService.markPatched(2L, "engineer");

        assertThat(finding.getStatus()).isEqualTo(FindingStatus.PATCHED);
        verify(historyWriter).record(
                eq(finding),
                eq(FindingStatus.IN_PROGRESS),
                eq(FindingStatus.PATCHED),
                eq(engineer),
                eq("Patch applied by assigned engineer.")
        );
    }

    @Test
    @DisplayName("A different engineer cannot mark a finding as patched")
    void markPatchedDeniedForOtherEngineer() {
        User assigned = user(20L, "engineer", UserRole.ENGINEER);
        User other = user(21L, "other-engineer", UserRole.ENGINEER);
        Finding finding = detectedFinding(2L, BigDecimal.valueOf(7.0), AssetCriticality.HIGH);
        finding.setStatus(FindingStatus.IN_PROGRESS);
        finding.setAssignedEngineer(assigned);

        when(authService.requireUser("other-engineer")).thenReturn(other);
        when(findingService.requireFinding(2L)).thenReturn(finding);

        assertThatThrownBy(() -> workflowService.markPatched(2L, "other-engineer"))
                .isInstanceOf(AccessDeniedException.class)
                .hasMessageContaining("Only the assigned engineer");

        assertThat(finding.getStatus()).isEqualTo(FindingStatus.IN_PROGRESS);
        verify(findingRepository, never()).save(any());
    }

    @Test
    @DisplayName("Close requires VERIFIED status")
    void closeFindingRequiresVerified() {
        User analyst = user(10L, "analyst", UserRole.SECURITY_ANALYST);
        Finding finding = detectedFinding(3L, BigDecimal.valueOf(6.0), AssetCriticality.MEDIUM);
        finding.setStatus(FindingStatus.PATCHED);

        when(authService.requireUser("analyst")).thenReturn(analyst);
        when(findingService.requireFinding(3L)).thenReturn(finding);

        assertThatThrownBy(() -> workflowService.closeFinding(3L, "analyst"))
                .isInstanceOf(InvalidStateTransitionException.class)
                .hasMessageContaining("cannot be closed unless it was verified");
    }

    @Test
    @DisplayName("Accept risk rejects expiration that is not at least one day ahead")
    void acceptRiskRejectsTooSoonExpiration() {
        User analyst = user(10L, "analyst", UserRole.SECURITY_ANALYST);
        Finding finding = detectedFinding(4L, BigDecimal.valueOf(4.0), AssetCriticality.LOW);
        finding.setStatus(FindingStatus.CONFIRMED);

        when(authService.requireUser("analyst")).thenReturn(analyst);
        when(findingService.requireFinding(4L)).thenReturn(finding);

        AcceptRiskRequest request = new AcceptRiskRequest("Business accepted", today);

        assertThatThrownBy(() -> workflowService.acceptRisk(4L, request, "analyst"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("at least one day in the future");
    }

    @Test
    @DisplayName("Assign moves CONFIRMED finding to ASSIGNED with engineer set")
    void assignFindingSetsEngineer() {
        User analyst = user(10L, "analyst", UserRole.SECURITY_ANALYST);
        User engineer = user(20L, "engineer", UserRole.ENGINEER);
        Finding finding = detectedFinding(5L, BigDecimal.valueOf(8.0), AssetCriticality.HIGH);
        finding.setStatus(FindingStatus.CONFIRMED);
        FindingResponse response = stubResponse(finding);

        when(authService.requireUser("analyst")).thenReturn(analyst);
        when(authService.requireEngineer(20L)).thenReturn(engineer);
        when(findingService.requireFinding(5L)).thenReturn(finding);
        when(findingService.toFindingResponse(finding)).thenReturn(response);

        workflowService.assignFinding(5L, new AssignFindingRequest(20L), "analyst");

        assertThat(finding.getStatus()).isEqualTo(FindingStatus.ASSIGNED);
        assertThat(finding.getAssignedEngineer()).isEqualTo(engineer);
        verify(historyWriter).record(
                eq(finding),
                eq(FindingStatus.CONFIRMED),
                eq(FindingStatus.ASSIGNED),
                eq(analyst),
                eq("Assigned to engineer.")
        );
    }

    @Test
    @DisplayName("Escalation marks overdue findings and writes history without changing status")
    void escalateOverdueFindings() {
        Finding overdue = detectedFinding(6L, BigDecimal.valueOf(9.0), AssetCriticality.CRITICAL);
        overdue.setStatus(FindingStatus.ASSIGNED);
        overdue.setDueDate(today.minusDays(1));

        when(findingRepository.findOverdueNotEscalated(eq(today), any()))
                .thenReturn(List.of(overdue));

        int count = workflowService.escalateOverdueFindings();

        assertThat(count).isEqualTo(1);
        assertThat(overdue.isEscalated()).isTrue();
        assertThat(overdue.getEscalatedAt()).isNotNull();
        assertThat(overdue.getStatus()).isEqualTo(FindingStatus.ASSIGNED);

        ArgumentCaptor<String> noteCaptor = ArgumentCaptor.forClass(String.class);
        verify(historyWriter).record(
                eq(overdue),
                eq(FindingStatus.ASSIGNED),
                eq(FindingStatus.ASSIGNED),
                isNull(),
                noteCaptor.capture()
        );
        assertThat(noteCaptor.getValue()).contains("missed SLA");
        verify(findingRepository).save(overdue);
    }

    @Test
    @DisplayName("Accept risk allows expiration exactly one day ahead of the business clock")
    void acceptRiskAllowsTomorrowExpiration() {
        User analyst = user(10L, "analyst", UserRole.SECURITY_ANALYST);
        Finding finding = detectedFinding(4L, BigDecimal.valueOf(4.0), AssetCriticality.LOW);
        finding.setStatus(FindingStatus.CONFIRMED);
        FindingResponse response = stubResponse(finding);

        when(authService.requireUser("analyst")).thenReturn(analyst);
        when(findingService.requireFinding(4L)).thenReturn(finding);
        when(findingService.toFindingResponse(finding)).thenReturn(response);

        workflowService.acceptRisk(4L, new AcceptRiskRequest("Accepted", today.plusDays(1)), "analyst");

        assertThat(finding.getStatus()).isEqualTo(FindingStatus.ACCEPTED_RISK);
        assertThat(finding.getAcceptedRiskExpiresAt()).isEqualTo(today.plusDays(1));
    }

    @Test
    @DisplayName("Accept risk rejects an expiration in the past")
    void acceptRiskRejectsPastExpiration() {
        User analyst = user(10L, "analyst", UserRole.SECURITY_ANALYST);
        Finding finding = detectedFinding(4L, BigDecimal.valueOf(4.0), AssetCriticality.LOW);
        finding.setStatus(FindingStatus.CONFIRMED);

        when(authService.requireUser("analyst")).thenReturn(analyst);
        when(findingService.requireFinding(4L)).thenReturn(finding);

        assertThatThrownBy(() -> workflowService.acceptRisk(
                4L, new AcceptRiskRequest("Accepted", today.minusDays(1)), "analyst"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("at least one day in the future");
    }

    @Test
    @DisplayName("Findings due today are not treated as overdue")
    void dueTodayIsNotEscalated() {
        when(findingRepository.findOverdueNotEscalated(eq(today), any())).thenReturn(List.of());

        int count = workflowService.escalateOverdueFindings();

        assertThat(count).isZero();
        verify(findingRepository, never()).save(any());
        verify(historyWriter, never()).record(any(), any(), any(), any(), any());
    }

    @Test
    @DisplayName("Already escalated findings are not escalated again")
    void alreadyEscalatedFindingsAreSkipped() {
        when(findingRepository.findOverdueNotEscalated(eq(today), any())).thenReturn(List.of());

        assertThat(workflowService.escalateOverdueFindings()).isZero();
        verify(historyWriter, never()).record(any(), any(), any(), any(), any());
    }

    @Test
    @DisplayName("Terminal findings are excluded from SLA escalation")
    void terminalFindingsAreNotEscalated() {
        when(findingRepository.findOverdueNotEscalated(eq(today), any())).thenReturn(List.of());

        assertThat(workflowService.escalateOverdueFindings()).isZero();
        verify(findingRepository).findOverdueNotEscalated(eq(today), eq(List.of(
                FindingStatus.CLOSED,
                FindingStatus.FALSE_POSITIVE,
                FindingStatus.ACCEPTED_RISK,
                FindingStatus.DUPLICATE
        )));
    }

    @Test
    @DisplayName("Findings due in the future are not escalated")
    void futureDueDateIsNotEscalated() {
        when(findingRepository.findOverdueNotEscalated(eq(today), any())).thenReturn(List.of());

        assertThat(workflowService.escalateOverdueFindings()).isZero();
        verify(findingRepository, never()).save(any());
    }

    private static User user(long id, String username, UserRole role) {
        User user = new User(username, "hash", username, role);
        ReflectionTestUtils.setField(user, "id", id);
        return user;
    }

    private static Finding detectedFinding(long id, BigDecimal cvss, AssetCriticality criticality) {
        Asset asset = new Asset("payments-api", "payments.internal", "10.0.0.10", criticality);
        ReflectionTestUtils.setField(asset, "id", 100L);
        Finding finding = new Finding(asset, null, "CVE-2024-TEST", "Test finding", "desc", cvss);
        ReflectionTestUtils.setField(finding, "id", id);
        return finding;
    }

    private static FindingResponse stubResponse(Finding finding) {
        return new FindingResponse(
                finding.getId(),
                100L,
                "payments-api",
                null,
                finding.getCveId(),
                finding.getTitle(),
                finding.getDescription(),
                finding.getCvssScore(),
                finding.getRiskScore(),
                finding.getSeverity(),
                finding.getStatus(),
                finding.getDueDate(),
                null,
                null,
                null,
                finding.isEscalated(),
                finding.getEscalatedAt(),
                null,
                finding.getCreatedAt(),
                finding.getUpdatedAt(),
                finding.getVersion()
        );
    }
}
