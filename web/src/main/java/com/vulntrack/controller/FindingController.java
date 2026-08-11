package com.vulntrack.controller;

import com.vulntrack.dto.*;
import com.vulntrack.enums.FindingStatus;
import com.vulntrack.enums.RiskSeverity;
import com.vulntrack.service.FindingService;
import com.vulntrack.service.FindingWorkflowService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/findings")
public class FindingController {

    private final FindingService findingService;
    private final FindingWorkflowService findingWorkflowService;

    public FindingController(FindingService findingService, FindingWorkflowService findingWorkflowService) {
        this.findingService = findingService;
        this.findingWorkflowService = findingWorkflowService;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public FindingResponse createFinding(
            @Valid @RequestBody CreateFindingRequest request,
            @AuthenticationPrincipal UserDetails principal
    ) {
        return findingService.createFinding(request, principal.getUsername());
    }

    @GetMapping
    public List<FindingResponse> getFindings(
            @RequestParam(required = false) RiskSeverity severity,
            @RequestParam(required = false) FindingStatus status
    ) {
        return findingService.getFindings(severity, status);
    }

    @GetMapping("/{id}")
    public FindingResponse getFinding(@PathVariable long id) {
        return findingService.getFinding(id);
    }

    @PatchMapping("/{id}/confirm")
    public FindingResponse confirmFinding(
            @PathVariable long id,
            @AuthenticationPrincipal UserDetails principal
    ) {
        return findingWorkflowService.confirmFinding(id, principal.getUsername());
    }

    @PatchMapping("/{id}/assign")
    public FindingResponse assignFinding(
            @PathVariable long id,
            @Valid @RequestBody AssignFindingRequest request,
            @AuthenticationPrincipal UserDetails principal
    ) {
        return findingWorkflowService.assignFinding(id, request, principal.getUsername());
    }

    @PatchMapping("/{id}/start-progress")
    public FindingResponse startProgress(
            @PathVariable long id,
            @AuthenticationPrincipal UserDetails principal
    ) {
        return findingWorkflowService.startProgress(id, principal.getUsername());
    }

    @PatchMapping("/{id}/mark-patched")
    public FindingResponse markPatched(
            @PathVariable long id,
            @AuthenticationPrincipal UserDetails principal
    ) {
        return findingWorkflowService.markPatched(id, principal.getUsername());
    }

    @PatchMapping("/{id}/verify")
    public FindingResponse verifyFinding(
            @PathVariable long id,
            @AuthenticationPrincipal UserDetails principal
    ) {
        return findingWorkflowService.verifyFinding(id, principal.getUsername());
    }

    @PatchMapping("/{id}/close")
    public FindingResponse closeFinding(
            @PathVariable long id,
            @AuthenticationPrincipal UserDetails principal
    ) {
        return findingWorkflowService.closeFinding(id, principal.getUsername());
    }

    @PatchMapping("/{id}/false-positive")
    public FindingResponse markFalsePositive(
            @PathVariable long id,
            @AuthenticationPrincipal UserDetails principal
    ) {
        return findingWorkflowService.markFalsePositive(id, principal.getUsername());
    }

    @PatchMapping("/{id}/accept-risk")
    public FindingResponse acceptRisk(
            @PathVariable long id,
            @Valid @RequestBody AcceptRiskRequest request,
            @AuthenticationPrincipal UserDetails principal
    ) {
        return findingWorkflowService.acceptRisk(id, request, principal.getUsername());
    }

    @GetMapping("/{id}/history")
    public List<FindingHistoryResponse> getHistory(@PathVariable long id) {
        return findingService.getFindingHistory(id);
    }

    @PostMapping("/{id}/comments")
    @ResponseStatus(HttpStatus.CREATED)
    public CommentResponse addComment(
            @PathVariable long id,
            @Valid @RequestBody CreateCommentRequest request,
            @AuthenticationPrincipal UserDetails principal
    ) {
        return findingService.addComment(id, request, principal.getUsername());
    }

    @GetMapping("/{id}/comments")
    public List<CommentResponse> getComments(@PathVariable long id) {
        return findingService.getComments(id);
    }
}
