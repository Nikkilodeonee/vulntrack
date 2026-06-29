package com.vulntrack.controller;

import com.vulntrack.enums.FindingStatus;
import com.vulntrack.enums.RiskSeverity;
import com.vulntrack.dto.*;
import com.vulntrack.service.VulnTrackService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/findings")
public class FindingController {

    private final VulnTrackService vulnTrackService;

    public FindingController(VulnTrackService vulnTrackService) {
        this.vulnTrackService = vulnTrackService;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public FindingResponse createFinding(
            @Valid @RequestBody CreateFindingRequest request,
            @AuthenticationPrincipal UserDetails principal
    ) {
        return vulnTrackService.createFinding(request, principal.getUsername());
    }

    @GetMapping
    public List<FindingResponse> getFindings(
            @RequestParam(required = false) RiskSeverity severity,
            @RequestParam(required = false) FindingStatus status
    ) {
        return vulnTrackService.getFindings(severity, status);
    }

    @GetMapping("/{id}")
    public FindingResponse getFinding(@PathVariable long id) {
        return vulnTrackService.getFinding(id);
    }

    @PatchMapping("/{id}/confirm")
    public FindingResponse confirmFinding(
            @PathVariable long id,
            @AuthenticationPrincipal UserDetails principal
    ) {
        return vulnTrackService.confirmFinding(id, principal.getUsername());
    }

    @PatchMapping("/{id}/assign")
    public FindingResponse assignFinding(
            @PathVariable long id,
            @Valid @RequestBody AssignFindingRequest request,
            @AuthenticationPrincipal UserDetails principal
    ) {
        return vulnTrackService.assignFinding(id, request, principal.getUsername());
    }

    @PatchMapping("/{id}/start-progress")
    public FindingResponse startProgress(
            @PathVariable long id,
            @AuthenticationPrincipal UserDetails principal
    ) {
        return vulnTrackService.startProgress(id, principal.getUsername());
    }

    @PatchMapping("/{id}/mark-patched")
    public FindingResponse markPatched(
            @PathVariable long id,
            @AuthenticationPrincipal UserDetails principal
    ) {
        return vulnTrackService.markPatched(id, principal.getUsername());
    }

    @PatchMapping("/{id}/verify")
    public FindingResponse verifyFinding(
            @PathVariable long id,
            @AuthenticationPrincipal UserDetails principal
    ) {
        return vulnTrackService.verifyFinding(id, principal.getUsername());
    }

    @PatchMapping("/{id}/close")
    public FindingResponse closeFinding(
            @PathVariable long id,
            @AuthenticationPrincipal UserDetails principal
    ) {
        return vulnTrackService.closeFinding(id, principal.getUsername());
    }

    @PatchMapping("/{id}/false-positive")
    public FindingResponse markFalsePositive(
            @PathVariable long id,
            @AuthenticationPrincipal UserDetails principal
    ) {
        return vulnTrackService.markFalsePositive(id, principal.getUsername());
    }

    @PatchMapping("/{id}/accept-risk")
    public FindingResponse acceptRisk(
            @PathVariable long id,
            @Valid @RequestBody AcceptRiskRequest request,
            @AuthenticationPrincipal UserDetails principal
    ) {
        return vulnTrackService.acceptRisk(id, request, principal.getUsername());
    }

    @GetMapping("/{id}/history")
    public List<FindingHistoryResponse> getHistory(@PathVariable long id) {
        return vulnTrackService.getFindingHistory(id);
    }

    @PostMapping("/{id}/comments")
    @ResponseStatus(HttpStatus.CREATED)
    public CommentResponse addComment(
            @PathVariable long id,
            @Valid @RequestBody CreateCommentRequest request,
            @AuthenticationPrincipal UserDetails principal
    ) {
        return vulnTrackService.addComment(id, request, principal.getUsername());
    }

    @GetMapping("/{id}/comments")
    public List<CommentResponse> getComments(@PathVariable long id) {
        return vulnTrackService.getComments(id);
    }
}
