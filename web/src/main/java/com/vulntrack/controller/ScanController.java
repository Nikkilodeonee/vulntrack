package com.vulntrack.controller;

import com.vulntrack.dto.CreateScanRequest;
import com.vulntrack.dto.ScanResponse;
import com.vulntrack.service.VulnTrackService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/scans")
public class ScanController {

    private final VulnTrackService vulnTrackService;

    public ScanController(VulnTrackService vulnTrackService) {
        this.vulnTrackService = vulnTrackService;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public ScanResponse createScan(@Valid @RequestBody CreateScanRequest request) {
        return vulnTrackService.createScan(request);
    }
}
