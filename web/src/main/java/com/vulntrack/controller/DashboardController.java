package com.vulntrack.controller;

import com.vulntrack.dto.RiskSummaryResponse;
import com.vulntrack.service.VulnTrackService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/dashboard")
public class DashboardController {

    private final VulnTrackService vulnTrackService;

    public DashboardController(VulnTrackService vulnTrackService) {
        this.vulnTrackService = vulnTrackService;
    }

    @GetMapping("/risk-summary")
    public RiskSummaryResponse getRiskSummary() {
        return vulnTrackService.getRiskSummary();
    }
}
