package com.vulntrack.controller;

import com.vulntrack.dto.RiskSummaryResponse;
import com.vulntrack.service.DashboardService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/dashboard")
public class DashboardController {

    private final DashboardService dashboardService;

    public DashboardController(DashboardService dashboardService) {
        this.dashboardService = dashboardService;
    }

    @GetMapping("/risk-summary")
    public RiskSummaryResponse getRiskSummary() {
        return dashboardService.getRiskSummary();
    }
}
