package com.vulntrack.controller;

import com.vulntrack.dto.AssetResponse;
import com.vulntrack.dto.CreateAssetRequest;
import com.vulntrack.service.VulnTrackService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/assets")
public class AssetController {

    private final VulnTrackService vulnTrackService;

    public AssetController(VulnTrackService vulnTrackService) {
        this.vulnTrackService = vulnTrackService;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public AssetResponse createAsset(@Valid @RequestBody CreateAssetRequest request) {
        return vulnTrackService.createAsset(request);
    }

    @GetMapping
    public List<AssetResponse> getAssets() {
        return vulnTrackService.getAssets();
    }
}
