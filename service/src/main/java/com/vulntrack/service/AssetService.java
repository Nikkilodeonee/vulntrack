package com.vulntrack.service;

import com.vulntrack.domain.Asset;
import com.vulntrack.dto.AssetResponse;
import com.vulntrack.dto.CreateAssetRequest;
import com.vulntrack.repository.AssetRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
public class AssetService {

    private final AssetRepository assetRepository;

    public AssetService(AssetRepository assetRepository) {
        this.assetRepository = assetRepository;
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
}
