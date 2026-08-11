package com.vulntrack.service;

import com.vulntrack.domain.Asset;
import com.vulntrack.domain.Scan;
import com.vulntrack.dto.CreateScanRequest;
import com.vulntrack.dto.ScanResponse;
import com.vulntrack.repository.AssetRepository;
import com.vulntrack.repository.ScanRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.NoSuchElementException;

@Service
public class ScanService {

    private final AssetRepository assetRepository;
    private final ScanRepository scanRepository;

    public ScanService(AssetRepository assetRepository, ScanRepository scanRepository) {
        this.assetRepository = assetRepository;
        this.scanRepository = scanRepository;
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
}
