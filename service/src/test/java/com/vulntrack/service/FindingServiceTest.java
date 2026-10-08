package com.vulntrack.service;

import com.vulntrack.domain.Asset;
import com.vulntrack.domain.User;
import com.vulntrack.dto.CreateFindingRequest;
import com.vulntrack.enums.AssetCriticality;
import com.vulntrack.enums.FindingStatus;
import com.vulntrack.enums.UserRole;
import com.vulntrack.repository.AssetRepository;
import com.vulntrack.repository.FindingRepository;
import org.hibernate.exception.ConstraintViolationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.test.util.ReflectionTestUtils;

import java.math.BigDecimal;
import java.sql.SQLException;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class FindingServiceTest {

    @Mock private AssetRepository assetRepository;
    @Mock private FindingRepository findingRepository;
    @Mock private AuthService authService;
    @Mock private FindingHistoryWriter historyWriter;

    private FindingService service;
    private final CreateFindingRequest request = new CreateFindingRequest(
            1L, null, "CVE-TEST-0001", "Test finding", null, new BigDecimal("5.0"));

    @BeforeEach
    void setUp() {
        service = new FindingService(assetRepository, null, findingRepository, null, null, authService, historyWriter);
        Asset asset = new Asset("Test asset", "test.example", null, AssetCriticality.HIGH);
        ReflectionTestUtils.setField(asset, "id", 1L);
        when(assetRepository.findById(1L)).thenReturn(Optional.of(asset));
        when(authService.requireUser("analyst"))
                .thenReturn(new User("analyst", "hash", "Analyst", UserRole.SECURITY_ANALYST));
        when(findingRepository.findFirstByAsset_IdAndCveIdAndStatusNot(1L, request.cveId(), FindingStatus.DUPLICATE))
                .thenReturn(Optional.empty());
    }

    @Test
    void onlyCanonicalUniqueViolationBecomesDuplicateConflict() {
        var failure = integrityFailure("23505", "uq_finding_canonical_asset_cve");
        when(findingRepository.saveAndFlush(any())).thenThrow(failure);

        assertThatThrownBy(() -> service.createFinding(request, "analyst"))
                .isInstanceOf(ResourceConflictException.class)
                .hasMessage("A finding for this asset and CVE already exists.")
                .hasCause(failure);
        verifyNoInteractions(historyWriter);
    }

    @ParameterizedTest
    @CsvSource({
            "23514, chk_finding_cvss_score",
            "23503, finding_asset_id_fkey",
            "23502, title",
            "23505, another_unique_constraint",
            "23514, uq_finding_canonical_asset_cve"
    })
    void otherIntegrityViolationsPropagateUnchanged(String sqlState, String constraintName) {
        var failure = integrityFailure(sqlState, constraintName);
        when(findingRepository.saveAndFlush(any())).thenThrow(failure);

        assertThatThrownBy(() -> service.createFinding(request, "analyst")).isSameAs(failure);
        verifyNoInteractions(historyWriter);
    }

    @Test
    void errorTextAloneCannotIdentifyTheDuplicateConstraint() {
        var failure = new DataIntegrityViolationException("uq_finding_canonical_asset_cve");
        when(findingRepository.saveAndFlush(any())).thenThrow(failure);

        assertThatThrownBy(() -> service.createFinding(request, "analyst")).isSameAs(failure);
        verifyNoInteractions(historyWriter);
    }

    private static DataIntegrityViolationException integrityFailure(String sqlState, String constraintName) {
        var violation = new ConstraintViolationException("insert failed",
                new SQLException("database details", sqlState), constraintName);
        return new DataIntegrityViolationException("insert failed", new RuntimeException(violation));
    }
}
