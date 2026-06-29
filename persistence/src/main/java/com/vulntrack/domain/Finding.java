package com.vulntrack.domain;

import com.vulntrack.enums.FindingStatus;
import com.vulntrack.enums.RiskSeverity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.LocalDateTime;

@Entity
@Table(name = "finding")
public class Finding {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "asset_id", nullable = false)
    private Asset asset;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "scan_id")
    private Scan scan;

    @Column(nullable = false)
    private String cveId;

    @Column(nullable = false)
    private String title;

    private String description;

    @Column(nullable = false, precision = 4, scale = 2)
    private BigDecimal cvssScore;

    @Column(precision = 5, scale = 2)
    private BigDecimal riskScore;

    @Enumerated(EnumType.STRING)
    private RiskSeverity severity;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private FindingStatus status;

    private LocalDate dueDate;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "assigned_engineer_id")
    private User assignedEngineer;

    private String acceptedRiskReason;

    private LocalDate acceptedRiskExpiresAt;

    @Column(nullable = false)
    private boolean escalated = false;

    private LocalDateTime escalatedAt;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "duplicate_of_id")
    private Finding duplicateOf;

    @Column(nullable = false)
    private LocalDateTime createdAt;

    @Column(nullable = false)
    private LocalDateTime updatedAt;

    protected Finding() {
    }

    public Finding(Asset asset, Scan scan, String cveId, String title, String description, BigDecimal cvssScore) {
        this.asset = asset;
        this.scan = scan;
        this.cveId = cveId;
        this.title = title;
        this.description = description;
        this.cvssScore = cvssScore;
        this.status = FindingStatus.DETECTED;
        this.createdAt = LocalDateTime.now();
        this.updatedAt = this.createdAt;
    }

    public Long getId() {
        return id;
    }

    public Asset getAsset() {
        return asset;
    }

    public Scan getScan() {
        return scan;
    }

    public String getCveId() {
        return cveId;
    }

    public String getTitle() {
        return title;
    }

    public String getDescription() {
        return description;
    }

    public BigDecimal getCvssScore() {
        return cvssScore;
    }

    public BigDecimal getRiskScore() {
        return riskScore;
    }

    public RiskSeverity getSeverity() {
        return severity;
    }

    public FindingStatus getStatus() {
        return status;
    }

    public LocalDate getDueDate() {
        return dueDate;
    }

    public User getAssignedEngineer() {
        return assignedEngineer;
    }

    public String getAcceptedRiskReason() {
        return acceptedRiskReason;
    }

    public LocalDate getAcceptedRiskExpiresAt() {
        return acceptedRiskExpiresAt;
    }

    public boolean isEscalated() {
        return escalated;
    }

    public LocalDateTime getEscalatedAt() {
        return escalatedAt;
    }

    public Finding getDuplicateOf() {
        return duplicateOf;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public LocalDateTime getUpdatedAt() {
        return updatedAt;
    }

    public void setRiskScore(BigDecimal riskScore) {
        this.riskScore = riskScore;
    }

    public void setSeverity(RiskSeverity severity) {
        this.severity = severity;
    }

    public void setStatus(FindingStatus status) {
        this.status = status;
        this.updatedAt = LocalDateTime.now();
    }

    public void setDueDate(LocalDate dueDate) {
        this.dueDate = dueDate;
    }

    public void setAssignedEngineer(User assignedEngineer) {
        this.assignedEngineer = assignedEngineer;
    }

    public void setAcceptedRiskReason(String acceptedRiskReason) {
        this.acceptedRiskReason = acceptedRiskReason;
    }

    public void setAcceptedRiskExpiresAt(LocalDate acceptedRiskExpiresAt) {
        this.acceptedRiskExpiresAt = acceptedRiskExpiresAt;
    }

    public void setEscalated(boolean escalated) {
        this.escalated = escalated;
        this.updatedAt = LocalDateTime.now();
    }

    public void setEscalatedAt(LocalDateTime escalatedAt) {
        this.escalatedAt = escalatedAt;
    }

    public void setDuplicateOf(Finding duplicateOf) {
        this.duplicateOf = duplicateOf;
    }
}
