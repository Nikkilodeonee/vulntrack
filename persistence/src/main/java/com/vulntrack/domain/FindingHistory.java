package com.vulntrack.domain;

import com.vulntrack.enums.FindingStatus;
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

import java.time.LocalDateTime;

@Entity
@Table(name = "finding_history")
public class FindingHistory {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "finding_id", nullable = false)
    private Finding finding;

    @Enumerated(EnumType.STRING)
    private FindingStatus fromStatus;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private FindingStatus toStatus;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "changed_by_id")
    private User changedBy;

    @Column(nullable = false)
    private LocalDateTime changedAt;

    private String note;

    protected FindingHistory() {
    }

    public FindingHistory(
            Finding finding,
            FindingStatus fromStatus,
            FindingStatus toStatus,
            User changedBy,
            String note
    ) {
        this.finding = finding;
        this.fromStatus = fromStatus;
        this.toStatus = toStatus;
        this.changedBy = changedBy;
        this.note = note;
        this.changedAt = LocalDateTime.now();
    }

    public Long getId() {
        return id;
    }

    public Finding getFinding() {
        return finding;
    }

    public FindingStatus getFromStatus() {
        return fromStatus;
    }

    public FindingStatus getToStatus() {
        return toStatus;
    }

    public User getChangedBy() {
        return changedBy;
    }

    public LocalDateTime getChangedAt() {
        return changedAt;
    }

    public String getNote() {
        return note;
    }
}
