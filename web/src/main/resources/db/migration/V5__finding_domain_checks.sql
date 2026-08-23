ALTER TABLE finding
    ADD CONSTRAINT chk_finding_cvss_score
        CHECK (cvss_score >= 0 AND cvss_score <= 10);

ALTER TABLE finding
    ADD CONSTRAINT chk_finding_escalation_timestamp
        CHECK (escalated = FALSE OR escalated_at IS NOT NULL);
