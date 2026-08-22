-- At most one canonical finding per asset + CVE.
-- DUPLICATE rows are excluded so re-imports can still be recorded against the original.
CREATE UNIQUE INDEX uq_finding_canonical_asset_cve
    ON finding (asset_id, cve_id)
    WHERE status <> 'DUPLICATE';
