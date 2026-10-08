-- Synthetic portfolio examples, installed only by the demo profile.
INSERT INTO finding (asset_id, scan_id, cve_id, title, description, cvss_score,
                     risk_score, severity, status, due_date, assigned_engineer_id,
                     created_at, updated_at) VALUES
    (1, 1, 'CVE-DEMO-0001', 'Demo: outdated dependency in payments API',
     'Synthetic finding illustrating critical risk and an assigned remediation owner.',
     9.8, 19.60, 'CRITICAL', 'ASSIGNED', CURRENT_DATE + 4, 3,
     CURRENT_TIMESTAMP - INTERVAL '3 days', CURRENT_TIMESTAMP - INTERVAL '1 day'),
    (2, NULL, 'CVE-DEMO-0002', 'Demo: missing authorization check in legacy portal',
     'Synthetic finding illustrating an engineer working on a high-risk issue.',
     6.4, 7.68, 'HIGH', 'IN_PROGRESS', CURRENT_DATE + 10, 3,
     CURRENT_TIMESTAMP - INTERVAL '4 days', CURRENT_TIMESTAMP - INTERVAL '1 day'),
    (1, 1, 'CVE-DEMO-0003', 'Demo: verbose error response',
     'Synthetic finding awaiting triage; asset criticality raises its risk score.',
     3.2, 6.40, 'MEDIUM', 'DETECTED', NULL, NULL,
     CURRENT_TIMESTAMP - INTERVAL '1 day', CURRENT_TIMESTAMP - INTERVAL '1 day'),
    (2, NULL, 'CVE-DEMO-0004', 'Demo: unnecessary server version header',
     'Synthetic example of a remediated, verified and closed finding.',
     2.0, 2.40, 'LOW', 'CLOSED', CURRENT_DATE + 60, 3,
     CURRENT_TIMESTAMP - INTERVAL '30 days', CURRENT_TIMESTAMP - INTERVAL '1 day');

INSERT INTO finding_history (finding_id, from_status, to_status, changed_by_id, changed_at, note)
SELECT id, NULL, 'DETECTED', 2, created_at, 'Synthetic portfolio finding imported.'
FROM finding WHERE cve_id LIKE 'CVE-DEMO-%';

INSERT INTO finding_history (finding_id, from_status, to_status, changed_by_id, changed_at, note)
SELECT id, 'DETECTED', 'CONFIRMED', 2, created_at + INTERVAL '1 hour', 'Confirmed during security triage.'
FROM finding WHERE cve_id IN ('CVE-DEMO-0001', 'CVE-DEMO-0002', 'CVE-DEMO-0004');

INSERT INTO finding_history (finding_id, from_status, to_status, changed_by_id, changed_at, note)
SELECT id, 'CONFIRMED', 'ASSIGNED', 1, created_at + INTERVAL '2 hours', 'Assigned to the platform engineer.'
FROM finding WHERE cve_id IN ('CVE-DEMO-0001', 'CVE-DEMO-0002', 'CVE-DEMO-0004');

INSERT INTO finding_history (finding_id, from_status, to_status, changed_by_id, changed_at, note)
SELECT id, 'ASSIGNED', 'IN_PROGRESS', 3, created_at + INTERVAL '3 hours', 'Remediation started.'
FROM finding WHERE cve_id IN ('CVE-DEMO-0002', 'CVE-DEMO-0004');

INSERT INTO finding_history (finding_id, from_status, to_status, changed_by_id, changed_at, note)
SELECT id, 'IN_PROGRESS', 'PATCHED', 3, created_at + INTERVAL '10 days', 'Patch applied in the demo scenario.'
FROM finding WHERE cve_id = 'CVE-DEMO-0004';

INSERT INTO finding_history (finding_id, from_status, to_status, changed_by_id, changed_at, note)
SELECT id, 'PATCHED', 'VERIFIED', 2, created_at + INTERVAL '11 days', 'Security analyst verified the fix.'
FROM finding WHERE cve_id = 'CVE-DEMO-0004';

INSERT INTO finding_history (finding_id, from_status, to_status, changed_by_id, changed_at, note)
SELECT id, 'VERIFIED', 'CLOSED', 2, updated_at, 'Remediation complete.'
FROM finding WHERE cve_id = 'CVE-DEMO-0004';

INSERT INTO comment (finding_id, author_id, content, created_at)
SELECT id, 3, 'Demo note: remediation is in progress; the next step is patch verification.', updated_at
FROM finding WHERE cve_id = 'CVE-DEMO-0002';
