DELETE FROM comment;
DELETE FROM finding_history;
DELETE FROM finding;
DELETE FROM scan;
DELETE FROM asset;
DELETE FROM app_user;

INSERT INTO app_user (id, username, password, full_name, role, enabled) VALUES
    (1, 'admin', '$2a$10$8eNSrjH2paYmpEvtU9KbQ.9h03aKEjxBjgHHHeoyvAaZcPzqkToUu', 'System Admin', 'ADMIN', TRUE),
    (2, 'analyst', '$2a$10$wF/1JrJJhLyKwCJLGx0MSek10G2951cOUoRX9jXBH7TkCBsvnvZiK', 'Security Analyst', 'SECURITY_ANALYST', TRUE),
    (3, 'engineer', '$2a$10$sBuS5XbpaRiJ0oEzJfIN5O3JoGrO2Nu/iKBvuZkPT3L5EorJukdPW', 'Platform Engineer', 'ENGINEER', TRUE),
    (4, 'viewer', '$2a$10$/myqYovBSvNkRLTkCBy7BuoqPXjgVcXV2tHt6iGwOZeu5KXwxkxxK', 'Read-only Viewer', 'VIEWER', TRUE);

INSERT INTO asset (id, name, hostname, ip_address, criticality, active, created_at) VALUES
    (1, 'payments-api', 'payments.internal', '10.0.0.10', 'CRITICAL', TRUE, CURRENT_TIMESTAMP),
    (2, 'legacy-portal', 'portal.internal', '10.0.0.20', 'MEDIUM', TRUE, CURRENT_TIMESTAMP),
    (3, 'retired-db', 'db-retired.internal', '10.0.0.99', 'LOW', FALSE, CURRENT_TIMESTAMP);

INSERT INTO scan (id, name, source, scanned_at, asset_id) VALUES
    (1, 'Weekly Nessus Scan', 'Nessus', CURRENT_TIMESTAMP, 1);

ALTER TABLE app_user ALTER COLUMN id RESTART WITH 5;
ALTER TABLE asset ALTER COLUMN id RESTART WITH 4;
ALTER TABLE scan ALTER COLUMN id RESTART WITH 2;
