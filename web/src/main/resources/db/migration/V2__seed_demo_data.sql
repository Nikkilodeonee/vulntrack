INSERT INTO app_user (username, password, full_name, role, enabled) VALUES
    ('admin', '$2a$10$8eNSrjH2paYmpEvtU9KbQ.9h03aKEjxBjgHHHeoyvAaZcPzqkToUu', 'System Admin', 'ADMIN', TRUE),
    ('analyst', '$2a$10$wF/1JrJJhLyKwCJLGx0MSek10G2951cOUoRX9jXBH7TkCBsvnvZiK', 'Security Analyst', 'SECURITY_ANALYST', TRUE),
    ('engineer', '$2a$10$sBuS5XbpaRiJ0oEzJfIN5O3JoGrO2Nu/iKBvuZkPT3L5EorJukdPW', 'Platform Engineer', 'ENGINEER', TRUE),
    ('viewer', '$2a$10$/myqYovBSvNkRLTkCBy7BuoqPXjgVcXV2tHt6iGwOZeu5KXwxkxxK', 'Read-only Viewer', 'VIEWER', TRUE);

INSERT INTO asset (name, hostname, ip_address, criticality, active, created_at) VALUES
    ('payments-api', 'payments.internal', '10.0.0.10', 'CRITICAL', TRUE, CURRENT_TIMESTAMP),
    ('legacy-portal', 'portal.internal', '10.0.0.20', 'MEDIUM', TRUE, CURRENT_TIMESTAMP),
    ('retired-db', 'db-retired.internal', '10.0.0.99', 'LOW', FALSE, CURRENT_TIMESTAMP);

INSERT INTO scan (name, source, scanned_at, asset_id) VALUES
    ('Weekly Nessus Scan', 'Nessus', CURRENT_TIMESTAMP, 1);
