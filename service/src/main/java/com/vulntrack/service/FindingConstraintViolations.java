package com.vulntrack.service;

import org.hibernate.exception.ConstraintViolationException;

public final class FindingConstraintViolations {

    private FindingConstraintViolations() {
    }

    public static boolean isCanonicalDuplicate(Throwable exception) {
        for (Throwable cause = exception; cause != null; cause = cause.getCause()) {
            if (cause instanceof ConstraintViolationException violation
                    && "23505".equals(violation.getSQLState())
                    && "uq_finding_canonical_asset_cve".equals(violation.getConstraintName())) {
                return true;
            }
        }
        return false;
    }
}
