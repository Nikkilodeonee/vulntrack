package com.vulntrack.web;

import com.vulntrack.service.AuthenticationException;
import com.vulntrack.service.InvalidStateTransitionException;
import com.vulntrack.service.ResourceConflictException;
import jakarta.persistence.OptimisticLockException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.orm.ObjectOptimisticLockingFailureException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.NoSuchElementException;

@RestControllerAdvice
public class RestExceptionHandler {

    @ExceptionHandler(NoSuchElementException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public ApiErrorResponse handleNotFound(NoSuchElementException exception) {
        return new ApiErrorResponse("NOT_FOUND", exception.getMessage());
    }

    @ExceptionHandler(AccessDeniedException.class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    public ApiErrorResponse handleForbidden(AccessDeniedException exception) {
        return new ApiErrorResponse("FORBIDDEN", exception.getMessage());
    }

    @ExceptionHandler({IllegalArgumentException.class, InvalidStateTransitionException.class})
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ApiErrorResponse handleBadRequest(RuntimeException exception) {
        return new ApiErrorResponse("BAD_REQUEST", exception.getMessage());
    }

    @ExceptionHandler({
            ResourceConflictException.class,
            ObjectOptimisticLockingFailureException.class,
            OptimisticLockException.class
    })
    @ResponseStatus(HttpStatus.CONFLICT)
    public ApiErrorResponse handleConflict(RuntimeException exception) {
        if (exception instanceof ObjectOptimisticLockingFailureException
                || exception instanceof OptimisticLockException) {
            return new ApiErrorResponse(
                    "CONFLICT",
                    "The finding was updated by another request. Reload and retry."
            );
        }
        return new ApiErrorResponse("CONFLICT", exception.getMessage());
    }

    @ExceptionHandler(DataIntegrityViolationException.class)
    @ResponseStatus(HttpStatus.CONFLICT)
    public ApiErrorResponse handleDataIntegrity(DataIntegrityViolationException exception) {
        if (containsConstraint(exception, "uq_finding_canonical_asset_cve")) {
            return new ApiErrorResponse(
                    "CONFLICT",
                    "A finding for this asset and CVE already exists."
            );
        }
        return new ApiErrorResponse("CONFLICT", "The request conflicts with existing resource state.");
    }

    @ExceptionHandler(AuthenticationException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public ApiErrorResponse handleUnauthorized(AuthenticationException exception) {
        return new ApiErrorResponse("UNAUTHORIZED", exception.getMessage());
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ApiErrorResponse handleValidation(MethodArgumentNotValidException exception) {
        String message = exception.getBindingResult().getFieldErrors().stream()
                .findFirst()
                .map(error -> error.getField() + ": " + error.getDefaultMessage())
                .orElse("Validation failed.");
        return new ApiErrorResponse("BAD_REQUEST", message);
    }

    private static boolean containsConstraint(Throwable exception, String constraintName) {
        Throwable current = exception;
        while (current != null) {
            String message = current.getMessage();
            if (message != null && message.contains(constraintName)) {
                return true;
            }
            current = current.getCause();
        }
        return false;
    }
}
