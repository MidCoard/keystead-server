package top.focess.keystead.server.audit;

import java.security.Principal;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Read-only query API for the audit trail. Every endpoint is owner-scoped to the authenticated
 * principal, so a caller can only ever page through their own events.
 */
@RestController
@RequestMapping("/api/v1/audit/events")
class AuditController {

    private final AuditService auditService;

    AuditController(@NonNull AuditService auditService) {
        this.auditService = auditService;
    }

    @GetMapping
    @NonNull AuditEventPageResponse page(
            @NonNull Principal principal,
            @RequestParam(defaultValue = "100") int limit,
            @RequestParam(required = false) @Nullable String vaultId,
            @RequestParam(required = false) @Nullable String before,
            @RequestParam(required = false) @Nullable String beforeId) {
        return auditService.pageForOwner(
                principal.getName(), limit, vaultId, parseBefore(before), beforeId);
    }

    private static @Nullable Instant parseBefore(@Nullable String before) {
        if (before == null || before.isBlank()) {
            return null;
        }
        try {
            return Instant.parse(before);
        } catch (DateTimeParseException e) {
            throw new InvalidAuditRequestException(
                    "Audit 'before' cursor must be an ISO-8601 instant");
        }
    }
}
