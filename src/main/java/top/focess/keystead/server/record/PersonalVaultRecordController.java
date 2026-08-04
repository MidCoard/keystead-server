package top.focess.keystead.server.record;

import java.security.Principal;
import org.jspecify.annotations.NonNull;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/vault/records")
class PersonalVaultRecordController {

    private final PersonalVaultRecordService records;

    PersonalVaultRecordController(@NonNull PersonalVaultRecordService records) {
        this.records = records;
    }

    @PostMapping
    @NonNull ResponseEntity<PersonalVaultRecordResponse> append(
            @NonNull Principal principal,
            @RequestBody @NonNull PersonalVaultRecordRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(records.append(principal.getName(), request));
    }

    @GetMapping
    @NonNull PersonalVaultRecordPageResponse page(
            @NonNull Principal principal,
            @RequestParam(defaultValue = "0") long afterSequence,
            @RequestParam(defaultValue = "100") int limit) {
        return records.page(principal.getName(), afterSequence, limit);
    }

    @DeleteMapping("/{secretId}")
    @NonNull PersonalVaultRecordDeletionResponse deleteRecordHistory(
            @NonNull Principal principal, @PathVariable @NonNull String secretId) {
        return records.deleteRecordHistory(principal.getName(), secretId);
    }

    @ExceptionHandler(PersonalVaultFingerprintConflictException.class)
    @NonNull ResponseEntity<PersonalVaultMismatchResponse> fingerprintConflict(
            @NonNull PersonalVaultFingerprintConflictException conflict) {
        return ResponseEntity.status(HttpStatus.CONFLICT)
                .body(
                        new PersonalVaultMismatchResponse(
                                "PERSONAL_VAULT_MISMATCH",
                                conflict.serverFingerprint,
                                conflict.submittedFingerprint));
    }
}
