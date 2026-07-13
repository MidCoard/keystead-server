package top.focess.keystead.server.recovery;

import java.security.Principal;
import java.util.List;
import org.jspecify.annotations.NonNull;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/recovery")
final class RecoveryEnrollmentController {

    private final RecoveryEnrollmentService service;

    RecoveryEnrollmentController(@NonNull RecoveryEnrollmentService service) {
        this.service = service;
    }

    @PostMapping("/enrollments")
    @NonNull ResponseEntity<RecoveryEnrollmentResponse> create(
            @NonNull Principal principal, @RequestBody @NonNull RecoveryEnrollmentRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(service.create(principal.getName(), request));
    }

    @GetMapping("/enrollments")
    @NonNull List<RecoveryEnrollmentResponse> list(@NonNull Principal principal) {
        return service.list(principal.getName());
    }

    @PostMapping("/enrollments/{enrollmentId}/commit")
    @NonNull RecoveryEnrollmentResponse commit(
            @NonNull Principal principal,
            @PathVariable @NonNull String enrollmentId,
            @RequestBody @NonNull RecoveryEnrollmentCommitRequest request) {
        return service.commit(principal.getName(), enrollmentId, request);
    }

    @PutMapping("/users/{username}/enrollments/{enrollmentId}/vaults/{vaultId}")
    @NonNull ResponseEntity<RecoveryVaultPackageResponse> putPackage(
            @NonNull Principal principal,
            @PathVariable @NonNull String username,
            @PathVariable @NonNull String enrollmentId,
            @PathVariable @NonNull String vaultId,
            @RequestBody @NonNull RecoveryVaultPackageRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(
                        service.putPackage(
                                principal.getName(), username, enrollmentId, vaultId, request));
    }

    @GetMapping("/enrollments/{enrollmentId}/vaults/{vaultId}")
    @NonNull RecoveryVaultPackageResponse getPackage(
            @NonNull Principal principal,
            @PathVariable @NonNull String enrollmentId,
            @PathVariable @NonNull String vaultId) {
        return service.getPackage(principal.getName(), enrollmentId, vaultId);
    }
}
