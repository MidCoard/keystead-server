package top.focess.keystead.server.vault;

import java.security.Principal;
import org.jspecify.annotations.NonNull;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/vaults/{vaultId}")
class VaultKeyRotationController {
    private final VaultKeyRotationService rotations;

    VaultKeyRotationController(@NonNull VaultKeyRotationService rotations) {
        this.rotations = rotations;
    }

    @PutMapping("/key-rotation")
    @NonNull ResponseEntity<Void> rotate(
            @NonNull Principal principal,
            @org.springframework.web.bind.annotation.PathVariable @NonNull String vaultId,
            @RequestBody @NonNull VaultKeyRotationRequest request) {
        rotations.rotate(principal.getName(), vaultId, request);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/rotations")
    @NonNull ResponseEntity<VaultRotationResponse> begin(
            @NonNull Principal principal,
            @org.springframework.web.bind.annotation.PathVariable @NonNull String vaultId,
            @RequestBody @NonNull VaultRotationBeginRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(rotations.begin(principal.getName(), vaultId, request));
    }

    @GetMapping("/rotations/{generationId}")
    @NonNull VaultRotationResponse status(
            @NonNull Principal principal,
            @org.springframework.web.bind.annotation.PathVariable @NonNull String vaultId,
            @org.springframework.web.bind.annotation.PathVariable @NonNull String generationId) {
        return rotations.status(principal.getName(), vaultId, generationId);
    }

    @PutMapping("/rotations/{generationId}/targets/{targetId}/package")
    @NonNull VaultRotationResponse putPackage(
            @NonNull Principal principal,
            @org.springframework.web.bind.annotation.PathVariable @NonNull String vaultId,
            @org.springframework.web.bind.annotation.PathVariable @NonNull String generationId,
            @org.springframework.web.bind.annotation.PathVariable @NonNull String targetId,
            @RequestBody @NonNull VaultRotationPackageRequest request) {
        return rotations.putPackage(principal.getName(), vaultId, generationId, targetId, request);
    }

    @GetMapping("/rotations/{generationId}/self-package")
    @NonNull VaultRotationPackageResponse selfPackage(
            @NonNull Principal principal,
            @org.springframework.web.bind.annotation.PathVariable @NonNull String vaultId,
            @org.springframework.web.bind.annotation.PathVariable @NonNull String generationId,
            @org.springframework.web.bind.annotation.RequestParam @NonNull String deviceId) {
        return rotations.selfPackage(principal.getName(), vaultId, generationId, deviceId);
    }

    @DeleteMapping("/rotations/{generationId}")
    @NonNull ResponseEntity<Void> cancel(
            @NonNull Principal principal,
            @org.springframework.web.bind.annotation.PathVariable @NonNull String vaultId,
            @org.springframework.web.bind.annotation.PathVariable @NonNull String generationId) {
        rotations.cancel(principal.getName(), vaultId, generationId);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/rotations/{generationId}/commit")
    @NonNull VaultRotationResponse commit(
            @NonNull Principal principal,
            @org.springframework.web.bind.annotation.PathVariable @NonNull String vaultId,
            @org.springframework.web.bind.annotation.PathVariable @NonNull String generationId) {
        return rotations.commit(principal.getName(), vaultId, generationId);
    }
}
