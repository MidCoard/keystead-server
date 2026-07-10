package top.focess.keystead.server.vault;

import java.security.Principal;
import org.jspecify.annotations.NonNull;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/vaults/{vaultId}/key-rotation")
class VaultKeyRotationController {
    private final VaultKeyRotationService rotations;

    VaultKeyRotationController(@NonNull VaultKeyRotationService rotations) {
        this.rotations = rotations;
    }

    @PutMapping
    @NonNull ResponseEntity<Void> rotate(
            @NonNull Principal principal,
            @org.springframework.web.bind.annotation.PathVariable @NonNull String vaultId,
            @RequestBody @NonNull VaultKeyRotationRequest request) {
        rotations.rotate(principal.getName(), vaultId, request);
        return ResponseEntity.noContent().build();
    }
}
