package top.focess.keystead.server.vault;

import java.security.Principal;
import java.util.List;
import org.jspecify.annotations.NonNull;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/vaults/{vaultId}/key-packages")
class VaultKeyPackageController {

    private final VaultKeyPackageService service;

    VaultKeyPackageController(@NonNull VaultKeyPackageService service) {
        this.service = service;
    }

    @PutMapping("/{deviceId}")
    @NonNull ResponseEntity<Void> put(
            @NonNull Principal principal,
            @PathVariable @NonNull String vaultId,
            @PathVariable @NonNull String deviceId,
            @RequestBody @NonNull VaultKeyPackageRequest request) {
        service.put(principal.getName(), vaultId, deviceId, request);
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    @PutMapping("/recipients/{recipientId}/devices/{deviceId}")
    @NonNull ResponseEntity<Void> putForRecipient(
            @NonNull Principal principal,
            @PathVariable @NonNull String vaultId,
            @PathVariable @NonNull String recipientId,
            @PathVariable @NonNull String deviceId,
            @RequestBody @NonNull VaultKeyPackageRequest request) {
        service.putForRecipient(principal.getName(), vaultId, recipientId, deviceId, request);
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    @GetMapping
    @NonNull List<VaultKeyPackageResponse> list(
            @NonNull Principal principal, @PathVariable @NonNull String vaultId) {
        return service.list(principal.getName(), vaultId);
    }
}
