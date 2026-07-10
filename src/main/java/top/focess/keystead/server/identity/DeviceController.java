package top.focess.keystead.server.identity;

import java.security.Principal;
import java.util.List;
import org.jspecify.annotations.NonNull;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/devices")
class DeviceController {

    private final IdentityService service;
    private final DeviceVaultSyncCursorService syncCursors;

    DeviceController(
            @NonNull IdentityService service, @NonNull DeviceVaultSyncCursorService syncCursors) {
        this.service = service;
        this.syncCursors = syncCursors;
    }

    @PostMapping
    @NonNull ResponseEntity<Void> register(
            @NonNull Principal principal, @RequestBody @NonNull DeviceRegistrationRequest request) {
        service.registerDevice(principal.getName(), request);
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    @GetMapping
    @NonNull List<DeviceResponse> list(@NonNull Principal principal) {
        return service.listDevices(principal.getName());
    }

    @PutMapping("/{deviceId}/vaults/{vaultId}/sync-cursor")
    @NonNull ResponseEntity<Void> acknowledgePulledRevision(
            @NonNull Principal principal,
            @PathVariable @NonNull String deviceId,
            @PathVariable @NonNull String vaultId,
            @RequestBody @NonNull DeviceVaultSyncCursorRequest request) {
        syncCursors.acknowledgePulledRevision(principal.getName(), deviceId, vaultId, request);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/{deviceId}/challenges")
    @NonNull ResponseEntity<DeviceChallengeResponse> createChallenge(
            @NonNull Principal principal, @PathVariable @NonNull String deviceId) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(service.createDeviceChallenge(principal.getName(), deviceId));
    }

    @PostMapping("/{deviceId}/proof")
    @NonNull ResponseEntity<Void> prove(
            @NonNull Principal principal,
            @PathVariable @NonNull String deviceId,
            @RequestBody @NonNull DeviceProofRequest request) {
        service.proveDevice(principal.getName(), deviceId, request);
        return ResponseEntity.noContent().build();
    }

    @DeleteMapping("/{deviceId}")
    @NonNull ResponseEntity<Void> revoke(
            @NonNull Principal principal, @PathVariable @NonNull String deviceId) {
        service.revokeDevice(principal.getName(), deviceId);
        return ResponseEntity.noContent().build();
    }
}
