package top.focess.keystead.server.recovery;

import org.jspecify.annotations.NonNull;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth/recovery/device-requests")
final class RecoveryPublicDeviceController {

    private final RecoveryDeviceService devices;

    RecoveryPublicDeviceController(@NonNull RecoveryDeviceService devices) {
        this.devices = devices;
    }

    @PostMapping
    @NonNull ResponseEntity<RecoveryDeviceRequestResponse> create(
            @RequestBody @NonNull RecoveryDeviceRequestPayload request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(devices.create(request));
    }

    @GetMapping("/{requestId}")
    @NonNull RecoveryDeviceRequestResponse status(@PathVariable @NonNull String requestId) {
        return devices.status(requestId);
    }

    @PostMapping("/{requestId}/claim")
    @NonNull RecoverySessionResponse claim(
            @PathVariable @NonNull String requestId,
            @RequestBody @NonNull RecoveryDeviceClaimRequest request) {
        return devices.claim(requestId, request);
    }
}
