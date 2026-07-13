package top.focess.keystead.server.recovery;

import java.security.Principal;
import java.util.List;
import org.jspecify.annotations.NonNull;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/recovery/device-requests")
final class RecoveryDeviceController {

    private final RecoveryDeviceService devices;

    RecoveryDeviceController(@NonNull RecoveryDeviceService devices) {
        this.devices = devices;
    }

    @GetMapping
    @NonNull List<RecoveryDeviceRequestResponse> list(@NonNull Principal principal) {
        return devices.listPending(principal.getName());
    }

    @PostMapping("/{requestId}/approve")
    @NonNull ResponseEntity<Void> approve(
            @NonNull Principal principal,
            @PathVariable @NonNull String requestId,
            @RequestBody @NonNull RecoveryDeviceApprovalRequest request) {
        devices.approve(principal.getName(), requestId, request);
        return ResponseEntity.noContent().build();
    }
}
