package top.focess.keystead.server.vaultaccess;

import java.security.Principal;
import java.util.List;
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
@RequestMapping("/api/v1/vault-access-requests")
final class VaultAccessRequestController {

    private final VaultAccessRequestService requests;

    VaultAccessRequestController(@NonNull VaultAccessRequestService requests) {
        this.requests = requests;
    }

    @PostMapping
    @NonNull ResponseEntity<VaultAccessRequestResponse> create(
            @NonNull Principal principal, @RequestBody @NonNull VaultAccessCreateRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(requests.create(principal.getName(), request));
    }

    @GetMapping
    @NonNull List<VaultAccessRequestResponse> list(@NonNull Principal principal) {
        return requests.listPending(principal.getName());
    }

    @GetMapping("/{requestId}")
    @NonNull VaultAccessRequestResponse status(
            @NonNull Principal principal, @PathVariable @NonNull String requestId) {
        return requests.status(principal.getName(), requestId);
    }

    @PostMapping("/{requestId}/approve")
    @NonNull ResponseEntity<Void> approve(
            @NonNull Principal principal,
            @PathVariable @NonNull String requestId,
            @RequestBody @NonNull VaultAccessApprovalRequest request) {
        requests.approve(principal.getName(), requestId, request);
        return ResponseEntity.noContent().build();
    }
}
