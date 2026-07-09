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
@RequestMapping("/api/v1/vaults")
class VaultController {

    private final VaultService service;

    VaultController(@NonNull VaultService service) {
        this.service = service;
    }

    @PutMapping("/{vaultId}")
    @NonNull ResponseEntity<Void> put(
            @NonNull Principal principal,
            @PathVariable @NonNull String vaultId,
            @RequestBody @NonNull VaultRequest request) {
        service.put(principal.getName(), vaultId, request);
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    @GetMapping
    @NonNull List<VaultResponse> list(@NonNull Principal principal) {
        return service.list(principal.getName());
    }
}
