package top.focess.keystead.server.record;

import jakarta.validation.Valid;
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
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/vaults/{vaultId}/records")
class EncryptedRecordController {

    private final EncryptedRecordService service;

    EncryptedRecordController(@NonNull EncryptedRecordService service) {
        this.service = service;
    }

    @PutMapping("/{secretId}")
    @NonNull ResponseEntity<Void> put(
            @NonNull Principal principal,
            @PathVariable @NonNull String vaultId,
            @PathVariable @NonNull String secretId,
            @Valid @RequestBody @NonNull EncryptedRecordRequest request) {
        StoreRecordResult result = service.store(principal.getName(), vaultId, secretId, request);
        return ResponseEntity.status(
                        result == StoreRecordResult.CREATED ? HttpStatus.CREATED : HttpStatus.OK)
                .build();
    }

    @GetMapping("/{secretId}")
    @NonNull ResponseEntity<EncryptedRecordResponse> get(
            @NonNull Principal principal,
            @PathVariable @NonNull String vaultId,
            @PathVariable @NonNull String secretId) {
        return service.find(principal.getName(), vaultId, secretId)
                .map(EncryptedRecordResponse::from)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @GetMapping
    @NonNull List<EncryptedRecordResponse> list(
            @NonNull Principal principal,
            @PathVariable @NonNull String vaultId,
            @RequestParam(defaultValue = "0") long sinceRevision) {
        return service.listSince(principal.getName(), vaultId, sinceRevision);
    }
}
