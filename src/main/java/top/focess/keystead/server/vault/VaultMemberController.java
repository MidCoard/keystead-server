package top.focess.keystead.server.vault;

import java.security.Principal;
import java.util.List;
import org.jspecify.annotations.NonNull;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/vaults/{fingerprint}/members")
class VaultMemberController {
    private final VaultMemberService service;

    VaultMemberController(@NonNull VaultMemberService service) {
        this.service = service;
    }

    @GetMapping
    @NonNull List<VaultMemberResponse> list(
            @NonNull Principal principal, @PathVariable @NonNull String fingerprint) {
        return service.list(principal.getName(), fingerprint);
    }

    @PutMapping("/{userId}")
    @NonNull ResponseEntity<Void> invite(
            @NonNull Principal principal,
            @PathVariable @NonNull String fingerprint,
            @PathVariable @NonNull String userId,
            @RequestBody @NonNull VaultMemberRequest request) {
        service.invite(principal.getName(), fingerprint, userId, request);
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    @PostMapping("/accept")
    @NonNull ResponseEntity<Void> accept(
            @NonNull Principal principal, @PathVariable @NonNull String fingerprint) {
        service.accept(principal.getName(), fingerprint);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/decline")
    @NonNull ResponseEntity<Void> decline(
            @NonNull Principal principal, @PathVariable @NonNull String fingerprint) {
        service.decline(principal.getName(), fingerprint);
        return ResponseEntity.noContent().build();
    }

    @PutMapping("/{userId}/role")
    @NonNull ResponseEntity<Void> role(
            @NonNull Principal principal,
            @PathVariable @NonNull String fingerprint,
            @PathVariable @NonNull String userId,
            @RequestBody @NonNull VaultMemberRequest request) {
        service.changeRole(principal.getName(), fingerprint, userId, request);
        return ResponseEntity.noContent().build();
    }

    @DeleteMapping("/{userId}")
    @NonNull ResponseEntity<Void> remove(
            @NonNull Principal principal,
            @PathVariable @NonNull String fingerprint,
            @PathVariable @NonNull String userId) {
        service.remove(principal.getName(), fingerprint, userId);
        return ResponseEntity.noContent().build();
    }
}
