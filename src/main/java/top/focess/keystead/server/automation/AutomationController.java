package top.focess.keystead.server.automation;

import java.security.Principal;
import org.jspecify.annotations.NonNull;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/vaults/{vaultId}/automation-principals")
class AutomationController {

    private final AutomationService automation;

    AutomationController(@NonNull AutomationService automation) {
        this.automation = automation;
    }

    @PutMapping("/{principalId}")
    @NonNull ResponseEntity<Void> putPrincipal(
            @NonNull Principal principal,
            @PathVariable @NonNull String vaultId,
            @PathVariable @NonNull String principalId,
            @RequestBody @NonNull AutomationPrincipalRequest request) {
        automation.putPrincipal(principal.getName(), vaultId, principalId, request);
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    @PutMapping("/{principalId}/key-package")
    @NonNull ResponseEntity<Void> putKeyPackage(
            @NonNull Principal principal,
            @PathVariable @NonNull String vaultId,
            @PathVariable @NonNull String principalId,
            @RequestBody @NonNull AutomationVaultKeyPackageRequest request) {
        automation.putKeyPackage(principal.getName(), vaultId, principalId, request);
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    @PostMapping("/{principalId}/tokens")
    @NonNull AutomationTokenResponse issueToken(
            @NonNull Principal principal,
            @PathVariable @NonNull String vaultId,
            @PathVariable @NonNull String principalId,
            @RequestBody @NonNull IssueAutomationTokenRequest request) {
        return automation.issueToken(principal.getName(), vaultId, principalId, request);
    }

    @DeleteMapping("/tokens")
    @NonNull ResponseEntity<Void> revokeToken(
            @NonNull Principal principal,
            @PathVariable @NonNull String vaultId,
            @RequestBody @NonNull RevokeAutomationTokenRequest request) {
        automation.revokeToken(principal.getName(), vaultId, request);
        return ResponseEntity.noContent().build();
    }

    @DeleteMapping("/{principalId}")
    @NonNull ResponseEntity<Void> revokePrincipal(
            @NonNull Principal principal,
            @PathVariable @NonNull String vaultId,
            @PathVariable @NonNull String principalId) {
        automation.revokePrincipal(principal.getName(), vaultId, principalId);
        return ResponseEntity.noContent().build();
    }

    @ExceptionHandler(InvalidAutomationRequestException.class)
    @NonNull ResponseEntity<Void> invalidRequest(
            @NonNull InvalidAutomationRequestException exception) {
        return ResponseEntity.badRequest().build();
    }

    @ExceptionHandler(AutomationNotFoundException.class)
    @NonNull ResponseEntity<Void> notFound(@NonNull AutomationNotFoundException exception) {
        return ResponseEntity.notFound().build();
    }
}
