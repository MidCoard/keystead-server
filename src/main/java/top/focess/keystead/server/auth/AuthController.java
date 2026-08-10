package top.focess.keystead.server.auth;

import jakarta.validation.Valid;
import java.security.Principal;
import java.util.Map;
import org.jspecify.annotations.NonNull;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import top.focess.keystead.server.audit.AuditService;

@RestController
@RequestMapping("/api/v1/auth")
class AuthController {

    private final AuthService service;
    private final AuditService audit;

    AuthController(@NonNull AuthService service, @NonNull AuditService audit) {
        this.service = service;
        this.audit = audit;
    }

    @PostMapping("/login")
    @NonNull AuthTokenResponse login(@Valid @RequestBody @NonNull LoginRequest request) {
        try {
            return service.login(request);
        } catch (AuthFailedException e) {
            // Audit after the login transaction has rolled back so the event persists; the
            // real client authenticates here (JSON body, not a Basic header), so this is
            // where wrong-password attempts are recorded.
            audit.loginFailed(request.username());
            throw e;
        }
    }

    @PostMapping("/refresh")
    @NonNull AuthTokenResponse refresh(@Valid @RequestBody @NonNull RefreshTokenRequest request) {
        return service.refresh(request);
    }

    @PostMapping("/revoke")
    @NonNull ResponseEntity<Void> revoke(@Valid @RequestBody @NonNull RefreshTokenRequest request) {
        service.revoke(request);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/logout-all")
    @NonNull ResponseEntity<Void> logoutAll(@NonNull Principal principal) {
        service.logoutAll(principal.getName());
        return ResponseEntity.noContent().build();
    }

    @ExceptionHandler(AuthFailedException.class)
    @NonNull ResponseEntity<Map<String, String>> authFailed(
            @NonNull AuthFailedException exception) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("message", exception.getMessage()));
    }
}
