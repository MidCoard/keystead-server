package top.focess.keystead.server.auth;

import jakarta.validation.Valid;
import java.util.Map;
import org.jspecify.annotations.NonNull;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
class AuthController {

    private final AuthService service;

    AuthController(@NonNull AuthService service) {
        this.service = service;
    }

    @PostMapping("/login")
    @NonNull AuthTokenResponse login(@Valid @RequestBody @NonNull LoginRequest request) {
        return service.login(request);
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

    @ExceptionHandler(AuthFailedException.class)
    @NonNull ResponseEntity<Map<String, String>> authFailed(
            @NonNull AuthFailedException exception) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("message", exception.getMessage()));
    }
}
