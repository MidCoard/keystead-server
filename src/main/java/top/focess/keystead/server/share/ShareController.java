package top.focess.keystead.server.share;

import jakarta.servlet.http.HttpServletRequest;
import java.security.Principal;
import java.util.List;
import org.jspecify.annotations.NonNull;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/shares")
class ShareController {

    private static final String RETRY_AFTER_SECONDS = "60";

    private final ShareService service;

    ShareController(@NonNull ShareService service) {
        this.service = service;
    }

    @PostMapping
    @NonNull ResponseEntity<MintShareResponse> mint(
            @NonNull Principal principal, @RequestBody @NonNull MintShareRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(service.mint(principal.getName(), request));
    }

    @GetMapping("/{code}")
    @NonNull RedeemShareResponse redeem(
            @PathVariable @NonNull String code, @NonNull HttpServletRequest request) {
        return service.redeem(code, clientIp(request));
    }

    @GetMapping
    @NonNull List<ShareSummary> list(@NonNull Principal principal) {
        return service.list(principal.getName());
    }

    @DeleteMapping("/{code}")
    @NonNull ResponseEntity<Void> delete(
            @NonNull Principal principal, @PathVariable @NonNull String code) {
        service.delete(principal.getName(), code);
        return ResponseEntity.noContent().build();
    }

    @ExceptionHandler(InvalidShareRequestException.class)
    @NonNull ResponseEntity<Void> invalidRequest(@NonNull InvalidShareRequestException exception) {
        return ResponseEntity.badRequest().build();
    }

    @ExceptionHandler(ShareNotFoundException.class)
    @NonNull ResponseEntity<Void> notFound(@NonNull ShareNotFoundException exception) {
        return ResponseEntity.notFound().build();
    }

    @ExceptionHandler(ShareExpiredException.class)
    @NonNull ResponseEntity<Void> expired(@NonNull ShareExpiredException exception) {
        return ResponseEntity.status(HttpStatus.GONE).build();
    }

    @ExceptionHandler(ShareRateLimitedException.class)
    @NonNull ResponseEntity<Void> rateLimited(@NonNull ShareRateLimitedException exception) {
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                .header("Retry-After", RETRY_AFTER_SECONDS)
                .build();
    }

    private static @NonNull String clientIp(@NonNull HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            int comma = forwarded.indexOf(',');
            String first = comma > 0 ? forwarded.substring(0, comma) : forwarded;
            String trimmed = first.strip();
            if (!trimmed.isEmpty()) {
                return trimmed;
            }
        }
        return request.getRemoteAddr();
    }
}
