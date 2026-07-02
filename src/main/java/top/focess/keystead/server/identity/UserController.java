package top.focess.keystead.server.identity;

import jakarta.validation.Valid;
import org.jspecify.annotations.NonNull;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/users")
class UserController {

    private final IdentityService service;

    UserController(@NonNull IdentityService service) {
        this.service = service;
    }

    @PostMapping
    @NonNull ResponseEntity<Void> register(
            @Valid @RequestBody @NonNull UserRegistrationRequest request) {
        service.register(request);
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }
}
