package top.focess.keystead.server.recovery;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth/recovery")
final class RecoveryAuthController {

    private final RecoverySessionService sessions;

    RecoveryAuthController(@NonNull RecoverySessionService sessions) {
        this.sessions = sessions;
    }

    @PostMapping("/challenges")
    @NonNull ResponseEntity<RecoveryChallengeResponse> challenge(
            @RequestBody @NonNull RecoveryChallengeRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(sessions.createChallenge(request));
    }

    @PostMapping("/kit")
    @NonNull RecoverySessionResponse verify(
            @RequestBody @NonNull RecoveryCredentialRequest request) {
        return sessions.verifyKit(request);
    }

    @GetMapping("/material")
    @NonNull RecoveryMaterialResponse material(
            @RequestHeader(name = HttpHeaders.AUTHORIZATION, required = false)
                    @Nullable String authorization) {
        return sessions.material(authorization);
    }
}
