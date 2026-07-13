package top.focess.keystead.server.auth;

import java.time.Instant;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthSessionRevocationService {

    private final RefreshTokenRepository refreshTokens;

    AuthSessionRevocationService(@NonNull RefreshTokenRepository refreshTokens) {
        this.refreshTokens = refreshTokens;
    }

    @Transactional
    public void revokeAll(@NonNull String username, @NonNull Instant revokedAt) {
        refreshTokens.revokeAllForUsername(username, revokedAt);
    }
}
