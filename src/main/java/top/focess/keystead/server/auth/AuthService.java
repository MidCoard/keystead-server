package top.focess.keystead.server.auth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import org.jspecify.annotations.NonNull;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import top.focess.keystead.server.identity.DeviceSessionEligibilityService;
import top.focess.keystead.server.identity.UserTokenVersionService;
import top.focess.keystead.server.security.AccessTokenService;
import top.focess.keystead.server.security.AccessTokenService.IssuedAccessToken;

@Service
class AuthService {

    private static final Duration REFRESH_TOKEN_TTL = Duration.ofDays(30);
    private static final int REFRESH_TOKEN_BYTES = 32;

    private final UserDetailsService users;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenRepository refreshTokens;
    private final AccessTokenService accessTokens;
    private final UserTokenVersionService tokenVersions;
    private final DeviceSessionEligibilityService deviceSessions;
    private final Clock clock;
    private final SecureRandom secureRandom;

    AuthService(
            @NonNull UserDetailsService users,
            @NonNull PasswordEncoder passwordEncoder,
            @NonNull RefreshTokenRepository refreshTokens,
            @NonNull AccessTokenService accessTokens,
            @NonNull UserTokenVersionService tokenVersions,
            @NonNull DeviceSessionEligibilityService deviceSessions,
            @NonNull Clock clock) {
        this.users = users;
        this.passwordEncoder = passwordEncoder;
        this.refreshTokens = refreshTokens;
        this.accessTokens = accessTokens;
        this.tokenVersions = tokenVersions;
        this.deviceSessions = deviceSessions;
        this.clock = clock;
        this.secureRandom = new SecureRandom();
    }

    @Transactional
    @NonNull AuthTokenResponse login(@NonNull LoginRequest request) {
        UserDetails user = loadUser(request.username());
        if (!passwordEncoder.matches(request.password(), user.getPassword())) {
            throw new AuthFailedException("Authentication failed");
        }
        if (request.deviceId() != null
                && !deviceSessions.canStartSession(user.getUsername(), request.deviceId())) {
            throw new AuthFailedException("Authentication failed");
        }
        String refreshToken = newRefreshToken();
        Instant now = clock.instant();
        Instant refreshExpiresAt = now.plus(REFRESH_TOKEN_TTL);
        refreshTokens.upsert(
                new StoredRefreshToken(
                        hash(refreshToken),
                        user.getUsername(),
                        request.deviceId(),
                        refreshExpiresAt,
                        null,
                        now,
                        now));
        IssuedAccessToken accessToken =
                accessTokens.issue(
                        user.getUsername(),
                        tokenVersions.tokenVersion(user.getUsername()),
                        request.deviceId());
        return AuthTokenResponse.login(
                accessToken.token(), refreshToken, accessToken.expiresAt(), refreshExpiresAt);
    }

    @Transactional
    @NonNull AuthTokenResponse refresh(@NonNull RefreshTokenRequest request) {
        StoredRefreshToken token =
                refreshTokens
                        .find(hash(request.refreshToken()))
                        .orElseThrow(() -> new AuthFailedException("Authentication failed"));
        Instant now = clock.instant();
        if (token.revokedAt() != null || !token.refreshExpiresAt().isAfter(now)) {
            throw new AuthFailedException("Authentication failed");
        }
        if (token.deviceId() != null
                && !deviceSessions.canStartSession(token.username(), token.deviceId())) {
            throw new AuthFailedException("Authentication failed");
        }
        refreshTokens.upsert(token.withLastUsedAt(now));
        IssuedAccessToken accessToken =
                accessTokens.issue(
                        token.username(),
                        tokenVersions.tokenVersion(token.username()),
                        token.deviceId());
        return AuthTokenResponse.refreshed(accessToken.token(), accessToken.expiresAt());
    }

    @Transactional
    void revoke(@NonNull RefreshTokenRequest request) {
        String tokenHash = hash(request.refreshToken());
        refreshTokens
                .find(tokenHash)
                .ifPresent(token -> refreshTokens.upsert(token.revoked(clock.instant())));
    }

    @Transactional
    void logoutAll(@NonNull String username) {
        refreshTokens.revokeAllForUsername(username, clock.instant());
        tokenVersions.incrementTokenVersion(username);
    }

    private @NonNull UserDetails loadUser(@NonNull String username) {
        try {
            return users.loadUserByUsername(username);
        } catch (UsernameNotFoundException e) {
            throw new AuthFailedException("Authentication failed", e);
        }
    }

    private @NonNull String newRefreshToken() {
        byte[] bytes = new byte[REFRESH_TOKEN_BYTES];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static @NonNull String hash(@NonNull String token) {
        try {
            byte[] digest =
                    MessageDigest.getInstance("SHA-256")
                            .digest(token.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (Exception e) {
            throw new IllegalStateException("Could not hash refresh token", e);
        }
    }
}
