package top.focess.keystead.server.auth;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.time.Instant;
import java.util.Objects;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record AuthTokenResponse(
        @NonNull String accessToken,
        @Nullable String refreshToken,
        @NonNull Instant accessTokenExpiresAt,
        @Nullable Instant refreshTokenExpiresAt) {

    public AuthTokenResponse {
        requireNotBlank(accessToken, "accessToken");
        Objects.requireNonNull(accessTokenExpiresAt, "accessTokenExpiresAt");
        if (refreshToken == null) {
            if (refreshTokenExpiresAt != null) {
                throw new IllegalArgumentException(
                        "refreshTokenExpiresAt requires a refresh token");
            }
        } else {
            requireNotBlank(refreshToken, "refreshToken");
            if (refreshTokenExpiresAt == null) {
                throw new IllegalArgumentException(
                        "refreshTokenExpiresAt is required with a refresh token");
            }
        }
    }

    static @NonNull AuthTokenResponse login(
            @NonNull String accessToken,
            @NonNull String refreshToken,
            @NonNull Instant accessTokenExpiresAt,
            @NonNull Instant refreshTokenExpiresAt) {
        return new AuthTokenResponse(
                accessToken, refreshToken, accessTokenExpiresAt, refreshTokenExpiresAt);
    }

    static @NonNull AuthTokenResponse refreshed(
            @NonNull String accessToken, @NonNull Instant accessTokenExpiresAt) {
        return new AuthTokenResponse(accessToken, null, accessTokenExpiresAt, null);
    }

    private static void requireNotBlank(@NonNull String value, @NonNull String field) {
        Objects.requireNonNull(value, field);
        if (value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
    }
}
