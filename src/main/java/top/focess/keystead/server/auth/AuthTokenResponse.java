package top.focess.keystead.server.auth;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.time.Instant;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record AuthTokenResponse(
        @NonNull String accessToken,
        @Nullable String refreshToken,
        @NonNull Instant accessTokenExpiresAt,
        @Nullable Instant refreshTokenExpiresAt) {

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
}
