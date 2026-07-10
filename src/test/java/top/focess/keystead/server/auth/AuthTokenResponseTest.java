package top.focess.keystead.server.auth;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import org.junit.jupiter.api.Test;

class AuthTokenResponseTest {

    private static final Instant ACCESS_EXPIRES_AT = Instant.parse("2026-07-09T00:15:00Z");
    private static final Instant REFRESH_EXPIRES_AT = Instant.parse("2026-08-08T00:00:00Z");

    @Test
    void rejectsBlankAccessToken() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new AuthTokenResponse(" ", null, ACCESS_EXPIRES_AT, null));
    }

    @Test
    void rejectsBlankRefreshTokenWhenPresent() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new AuthTokenResponse(
                                "access-token", " ", ACCESS_EXPIRES_AT, REFRESH_EXPIRES_AT));
    }

    @Test
    void rejectsRefreshTokenWithoutExpiry() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new AuthTokenResponse(
                                "access-token", "refresh-token", ACCESS_EXPIRES_AT, null));
    }

    @Test
    void rejectsRefreshExpiryWithoutRefreshToken() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new AuthTokenResponse(
                                "access-token", null, ACCESS_EXPIRES_AT, REFRESH_EXPIRES_AT));
    }

    @Test
    void refreshedResponseCarriesReplacementRefreshToken() {
        new AuthTokenResponse(
                "access-token", "replacement-token", ACCESS_EXPIRES_AT, REFRESH_EXPIRES_AT);
    }
}
