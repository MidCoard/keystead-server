package top.focess.keystead.server.auth;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import org.junit.jupiter.api.Test;

class StoredRefreshTokenTest {

    private static final Instant CREATED_AT = Instant.parse("2026-07-09T00:00:00Z");
    private static final Instant LAST_USED_AT = Instant.parse("2026-07-09T00:01:00Z");
    private static final Instant EXPIRES_AT = Instant.parse("2026-08-08T00:00:00Z");
    private static final Instant BEFORE_CREATED_AT = Instant.parse("2026-07-08T23:59:59Z");

    @Test
    void rejectsBlankDeviceBinding() {
        assertThrows(IllegalArgumentException.class, () -> token(" "));
    }

    @Test
    void rejectsUsageAfterRevocation() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new StoredRefreshToken(
                                "token-hash",
                                "alice",
                                "device-a",
                                EXPIRES_AT,
                                CREATED_AT,
                                CREATED_AT,
                                LAST_USED_AT));
    }

    @Test
    void rejectsLifecycleMarkersBeforeCreatedTime() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new StoredRefreshToken(
                                "token-hash",
                                "alice",
                                null,
                                EXPIRES_AT,
                                BEFORE_CREATED_AT,
                                CREATED_AT,
                                LAST_USED_AT));
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new StoredRefreshToken(
                                "token-hash",
                                "alice",
                                null,
                                EXPIRES_AT,
                                null,
                                CREATED_AT,
                                BEFORE_CREATED_AT));
    }

    @Test
    void rejectsBlankTokenHashAndUsername() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new StoredRefreshToken(
                                " ", "alice", null, EXPIRES_AT, null, CREATED_AT, LAST_USED_AT));
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new StoredRefreshToken(
                                "token-hash",
                                " ",
                                null,
                                EXPIRES_AT,
                                null,
                                CREATED_AT,
                                LAST_USED_AT));
    }

    @Test
    void rejectsExpiryNotAfterCreation() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new StoredRefreshToken(
                                "token-hash",
                                "alice",
                                null,
                                CREATED_AT,
                                null,
                                CREATED_AT,
                                LAST_USED_AT));
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new StoredRefreshToken(
                                "token-hash",
                                "alice",
                                null,
                                BEFORE_CREATED_AT,
                                null,
                                CREATED_AT,
                                LAST_USED_AT));
    }

    private static StoredRefreshToken token(String deviceId) {
        return new StoredRefreshToken(
                "token-hash", "alice", deviceId, EXPIRES_AT, null, CREATED_AT, LAST_USED_AT);
    }
}
