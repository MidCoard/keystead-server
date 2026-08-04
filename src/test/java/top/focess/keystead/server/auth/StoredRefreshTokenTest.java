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
    void rejectsUsageAfterRevocation() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new StoredRefreshToken(
                                "token-hash",
                                "alice",
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
                                EXPIRES_AT,
                                null,
                                CREATED_AT,
                                BEFORE_CREATED_AT));
    }

    @Test
    void rejectsBlankIdentityAndInvalidExpiry() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new StoredRefreshToken(
                                " ", "alice", EXPIRES_AT, null, CREATED_AT, LAST_USED_AT));
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new StoredRefreshToken(
                                "token-hash", " ", EXPIRES_AT, null, CREATED_AT, LAST_USED_AT));
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new StoredRefreshToken(
                                "token-hash", "alice", CREATED_AT, null, CREATED_AT, LAST_USED_AT));
    }
}
