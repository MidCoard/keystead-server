package top.focess.keystead.server.identity;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import org.junit.jupiter.api.Test;

class IdentityRowInvariantTest {

    private static final Instant CREATED_AT = Instant.parse("2026-07-09T00:00:00Z");
    private static final Instant UPDATED_AT = Instant.parse("2026-07-09T00:01:00Z");
    private static final Instant BEFORE_CREATED_AT = Instant.parse("2026-07-08T23:59:59Z");

    @Test
    void storedUserRejectsBlankPasswordHash() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new StoredUser("alice", " ", CREATED_AT, UPDATED_AT));
    }

    @Test
    void storedUserRejectsUpdatedTimeBeforeCreatedTime() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new StoredUser("alice", "password-hash", UPDATED_AT, CREATED_AT));
    }

    @Test
    void storedDeviceRejectsBlankPublicKeyFields() {
        assertThrows(
                IllegalArgumentException.class, () -> device(" ", "public-key", null, null, null));
        assertThrows(
                IllegalArgumentException.class,
                () -> device("RSA_OAEP_SHA256", " ", null, null, null));
    }

    @Test
    void storedDeviceRejectsLifecycleMarkersBeforeCreatedTime() {
        assertThrows(
                IllegalArgumentException.class,
                () -> device("RSA_OAEP_SHA256", "public-key", BEFORE_CREATED_AT, null, null));
        assertThrows(
                IllegalArgumentException.class,
                () -> device("RSA_OAEP_SHA256", "public-key", null, BEFORE_CREATED_AT, null));
        assertThrows(
                IllegalArgumentException.class,
                () -> device("RSA_OAEP_SHA256", "public-key", null, null, BEFORE_CREATED_AT));
    }

    private static StoredDevice device(
            String keyAlgorithm,
            String publicKey,
            Instant verifiedAt,
            Instant lastSeenAt,
            Instant revokedAt) {
        return new StoredDevice(
                "alice",
                "device-a",
                keyAlgorithm,
                publicKey,
                CREATED_AT,
                verifiedAt,
                lastSeenAt,
                revokedAt);
    }
}
