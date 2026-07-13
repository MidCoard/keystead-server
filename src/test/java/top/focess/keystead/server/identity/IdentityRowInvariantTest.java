package top.focess.keystead.server.identity;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
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
                () -> new StoredUser("alice", " ", CREATED_AT, UPDATED_AT, 0L));
    }

    @Test
    void storedUserRejectsBlankUsername() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new StoredUser(" ", "password-hash", CREATED_AT, UPDATED_AT, 0L));
    }

    @Test
    void storedUserRejectsUpdatedTimeBeforeCreatedTime() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new StoredUser("alice", "password-hash", UPDATED_AT, CREATED_AT, 0L));
    }

    @Test
    void storedUserRejectsNegativeTokenVersion() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new StoredUser("alice", "password-hash", CREATED_AT, UPDATED_AT, -1L));
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
    void storedDeviceRejectsBlankPrimaryKeys() {
        assertThrows(
                IllegalArgumentException.class,
                () -> device(" ", "device-a", "RSA_OAEP_SHA256", "public-key"));
        assertThrows(
                IllegalArgumentException.class,
                () -> device("alice", " ", "RSA_OAEP_SHA256", "public-key"));
    }

    @Test
    void storedDeviceRejectsUnsupportedAlgorithm() {
        assertThrows(
                IllegalArgumentException.class,
                () -> device("alice", "device-a", "RAW_RSA", "public-key"));
    }

    @Test
    void storedDeviceAcceptsApprovedWrappingPublicKeyAlgorithms() {
        assertDoesNotThrow(
                () ->
                        deviceWithWrapping(
                                "TINK_ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM",
                                "tink-wrapping-public-key"));
        assertDoesNotThrow(() -> deviceWithWrapping("RSA_OAEP_SHA256", "rsa-wrapping-public-key"));
    }

    @Test
    void storedDeviceRejectsHalfPresentWrappingPublicKeyPair() {
        assertThrows(
                IllegalArgumentException.class, () -> deviceWithWrapping("RSA_OAEP_SHA256", null));
        assertThrows(
                IllegalArgumentException.class,
                () -> deviceWithWrapping(null, "rsa-wrapping-public-key"));
    }

    @Test
    void storedDeviceRejectsNonPublicWrappingAlgorithm() {
        assertThrows(
                IllegalArgumentException.class,
                () -> deviceWithWrapping("TINK_DEVICE_KEY_PACKAGE", "not-a-public-key-algorithm"));
    }

    @Test
    void storedDeviceRejectsReusedProofAndWrappingPublicKey() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new StoredDevice(
                                "alice",
                                "device-a",
                                "RSA_OAEP_SHA256",
                                "same-public-key",
                                "RSA_OAEP_SHA256",
                                "same-public-key",
                                CREATED_AT,
                                null,
                                null,
                                null));
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new StoredDevice(
                                "alice",
                                "device-a",
                                "ED25519",
                                "AQI=",
                                "RSA_OAEP_SHA256",
                                "AQI",
                                CREATED_AT,
                                null,
                                null,
                                null));
    }

    @Test
    void storedDeviceRejectsAmbiguousP256ProofAndWrappingKeyPairing() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new StoredDevice(
                                "alice",
                                "device-p256-ambiguous",
                                "ECDSA_P256_SHA256",
                                "x509-p256-proof-public-key",
                                "TINK_ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM",
                                "tink-p256-wrapping-public-key",
                                CREATED_AT,
                                null,
                                null,
                                null));
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

    @Test
    void storedDeviceChallengeRejectsBlankNonce() {
        assertThrows(
                IllegalArgumentException.class, () -> challenge(" ", UPDATED_AT, null, CREATED_AT));
    }

    @Test
    void storedDeviceChallengeRejectsBlankPrimaryKeys() {
        assertThrows(
                IllegalArgumentException.class,
                () -> challenge(" ", "device-a", "challenge-a", "nonce"));
        assertThrows(
                IllegalArgumentException.class,
                () -> challenge("alice", " ", "challenge-a", "nonce"));
        assertThrows(
                IllegalArgumentException.class, () -> challenge("alice", "device-a", " ", "nonce"));
    }

    @Test
    void storedDeviceChallengeRejectsExpiryBeforeCreatedTime() {
        assertThrows(
                IllegalArgumentException.class,
                () -> challenge("nonce", BEFORE_CREATED_AT, null, CREATED_AT));
    }

    @Test
    void storedDeviceChallengeRejectsUsedTimeOutsideChallengeWindow() {
        assertThrows(
                IllegalArgumentException.class,
                () -> challenge("nonce", UPDATED_AT, BEFORE_CREATED_AT, CREATED_AT));
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        challenge(
                                "nonce",
                                UPDATED_AT,
                                Instant.parse("2026-07-09T00:02:00Z"),
                                CREATED_AT));
    }

    @Test
    void storedDeviceVaultSyncCursorRejectsNegativeRevisionAndBlankPrimaryKeys() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new StoredDeviceVaultSyncCursor(
                                "alice", "vault-a", "device-a", -1L, UPDATED_AT));
        assertThrows(
                IllegalArgumentException.class,
                () -> new StoredDeviceVaultSyncCursor(" ", "vault-a", "device-a", 1L, UPDATED_AT));
        assertThrows(
                IllegalArgumentException.class,
                () -> new StoredDeviceVaultSyncCursor("alice", " ", "device-a", 1L, UPDATED_AT));
        assertThrows(
                IllegalArgumentException.class,
                () -> new StoredDeviceVaultSyncCursor("alice", "vault-a", " ", 1L, UPDATED_AT));
    }

    private static StoredDevice device(
            String keyAlgorithm,
            String publicKey,
            Instant verifiedAt,
            Instant lastSeenAt,
            Instant revokedAt) {
        return device(
                "alice", "device-a", keyAlgorithm, publicKey, verifiedAt, lastSeenAt, revokedAt);
    }

    private static StoredDevice device(
            String ownerId, String deviceId, String keyAlgorithm, String publicKey) {
        return device(ownerId, deviceId, keyAlgorithm, publicKey, null, null, null);
    }

    private static StoredDevice device(
            String ownerId,
            String deviceId,
            String keyAlgorithm,
            String publicKey,
            Instant verifiedAt,
            Instant lastSeenAt,
            Instant revokedAt) {
        return new StoredDevice(
                ownerId,
                deviceId,
                keyAlgorithm,
                publicKey,
                CREATED_AT,
                verifiedAt,
                lastSeenAt,
                revokedAt);
    }

    private static StoredDevice deviceWithWrapping(
            String wrappingKeyAlgorithm, String wrappingPublicKey) {
        return new StoredDevice(
                "alice",
                "device-a",
                "ED25519",
                "proof-public-key",
                wrappingKeyAlgorithm,
                wrappingPublicKey,
                CREATED_AT,
                null,
                null,
                null);
    }

    private static StoredDeviceChallenge challenge(
            String nonce, Instant expiresAt, Instant usedAt, Instant createdAt) {
        return new StoredDeviceChallenge(
                "alice", "device-a", "challenge-a", nonce, expiresAt, usedAt, createdAt);
    }

    private static StoredDeviceChallenge challenge(
            String ownerId, String deviceId, String challengeId, String nonce) {
        return new StoredDeviceChallenge(
                ownerId, deviceId, challengeId, nonce, UPDATED_AT, null, CREATED_AT);
    }
}
