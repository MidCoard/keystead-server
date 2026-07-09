package top.focess.keystead.server.identity;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.test.context.ActiveProfiles;

@SpringBootTest
@ActiveProfiles("test")
class IdentityRepositoryTest {

    private static final Instant CREATED_AT = Instant.parse("2026-07-09T00:00:00Z");
    private static final Instant UPDATED_AT = Instant.parse("2026-07-09T00:01:00Z");

    @Autowired private UserRepository users;
    @Autowired private DeviceRepository devices;
    @Autowired private DeviceChallengeRepository challenges;

    @Test
    void databaseInsertRejectsDuplicateUsername() {
        users.insert(user("identity-db-user", "password-hash-a"));

        assertThrows(
                DataIntegrityViolationException.class,
                () -> users.insert(user("identity-db-user", "password-hash-b")));
    }

    @Test
    void databaseInsertRejectsDuplicateDevicePrimaryKey() {
        devices.insert(device("identity-db-device-owner", "laptop-a", "public-key-a"));

        assertThrows(
                DataIntegrityViolationException.class,
                () ->
                        devices.insert(
                                device("identity-db-device-owner", "laptop-a", "public-key-b")));
    }

    @Test
    void databaseInsertRejectsDuplicateDeviceChallengePrimaryKey() {
        challenges.insert(
                challenge("identity-db-challenge-owner", "laptop-a", "challenge-a", "nonce-a"));

        assertThrows(
                DataIntegrityViolationException.class,
                () ->
                        challenges.insert(
                                challenge(
                                        "identity-db-challenge-owner",
                                        "laptop-a",
                                        "challenge-a",
                                        "nonce-b")));
    }

    private static StoredUser user(String username, String passwordHash) {
        return new StoredUser(username, passwordHash, CREATED_AT, UPDATED_AT, 0L);
    }

    private static StoredDevice device(String ownerId, String deviceId, String publicKey) {
        return new StoredDevice(
                ownerId, deviceId, "RSA_OAEP_SHA256", publicKey, CREATED_AT, null, null, null);
    }

    private static StoredDeviceChallenge challenge(
            String ownerId, String deviceId, String challengeId, String nonce) {
        return new StoredDeviceChallenge(
                ownerId, deviceId, challengeId, nonce, UPDATED_AT, null, CREATED_AT);
    }
}
