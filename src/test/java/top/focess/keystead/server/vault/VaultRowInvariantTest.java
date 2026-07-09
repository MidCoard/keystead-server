package top.focess.keystead.server.vault;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import org.junit.jupiter.api.Test;

class VaultRowInvariantTest {

    private static final Instant CREATED_AT = Instant.parse("2026-07-09T00:00:00Z");
    private static final Instant UPDATED_AT = Instant.parse("2026-07-09T00:01:00Z");

    @Test
    void storedVaultRejectsBlankEncryptedMetadata() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new StoredVault("alice", "vault-a", " ", CREATED_AT, UPDATED_AT));
    }

    @Test
    void storedVaultRejectsBlankPrimaryKeys() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new StoredVault(
                                " ", "vault-a", "encrypted-metadata", CREATED_AT, UPDATED_AT));
        assertThrows(
                IllegalArgumentException.class,
                () -> new StoredVault("alice", " ", "encrypted-metadata", CREATED_AT, UPDATED_AT));
    }

    @Test
    void storedVaultRejectsUpdatedTimeBeforeCreatedTime() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new StoredVault(
                                "alice", "vault-a", "encrypted-metadata", UPDATED_AT, CREATED_AT));
    }

    @Test
    void storedVaultKeyPackageRejectsBlankOpaqueFields() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new StoredVaultKeyPackage(
                                "alice",
                                "vault-a",
                                "device-a",
                                " ",
                                "wrapped-key",
                                CREATED_AT,
                                UPDATED_AT));
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new StoredVaultKeyPackage(
                                "alice",
                                "vault-a",
                                "device-a",
                                "RSA_OAEP_SHA256",
                                " ",
                                CREATED_AT,
                                UPDATED_AT));
    }

    @Test
    void storedVaultKeyPackageRejectsBlankPrimaryKeys() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new StoredVaultKeyPackage(
                                " ",
                                "vault-a",
                                "device-a",
                                "RSA_OAEP_SHA256",
                                "wrapped-key",
                                CREATED_AT,
                                UPDATED_AT));
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new StoredVaultKeyPackage(
                                "alice",
                                " ",
                                "device-a",
                                "RSA_OAEP_SHA256",
                                "wrapped-key",
                                CREATED_AT,
                                UPDATED_AT));
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new StoredVaultKeyPackage(
                                "alice",
                                "vault-a",
                                " ",
                                "RSA_OAEP_SHA256",
                                "wrapped-key",
                                CREATED_AT,
                                UPDATED_AT));
    }

    @Test
    void storedVaultKeyPackageRejectsUnsupportedAlgorithm() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new StoredVaultKeyPackage(
                                "alice",
                                "vault-a",
                                "device-a",
                                "RAW_RSA",
                                "wrapped-key",
                                CREATED_AT,
                                UPDATED_AT));
    }

    @Test
    void storedVaultKeyPackageRejectsUpdatedTimeBeforeCreatedTime() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new StoredVaultKeyPackage(
                                "alice",
                                "vault-a",
                                "device-a",
                                "RSA_OAEP_SHA256",
                                "wrapped-key",
                                UPDATED_AT,
                                CREATED_AT));
    }
}
