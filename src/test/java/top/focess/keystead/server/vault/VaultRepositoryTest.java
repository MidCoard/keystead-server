package top.focess.keystead.server.vault;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.test.context.ActiveProfiles;

@SpringBootTest
@ActiveProfiles("test")
class VaultRepositoryTest {

    private static final Instant CREATED_AT = Instant.parse("2026-07-09T00:00:00Z");
    private static final Instant UPDATED_AT = Instant.parse("2026-07-09T00:01:00Z");

    @Autowired private VaultRepository vaults;
    @Autowired private VaultKeyPackageRepository keyPackages;

    @Test
    void databaseInsertRejectsDuplicateVaultPrimaryKey() {
        vaults.insert(vault("vault-db-primary-key", "alice", "encrypted-metadata-a"));

        assertThrows(
                DataIntegrityViolationException.class,
                () ->
                        vaults.insert(
                                vault("vault-db-primary-key", "alice", "encrypted-metadata-b")));
    }

    @Test
    void databaseInsertRejectsDuplicateVaultKeyPackagePrimaryKey() {
        keyPackages.insert(keyPackage("package-db-owner", "vault-a", "device-a", "wrapped-key-a"));

        assertThrows(
                DataIntegrityViolationException.class,
                () ->
                        keyPackages.insert(
                                keyPackage(
                                        "package-db-owner",
                                        "vault-a",
                                        "device-a",
                                        "wrapped-key-b")));
    }

    private static StoredVault vault(String vaultId, String ownerId, String encryptedMetadata) {
        return new StoredVault(ownerId, vaultId, encryptedMetadata, CREATED_AT, UPDATED_AT);
    }

    private static StoredVaultKeyPackage keyPackage(
            String ownerId, String vaultId, String deviceId, String encryptedVaultKey) {
        return new StoredVaultKeyPackage(
                ownerId,
                vaultId,
                deviceId,
                "RSA_OAEP_SHA256",
                encryptedVaultKey,
                CREATED_AT,
                UPDATED_AT);
    }
}
