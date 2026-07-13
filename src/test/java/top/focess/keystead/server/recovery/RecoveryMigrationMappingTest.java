package top.focess.keystead.server.recovery;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;
import org.junit.jupiter.api.Test;

class RecoveryMigrationMappingTest {

    @Test
    void migrationCreatesJPARecoveryTablesWithoutPlaintextSecrets() throws IOException {
        String migration =
                Files.readString(
                                Path.of(
                                        "src/main/resources/db/migration/V20__zero_knowledge_recovery.sql"))
                        .toLowerCase(Locale.ROOT)
                        .replaceAll("\\s+", " ")
                        .trim();

        assertTrue(migration.contains("create table recovery_enrollments"));
        assertTrue(migration.contains("create table recovery_vault_packages"));
        assertTrue(migration.contains("create table recovery_challenges"));
        assertTrue(migration.contains("create table recovery_device_requests"));
        assertTrue(migration.contains("create table recovery_sessions"));
        assertTrue(migration.contains("credential_hash varchar(255) not null"));
        assertTrue(migration.contains("encrypted_private_key text not null"));
        assertTrue(migration.contains("token_hash varchar(255) not null"));
        assertFalse(migration.contains("recovery_secret"));
        assertFalse(migration.contains("plaintext_private_key"));
        assertFalse(migration.contains("new_password"));
        assertFalse(migration.contains("local_passphrase"));
    }
}
