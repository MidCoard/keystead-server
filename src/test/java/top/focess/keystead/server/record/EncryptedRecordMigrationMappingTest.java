package top.focess.keystead.server.record;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;
import org.junit.jupiter.api.Test;

class EncryptedRecordMigrationMappingTest {

    @Test
    void migrationsCreateEntityDeclaredRevisionAndSyncIndexes() throws IOException {
        String migrations = encryptedRecordMigrationSql();

        assertTrue(
                migrations.contains("create unique index uq_encrypted_records_owner_vault_revision")
                        && migrations.contains(
                                "on encrypted_records (owner_id, vault_id, revision)"));
        assertTrue(
                migrations.contains("create index idx_encrypted_records_sync_page")
                        && migrations.contains(
                                "on encrypted_records (owner_id, vault_id, revision, secret_id)"));
    }

    private static String encryptedRecordMigrationSql() throws IOException {
        StringBuilder sql = new StringBuilder();
        try (var paths = Files.list(Path.of("src/main/resources/db/migration"))) {
            for (Path path :
                    paths.filter(path -> path.getFileName().toString().endsWith(".sql"))
                            .sorted()
                            .toList()) {
                sql.append(Files.readString(path)).append('\n');
            }
        }
        return sql.toString().toLowerCase(Locale.ROOT).replaceAll("\\s+", " ").trim();
    }
}
