package top.focess.keystead.server.identity;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;
import org.junit.jupiter.api.Test;

class DeviceVaultSyncCursorMigrationMappingTest {

    @Test
    void migrationCreatesEntityDeclaredAcknowledgementIndex() throws IOException {
        String migrations = migrationSql();

        assertTrue(
                migrations.contains(
                                "create index idx_device_vault_sync_cursors_owner_vault_revision")
                        && migrations.contains(
                                "on device_vault_sync_cursors (owner_id, vault_id, pulled_revision)"));
    }

    private static String migrationSql() throws IOException {
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
