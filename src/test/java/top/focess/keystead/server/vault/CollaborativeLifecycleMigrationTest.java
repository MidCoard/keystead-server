package top.focess.keystead.server.vault;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.Locale;
import java.util.UUID;
import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.MigrationVersion;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

class CollaborativeLifecycleMigrationTest {

    @Test
    void membershipEnumIncludesAcceptedPendingKey() {
        assertArrayEquals(
                new VaultMemberState[] {
                    VaultMemberState.INVITED,
                    VaultMemberState.ACCEPTED_PENDING_KEY,
                    VaultMemberState.ACTIVE,
                    VaultMemberState.REMOVED
                },
                VaultMemberState.values());
    }

    @Test
    void migrationDefinesOnlyPublicLifecycleAndOpaquePackageState() throws IOException {
        String migration =
                Files.readString(
                                Path.of(
                                        "src/main/resources/db/migration/V21__collaborative_vault_lifecycle.sql"))
                        .toLowerCase(Locale.ROOT)
                        .replaceAll("\\s+", " ")
                        .trim();

        assertTrue(migration.contains("create table vault_key_states"));
        assertTrue(migration.contains("create table vault_rotation_generations"));
        assertTrue(migration.contains("create table vault_rotation_targets"));
        assertTrue(migration.contains("create table vault_rotation_packages"));
        assertTrue(migration.contains("encrypted_vault_key text not null"));
        assertTrue(migration.contains("accepted_pending_key"));
        assertTrue(migration.contains("drop table vault_key_rotations"));
        assertFalse(migration.contains("plaintext_vault_key"));
        assertFalse(migration.contains("private_key"));
        assertFalse(migration.contains("recovery_secret"));
    }

    @Test
    void migrationPreservesLegacyMembershipAndCurrentKeyState() throws Exception {
        String database =
                "jdbc:h2:mem:collaborative_migration_"
                        + UUID.randomUUID()
                        + ";MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1";
        migrate(database, "18");
        try (Connection connection = DriverManager.getConnection(database, "sa", "");
                Statement statement = connection.createStatement()) {
            statement.executeUpdate(
                    "insert into vaults (owner_id, vault_id, encrypted_metadata, created_at, updated_at) "
                            + "values ('owner', 'vault-legacy', 'opaque-metadata', current_timestamp, current_timestamp)");
            statement.executeUpdate(
                    "insert into vault_members (vault_id, user_id, role, state, created_at, updated_at) "
                            + "values ('vault-legacy', 'invitee', 'VIEWER', 'INVITED', current_timestamp, current_timestamp)");
            statement.executeUpdate(
                    "insert into vault_key_rotations (owner_id, vault_id, vault_key_id, rotated_at) "
                            + "values ('owner', 'vault-legacy', 'key-legacy', current_timestamp)");
        }

        migrate(database, null);

        try (Connection connection = DriverManager.getConnection(database, "sa", "");
                Statement statement = connection.createStatement()) {
            assertEquals(
                    "INVITED",
                    scalar(
                            statement,
                            "select state from vault_members where vault_id = 'vault-legacy' and user_id = 'invitee'"));
            assertEquals(
                    "key-legacy",
                    scalar(
                            statement,
                            "select current_vault_key_id from vault_key_states where owner_id = 'owner' and vault_id = 'vault-legacy'"));
            assertEquals(
                    "STABLE",
                    scalar(
                            statement,
                            "select lifecycle_state from vault_key_states where owner_id = 'owner' and vault_id = 'vault-legacy'"));
            assertEquals(
                    "0",
                    scalar(
                            statement,
                            "select count(*) from information_schema.tables where table_name = 'vault_key_rotations'"));
        }
    }

    private static void migrate(@NonNull String database, String target) {
        var configuration = Flyway.configure().dataSource(database, "sa", "");
        if (target != null) {
            configuration.target(MigrationVersion.fromVersion(target));
        }
        configuration.load().migrate();
    }

    private static @NonNull String scalar(@NonNull Statement statement, @NonNull String sql)
            throws Exception {
        try (ResultSet result = statement.executeQuery(sql)) {
            assertTrue(result.next());
            return result.getString(1);
        }
    }
}
