package top.focess.keystead.server.vault;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.List;
import java.util.Optional;
import org.jspecify.annotations.NonNull;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
public class VaultRepository {

    private final JdbcTemplate jdbc;

    VaultRepository(@NonNull JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @NonNull Optional<StoredVault> find(@NonNull String ownerId, @NonNull String vaultId) {
        return jdbc
                .query(
                        """
                        select owner_id, vault_id, encrypted_metadata, created_at, updated_at
                          from vaults
                         where owner_id = ? and vault_id = ?
                        """,
                        this::map,
                        ownerId,
                        vaultId)
                .stream()
                .findFirst();
    }

    public boolean exists(@NonNull String ownerId, @NonNull String vaultId) {
        Integer count =
                jdbc.queryForObject(
                        "select count(*) from vaults where owner_id = ? and vault_id = ?",
                        Integer.class,
                        ownerId,
                        vaultId);
        return count != null && count > 0;
    }

    @NonNull List<StoredVault> list(@NonNull String ownerId) {
        return jdbc.query(
                """
                select owner_id, vault_id, encrypted_metadata, created_at, updated_at
                  from vaults
                 where owner_id = ?
                 order by vault_id
                """,
                this::map,
                ownerId);
    }

    void upsert(@NonNull StoredVault vault) {
        int updated =
                jdbc.update(
                        """
                        update vaults
                           set encrypted_metadata = ?, updated_at = ?
                         where owner_id = ? and vault_id = ?
                        """,
                        vault.encryptedMetadata(),
                        Timestamp.from(vault.updatedAt()),
                        vault.ownerId(),
                        vault.vaultId());
        if (updated > 0) {
            return;
        }
        jdbc.update(
                """
                insert into vaults (owner_id, vault_id, encrypted_metadata, created_at, updated_at)
                values (?, ?, ?, ?, ?)
                """,
                vault.ownerId(),
                vault.vaultId(),
                vault.encryptedMetadata(),
                Timestamp.from(vault.createdAt()),
                Timestamp.from(vault.updatedAt()));
    }

    private @NonNull StoredVault map(@NonNull ResultSet resultSet, int row) throws SQLException {
        return new StoredVault(
                resultSet.getString("owner_id"),
                resultSet.getString("vault_id"),
                resultSet.getString("encrypted_metadata"),
                resultSet.getTimestamp("created_at").toInstant(),
                resultSet.getTimestamp("updated_at").toInstant());
    }
}
