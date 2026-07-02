package top.focess.keystead.server.record;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.List;
import java.util.Optional;
import org.jspecify.annotations.NonNull;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
class EncryptedRecordRepository {

    private final JdbcTemplate jdbc;

    EncryptedRecordRepository(@NonNull JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @NonNull Optional<StoredEncryptedRecord> find(
            @NonNull String ownerId, @NonNull String vaultId, @NonNull String secretId) {
        return jdbc
                .query(
                        """
                        select owner_id, vault_id, secret_id, revision, secret_type, metadata,
                               envelope, deleted, updated_at
                          from encrypted_records
                         where owner_id = ? and vault_id = ? and secret_id = ?
                        """,
                        this::map,
                        ownerId,
                        vaultId,
                        secretId)
                .stream()
                .findFirst();
    }

    @NonNull List<StoredEncryptedRecord> listSince(
            @NonNull String ownerId, @NonNull String vaultId, long sinceRevision) {
        return jdbc.query(
                """
                select owner_id, vault_id, secret_id, revision, secret_type, metadata,
                       envelope, deleted, updated_at
                  from encrypted_records
                 where owner_id = ? and vault_id = ? and revision > ?
                 order by revision, secret_id
                """,
                this::map,
                ownerId,
                vaultId,
                sinceRevision);
    }

    void insert(@NonNull StoredEncryptedRecord record) {
        jdbc.update(
                """
                insert into encrypted_records
                    (owner_id, vault_id, secret_id, revision, secret_type, metadata, envelope,
                     deleted, updated_at)
                values (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                record.ownerId(),
                record.vaultId(),
                record.secretId(),
                record.revision(),
                record.secretType(),
                record.metadata(),
                record.envelope(),
                record.deleted(),
                Timestamp.from(record.updatedAt()));
    }

    void update(@NonNull StoredEncryptedRecord record) {
        jdbc.update(
                """
                update encrypted_records
                   set revision = ?,
                       secret_type = ?,
                       metadata = ?,
                       envelope = ?,
                       deleted = ?,
                       updated_at = ?
                 where owner_id = ? and vault_id = ? and secret_id = ?
                """,
                record.revision(),
                record.secretType(),
                record.metadata(),
                record.envelope(),
                record.deleted(),
                Timestamp.from(record.updatedAt()),
                record.ownerId(),
                record.vaultId(),
                record.secretId());
    }

    private @NonNull StoredEncryptedRecord map(@NonNull ResultSet resultSet, int row)
            throws SQLException {
        return new StoredEncryptedRecord(
                resultSet.getString("owner_id"),
                resultSet.getString("vault_id"),
                resultSet.getString("secret_id"),
                resultSet.getLong("revision"),
                resultSet.getString("secret_type"),
                resultSet.getString("metadata"),
                resultSet.getString("envelope"),
                resultSet.getBoolean("deleted"),
                resultSet.getTimestamp("updated_at").toInstant());
    }
}
