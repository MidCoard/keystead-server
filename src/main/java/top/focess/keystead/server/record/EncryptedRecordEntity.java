package top.focess.keystead.server.record;

import jakarta.persistence.Column;
import jakarta.persistence.EmbeddedId;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import java.time.Instant;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

@Entity
@Table(name = "encrypted_records")
public class EncryptedRecordEntity {

    @EmbeddedId @NonNull EncryptedRecordEntityId id = new EncryptedRecordEntityId();

    @Column(name = "revision", nullable = false)
    long revision;

    @Column(name = "secret_type", nullable = false)
    @NonNull String secretType = "";

    @Column(name = "metadata", nullable = false, columnDefinition = "text")
    @NonNull String metadata = "";

    @Column(name = "encrypted_profile", columnDefinition = "text")
    @Nullable String encryptedProfile;

    @Column(name = "envelope", nullable = false, columnDefinition = "text")
    @NonNull String envelope = "";

    @Column(name = "deleted", nullable = false)
    boolean deleted;

    @Column(name = "updated_at", nullable = false)
    @NonNull Instant updatedAt = Instant.EPOCH;

    protected EncryptedRecordEntity() {}

    private EncryptedRecordEntity(@NonNull StoredEncryptedRecord record) {
        this.id =
                new EncryptedRecordEntityId(record.ownerId(), record.vaultId(), record.secretId());
        this.revision = record.revision();
        this.secretType = record.secretType();
        this.metadata = record.metadata();
        this.encryptedProfile = record.encryptedProfile();
        this.envelope = record.envelope();
        this.deleted = record.deleted();
        this.updatedAt = record.updatedAt();
    }

    static @NonNull EncryptedRecordEntity from(@NonNull StoredEncryptedRecord record) {
        return new EncryptedRecordEntity(record);
    }

    @NonNull StoredEncryptedRecord toStored() {
        return new StoredEncryptedRecord(
                id.ownerId,
                id.vaultId,
                id.secretId,
                revision,
                secretType,
                metadata,
                encryptedProfile == null ? metadata : encryptedProfile,
                envelope,
                deleted,
                updatedAt);
    }
}
