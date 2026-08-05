package top.focess.keystead.server.record;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import org.jspecify.annotations.NonNull;

@Entity
@Table(name = "vault_record_events")
class VaultRecordEventEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "server_sequence", nullable = false)
    long serverSequence;

    @Column(name = "owner_id", nullable = false)
    @NonNull String ownerId = "";

    @Column(name = "event_id", nullable = false, length = 128)
    @NonNull String eventId = "";

    @Column(name = "fingerprint", nullable = false)
    @NonNull String fingerprint = "";

    @Column(name = "secret_id", nullable = false)
    @NonNull String secretId = "";

    @Column(name = "local_revision", nullable = false)
    long revision;

    @Column(name = "secret_type", nullable = false, length = 64)
    @NonNull String secretType = "";

    @Column(name = "encrypted_profile", nullable = false, columnDefinition = "text")
    @NonNull String encryptedProfile = "";

    @Column(name = "envelope", nullable = false, columnDefinition = "text")
    @NonNull String envelope = "";

    @Column(name = "content_key", nullable = false, length = 128)
    @NonNull String contentKey = "";

    @Column(name = "deleted", nullable = false)
    boolean deleted;

    @Column(name = "created_at", nullable = false)
    @NonNull Instant createdAt = Instant.EPOCH;
}
