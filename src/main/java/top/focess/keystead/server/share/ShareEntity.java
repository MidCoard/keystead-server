package top.focess.keystead.server.share;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import org.jspecify.annotations.NonNull;

@Entity
@Table(name = "shares")
public class ShareEntity {

    @Id
    @Column(name = "code", nullable = false)
    @NonNull String code = "";

    @Column(name = "owner_id", nullable = false)
    @NonNull String ownerId = "";

    @Column(name = "payload", nullable = false)
    @NonNull String payload = "";

    @Column(name = "burn_after_reading", nullable = false)
    boolean burnAfterReading = true;

    @Column(name = "expires_at", nullable = false)
    @NonNull Instant expiresAt = Instant.EPOCH;

    @Column(name = "created_at", nullable = false)
    @NonNull Instant createdAt = Instant.EPOCH;

    protected ShareEntity() {}

    private ShareEntity(@NonNull Share share) {
        code = share.code();
        ownerId = share.ownerId();
        payload = share.payload();
        burnAfterReading = share.burnAfterReading();
        expiresAt = share.expiresAt();
        createdAt = share.createdAt();
    }

    static @NonNull ShareEntity from(@NonNull Share share) {
        return new ShareEntity(share);
    }

    @NonNull Share toStored() {
        return new Share(code, ownerId, payload, burnAfterReading, expiresAt, createdAt);
    }
}
