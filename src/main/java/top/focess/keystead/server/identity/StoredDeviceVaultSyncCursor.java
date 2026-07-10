package top.focess.keystead.server.identity;

import java.time.Instant;
import java.util.Objects;
import org.jspecify.annotations.NonNull;

record StoredDeviceVaultSyncCursor(
        @NonNull String ownerId,
        @NonNull String vaultId,
        @NonNull String deviceId,
        long pulledRevision,
        @NonNull Instant updatedAt) {

    StoredDeviceVaultSyncCursor {
        requireNotBlank(ownerId, "ownerId");
        requireNotBlank(vaultId, "vaultId");
        requireNotBlank(deviceId, "deviceId");
        Objects.requireNonNull(updatedAt, "updatedAt");
        if (pulledRevision < 0) {
            throw new IllegalArgumentException("pulledRevision must not be negative");
        }
    }

    private static void requireNotBlank(@NonNull String value, @NonNull String field) {
        Objects.requireNonNull(value, field);
        if (value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
    }
}
