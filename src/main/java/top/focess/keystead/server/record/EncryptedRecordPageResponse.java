package top.focess.keystead.server.record;

import java.util.List;
import java.util.Objects;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

record EncryptedRecordPageResponse(
        @NonNull String vaultId,
        long sinceRevision,
        @NonNull List<EncryptedRecordResponse> records,
        long highestRevision,
        boolean hasMore,
        @Nullable Long nextSinceRevision) {

    EncryptedRecordPageResponse {
        requireNotBlank(vaultId, "vaultId");
        records = List.copyOf(Objects.requireNonNull(records, "records"));
        if (sinceRevision < 0) {
            throw new IllegalArgumentException("sinceRevision must not be negative");
        }
        if (highestRevision < sinceRevision) {
            throw new IllegalArgumentException("highestRevision must not be before sinceRevision");
        }
        long lastRevision = sinceRevision;
        for (EncryptedRecordResponse record : records) {
            if (!vaultId.equals(record.vaultId())) {
                throw new IllegalArgumentException("Page row belongs to a different vault");
            }
            if (record.revision() <= lastRevision) {
                throw new IllegalArgumentException("Page row revisions must advance");
            }
            lastRevision = record.revision();
        }
        if (highestRevision != lastRevision) {
            throw new IllegalArgumentException("highestRevision must match returned rows");
        }
        if (hasMore) {
            if (nextSinceRevision == null || nextSinceRevision != highestRevision) {
                throw new IllegalArgumentException(
                        "nextSinceRevision must advance to highestRevision");
            }
            if (highestRevision <= sinceRevision) {
                throw new IllegalArgumentException(
                        "Paged cursor must advance when more rows exist");
            }
        } else if (nextSinceRevision != null) {
            throw new IllegalArgumentException(
                    "nextSinceRevision is only valid when more rows exist");
        }
    }

    private static void requireNotBlank(@NonNull String value, @NonNull String field) {
        Objects.requireNonNull(value, field);
        if (value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
    }
}
