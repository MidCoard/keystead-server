package top.focess.keystead.server.record;

import java.util.List;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

record EncryptedRecordPageResponse(
        @NonNull String vaultId,
        long sinceRevision,
        @NonNull List<EncryptedRecordResponse> records,
        long highestRevision,
        boolean hasMore,
        @Nullable Long nextSinceRevision) {}
