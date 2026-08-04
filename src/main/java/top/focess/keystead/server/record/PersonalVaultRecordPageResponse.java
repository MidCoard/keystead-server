package top.focess.keystead.server.record;

import java.util.List;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

public record PersonalVaultRecordPageResponse(
        long afterSequence,
        @NonNull List<PersonalVaultRecordResponse> records,
        long highestSequence,
        boolean hasMore,
        @Nullable Long nextSequence) {

    public PersonalVaultRecordPageResponse {
        records = List.copyOf(records);
    }
}
