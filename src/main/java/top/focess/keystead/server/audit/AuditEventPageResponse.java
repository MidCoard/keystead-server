package top.focess.keystead.server.audit;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * One page of an owner's audit trail, newest-first. The cursor is the {@code (createdAt, eventId)}
 * tuple of the oldest row in the page; because {@code createdAt} is not unique, {@code eventId}
 * breaks ties so paging never skips or repeats rows that share a timestamp.
 *
 * @param events the rows in this page, newest-first.
 * @param limit the effective page size requested by the caller.
 * @param hasMore whether older rows remain beyond this page.
 * @param nextBefore the {@code createdAt} to use as the {@code before} cursor for the next page;
 *     present only when {@code hasMore} is true.
 * @param nextBeforeId the {@code eventId} to use as the {@code beforeId} cursor for the next page;
 *     present only when {@code hasMore} is true.
 */
public record AuditEventPageResponse(
        @NonNull List<AuditEventResponse> events,
        int limit,
        boolean hasMore,
        @Nullable Instant nextBefore,
        @Nullable String nextBeforeId) {

    public AuditEventPageResponse {
        events = List.copyOf(Objects.requireNonNull(events, "events"));
        if (limit <= 0) {
            throw new IllegalArgumentException("Audit page limit must be positive");
        }
        if (hasMore) {
            if (nextBefore == null || nextBeforeId == null) {
                throw new IllegalArgumentException(
                        "Audit cursor is required when more events exist");
            }
        } else if (nextBefore != null || nextBeforeId != null) {
            throw new IllegalArgumentException("Audit cursor is only valid when more events exist");
        }
    }
}
