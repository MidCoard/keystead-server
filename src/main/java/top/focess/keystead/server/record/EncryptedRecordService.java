package top.focess.keystead.server.record;

import java.time.Clock;
import java.util.List;
import java.util.Optional;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import top.focess.keystead.server.audit.AuditService;
import top.focess.keystead.server.vault.VaultAccessGuard;

@Service
class EncryptedRecordService {

    private static final int MAX_PAGE_LIMIT = 500;

    private final EncryptedRecordRepository records;
    private final VaultAccessGuard accessGuard;
    private final AuditService audit;
    private final Clock clock;

    EncryptedRecordService(
            @NonNull EncryptedRecordRepository records,
            @NonNull VaultAccessGuard accessGuard,
            @NonNull AuditService audit,
            @NonNull Clock clock) {
        this.records = records;
        this.accessGuard = accessGuard;
        this.audit = audit;
        this.clock = clock;
    }

    @Transactional
    @NonNull StoreRecordResult store(
            @NonNull String ownerId,
            @NonNull String vaultId,
            @NonNull String secretId,
            @NonNull EncryptedRecordRequest request) {
        accessGuard.requireOwnedVault(ownerId, vaultId);
        Optional<StoredEncryptedRecord> existing = records.find(ownerId, vaultId, secretId);
        records.latestRevision(ownerId, vaultId)
                .filter(record -> request.revision() <= record.revision())
                .ifPresent(
                        record ->
                                throwRevisionConflict(
                                        ownerId, vaultId, secretId, record, request.revision()));
        String encryptedProfile = request.resolvedEncryptedProfile();
        String envelope = request.resolvedEnvelope();
        StoredEncryptedRecord next =
                new StoredEncryptedRecord(
                        ownerId,
                        vaultId,
                        secretId,
                        request.revision(),
                        request.secretType(),
                        encryptedProfile,
                        encryptedProfile,
                        envelope,
                        request.deleted(),
                        clock.instant());
        StoreRecordResult result;
        if (existing.isEmpty()) {
            records.insert(next);
            result = StoreRecordResult.CREATED;
        } else {
            records.update(next);
            result = StoreRecordResult.UPDATED;
        }
        audit.recordStored(
                ownerId,
                ownerId,
                vaultId,
                secretId,
                request.revision(),
                request.secretType(),
                request.deleted());
        return result;
    }

    @Transactional
    void delete(
            @NonNull String ownerId,
            @NonNull String vaultId,
            @NonNull String secretId,
            long revision) {
        accessGuard.requireOwnedVault(ownerId, vaultId);
        StoredEncryptedRecord existing =
                records.find(ownerId, vaultId, secretId)
                        .orElseThrow(() -> new RecordNotFoundException("Record does not exist"));
        records.latestRevision(ownerId, vaultId)
                .filter(record -> revision <= record.revision())
                .ifPresent(
                        record ->
                                throwRevisionConflict(
                                        ownerId, vaultId, secretId, record, revision));
        records.update(
                new StoredEncryptedRecord(
                        ownerId,
                        vaultId,
                        secretId,
                        revision,
                        existing.secretType(),
                        "",
                        "",
                        "",
                        true,
                        clock.instant()));
        audit.recordDeleted(ownerId, ownerId, vaultId, secretId, revision);
    }

    @Transactional(readOnly = true)
    @NonNull Optional<StoredEncryptedRecord> find(
            @NonNull String ownerId, @NonNull String vaultId, @NonNull String secretId) {
        return records.find(ownerId, vaultId, secretId);
    }

    @Transactional(readOnly = true)
    @NonNull List<EncryptedRecordResponse> listSince(
            @NonNull String ownerId, @NonNull String vaultId, long sinceRevision) {
        requireNonNegativeSinceRevision(sinceRevision);
        accessGuard.requireOwnedVault(ownerId, vaultId);
        return records.listSince(ownerId, vaultId, sinceRevision).stream()
                .map(EncryptedRecordResponse::from)
                .toList();
    }

    @Transactional(readOnly = true)
    @NonNull EncryptedRecordPageResponse pageSince(
            @NonNull String ownerId, @NonNull String vaultId, long sinceRevision, int limit) {
        requireNonNegativeSinceRevision(sinceRevision);
        if (limit <= 0 || limit > MAX_PAGE_LIMIT) {
            throw new InvalidRecordRequestException("Record page limit is out of range");
        }
        accessGuard.requireOwnedVault(ownerId, vaultId);
        List<StoredEncryptedRecord> fetched =
                records.pageSince(ownerId, vaultId, sinceRevision, limit + 1);
        boolean hasMore = fetched.size() > limit;
        List<EncryptedRecordResponse> page =
                fetched.stream().limit(limit).map(EncryptedRecordResponse::from).toList();
        long highestRevision =
                page.stream()
                        .mapToLong(EncryptedRecordResponse::revision)
                        .max()
                        .orElse(sinceRevision);
        Long nextSinceRevision = hasMore ? highestRevision : null;
        return new EncryptedRecordPageResponse(
                vaultId, sinceRevision, page, highestRevision, hasMore, nextSinceRevision);
    }

    private void requireNonNegativeSinceRevision(long sinceRevision) {
        if (sinceRevision < 0) {
            throw new InvalidRecordRequestException("sinceRevision must not be negative");
        }
    }

    private void throwRevisionConflict(
            @NonNull String ownerId,
            @NonNull String vaultId,
            @NonNull String secretId,
            @NonNull StoredEncryptedRecord serverRecord,
            long rejectedRevision) {
        audit.recordRevisionConflict(
                ownerId, ownerId, vaultId, secretId, serverRecord.revision(), rejectedRevision);
        throw new RevisionConflictException(
                "Record revision must increase",
                vaultId,
                secretId,
                serverRecord.revision(),
                rejectedRevision,
                serverRecord.deleted(),
                serverRecord.updatedAt());
    }
}
