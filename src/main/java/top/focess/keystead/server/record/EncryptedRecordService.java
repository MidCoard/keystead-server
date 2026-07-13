package top.focess.keystead.server.record;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validator;
import java.time.Clock;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.jspecify.annotations.NonNull;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import top.focess.keystead.server.audit.AuditService;
import top.focess.keystead.server.vault.VaultAccessGuard;

@Service
public class EncryptedRecordService {

    private static final int MAX_PAGE_LIMIT = 500;

    private final EncryptedRecordRepository records;
    private final VaultAccessGuard accessGuard;
    private final AuditService audit;
    private final Clock clock;
    private final Validator validator;

    EncryptedRecordService(
            @NonNull EncryptedRecordRepository records,
            @NonNull VaultAccessGuard accessGuard,
            @NonNull AuditService audit,
            @NonNull Clock clock,
            @NonNull Validator validator) {
        this.records = records;
        this.accessGuard = accessGuard;
        this.audit = audit;
        this.clock = clock;
        this.validator = validator;
    }

    @Transactional
    @NonNull StoreRecordResult store(
            @NonNull String ownerId,
            @NonNull String vaultId,
            @NonNull String secretId,
            @NonNull EncryptedRecordRequest request) {
        String vaultOwnerId = accessGuard.requireActiveMemberAndResolveOwner(ownerId, vaultId);
        accessGuard.requireWritableMember(ownerId, vaultId);
        accessGuard.requireStableForWrite(vaultOwnerId, vaultId);
        validate(request);
        request.validateShape();
        Optional<StoredEncryptedRecord> existing = records.find(vaultOwnerId, vaultId, secretId);
        records.latestRevision(vaultOwnerId, vaultId)
                .filter(record -> request.revision() <= record.revision())
                .ifPresent(
                        record ->
                                throwRevisionConflict(
                                        vaultOwnerId,
                                        vaultId,
                                        secretId,
                                        record,
                                        request.revision()));
        String encryptedProfile = request.resolvedEncryptedProfile();
        String envelope = request.resolvedEnvelope();
        StoredEncryptedRecord next =
                newRecord(
                        vaultOwnerId,
                        vaultId,
                        secretId,
                        request.revision(),
                        request.secretType(),
                        "",
                        encryptedProfile,
                        envelope,
                        request.deleted());
        StoreRecordResult result;
        try {
            if (existing.isEmpty()) {
                records.insert(next);
                result = StoreRecordResult.CREATED;
            } else {
                records.update(next);
                result = StoreRecordResult.UPDATED;
            }
        } catch (DataIntegrityViolationException e) {
            throwRevisionConflictFromConstraint(
                    vaultOwnerId, vaultId, secretId, request.revision(), e);
            throw e;
        }
        audit.recordStored(
                vaultOwnerId,
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
        requirePositiveRevision(revision);
        String vaultOwnerId = accessGuard.requireActiveMemberAndResolveOwner(ownerId, vaultId);
        accessGuard.requireWritableMember(ownerId, vaultId);
        accessGuard.requireStableForWrite(vaultOwnerId, vaultId);
        StoredEncryptedRecord existing =
                records.find(vaultOwnerId, vaultId, secretId)
                        .orElseThrow(() -> new RecordNotFoundException("Record does not exist"));
        records.latestRevision(vaultOwnerId, vaultId)
                .filter(record -> revision <= record.revision())
                .ifPresent(
                        record ->
                                throwRevisionConflict(
                                        vaultOwnerId, vaultId, secretId, record, revision));
        try {
            records.update(
                    newRecord(
                            vaultOwnerId,
                            vaultId,
                            secretId,
                            revision,
                            existing.secretType(),
                            "",
                            "",
                            "",
                            true));
        } catch (DataIntegrityViolationException e) {
            throwRevisionConflictFromConstraint(vaultOwnerId, vaultId, secretId, revision, e);
            throw e;
        }
        audit.recordDeleted(vaultOwnerId, ownerId, vaultId, secretId, revision);
    }

    private void requirePositiveRevision(long revision) {
        if (revision <= 0) {
            throw new InvalidRecordRequestException("revision must be positive");
        }
    }

    private void validate(@NonNull EncryptedRecordRequest request) {
        Set<ConstraintViolation<EncryptedRecordRequest>> violations = validator.validate(request);
        if (!violations.isEmpty()) {
            throw new InvalidRecordRequestException(
                    violations.iterator().next().getPropertyPath() + " is invalid");
        }
    }

    private @NonNull StoredEncryptedRecord newRecord(
            @NonNull String ownerId,
            @NonNull String vaultId,
            @NonNull String secretId,
            long revision,
            @NonNull String secretType,
            @NonNull String metadata,
            @NonNull String encryptedProfile,
            @NonNull String envelope,
            boolean deleted) {
        try {
            return new StoredEncryptedRecord(
                    ownerId,
                    vaultId,
                    secretId,
                    revision,
                    secretType,
                    metadata,
                    encryptedProfile,
                    envelope,
                    deleted,
                    clock.instant());
        } catch (IllegalArgumentException e) {
            throw new InvalidRecordRequestException(e.getMessage());
        }
    }

    @Transactional(readOnly = true)
    @NonNull Optional<StoredEncryptedRecord> find(
            @NonNull String ownerId, @NonNull String vaultId, @NonNull String secretId) {
        return records.find(
                accessGuard.requireActiveMemberAndResolveOwner(ownerId, vaultId),
                vaultId,
                secretId);
    }

    @Transactional(readOnly = true)
    @NonNull List<EncryptedRecordResponse> listSince(
            @NonNull String ownerId, @NonNull String vaultId, long sinceRevision) {
        requireNonNegativeSinceRevision(sinceRevision);
        return records
                .listSince(
                        accessGuard.requireActiveMemberAndResolveOwner(ownerId, vaultId),
                        vaultId,
                        sinceRevision)
                .stream()
                .map(EncryptedRecordResponse::from)
                .toList();
    }

    @Transactional(readOnly = true)
    public @NonNull List<EncryptedRecordResponse> listForAutomation(
            @NonNull String ownerId, @NonNull String vaultId, long sinceRevision) {
        requireNonNegativeSinceRevision(sinceRevision);
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
        String vaultOwnerId = accessGuard.requireActiveMemberAndResolveOwner(ownerId, vaultId);
        List<StoredEncryptedRecord> fetched =
                records.pageSince(vaultOwnerId, vaultId, sinceRevision, limit + 1);
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

    @Transactional(readOnly = true)
    public @NonNull EncryptedRecordPageResponse pageForAutomation(
            @NonNull String ownerId, @NonNull String vaultId, long sinceRevision, int limit) {
        requireNonNegativeSinceRevision(sinceRevision);
        if (limit <= 0 || limit > MAX_PAGE_LIMIT) {
            throw new InvalidRecordRequestException("Record page limit is out of range");
        }
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

    private void throwRevisionConflictFromConstraint(
            @NonNull String ownerId,
            @NonNull String vaultId,
            @NonNull String secretId,
            long rejectedRevision,
            @NonNull DataIntegrityViolationException cause) {
        StoredEncryptedRecord serverRecord =
                records.latestRevision(ownerId, vaultId)
                        .orElseThrow(
                                () ->
                                        new InvalidRecordRequestException(
                                                "Record revision could not be checked"));
        audit.recordRevisionConflict(
                ownerId, ownerId, vaultId, secretId, serverRecord.revision(), rejectedRevision);
        throw new RevisionConflictException(
                "Record revision must increase",
                vaultId,
                secretId,
                serverRecord.revision(),
                rejectedRevision,
                serverRecord.deleted(),
                serverRecord.updatedAt(),
                cause);
    }
}
