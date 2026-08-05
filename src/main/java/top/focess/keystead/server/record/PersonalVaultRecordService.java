package top.focess.keystead.server.record;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validator;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import org.jspecify.annotations.NonNull;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import top.focess.keystead.server.audit.AuditService;
import top.focess.keystead.service.EncryptedSyncRecord;
import top.focess.keystead.service.SyncRecordEventId;

@Service
class PersonalVaultRecordService {

    private static final int MAX_PAGE_LIMIT = 500;

    private final PersonalVaultRepository vaults;
    private final VaultRecordEventRepository events;
    private final Validator validator;
    private final Clock clock;
    private final AuditService audit;

    PersonalVaultRecordService(
            @NonNull PersonalVaultRepository vaults,
            @NonNull VaultRecordEventRepository events,
            @NonNull Validator validator,
            @NonNull Clock clock,
            @NonNull AuditService audit) {
        this.vaults = vaults;
        this.events = events;
        this.validator = validator;
        this.clock = clock;
        this.audit = audit;
    }

    @Transactional
    @NonNull PersonalVaultRecordResponse append(
            @NonNull String ownerId, @NonNull PersonalVaultRecordRequest request) {
        validate(request);
        request.validateShape();
        validateEventId(request);
        Instant now = clock.instant();
        PersonalVaultEntity vault = vaults.findById(ownerId).orElse(null);
        if (vault == null) {
            vaults.save(new PersonalVaultEntity(ownerId, request.fingerprint(), now, now));
        } else if (!vault.fingerprint.equals(request.fingerprint())) {
            throw new PersonalVaultFingerprintConflictException(
                    vault.fingerprint, request.fingerprint());
        }
        VaultRecordEventEntity existing =
                events.findByOwnerIdAndEventId(ownerId, request.eventId()).orElse(null);
        if (existing != null) {
            return PersonalVaultRecordResponse.from(existing);
        }
        VaultRecordEventEntity entity = new VaultRecordEventEntity();
        entity.ownerId = ownerId;
        entity.eventId = request.eventId();
        entity.fingerprint = request.fingerprint();
        entity.secretId = request.secretId();
        entity.revision = request.revision();
        entity.secretType = request.secretType();
        entity.encryptedProfile = request.encryptedProfile();
        entity.envelope = request.envelope();
        entity.contentKey = request.contentKey();
        entity.deleted = request.deleted();
        entity.createdAt = now;
        PersonalVaultRecordResponse stored =
                PersonalVaultRecordResponse.from(events.saveAndFlush(entity));
        if (request.deleted()) {
            audit.recordDeleted(
                    ownerId, request.fingerprint(), request.secretId(), request.revision());
        } else {
            audit.recordStored(
                    ownerId,
                    request.fingerprint(),
                    request.secretId(),
                    request.revision(),
                    request.secretType());
        }
        return stored;
    }

    @Transactional(readOnly = true)
    @NonNull PersonalVaultRecordPageResponse page(
            @NonNull String ownerId, long afterSequence, int limit) {
        if (afterSequence < 0 || limit <= 0 || limit > MAX_PAGE_LIMIT) {
            throw new InvalidPersonalVaultRecordException("Record page cursor is invalid");
        }
        List<VaultRecordEventEntity> fetched =
                events.pageAfter(ownerId, afterSequence, Pageable.ofSize(limit + 1));
        boolean hasMore = fetched.size() > limit;
        List<PersonalVaultRecordResponse> page =
                fetched.stream().limit(limit).map(PersonalVaultRecordResponse::from).toList();
        long highest =
                page.stream()
                        .mapToLong(PersonalVaultRecordResponse::serverSequence)
                        .max()
                        .orElse(afterSequence);
        return new PersonalVaultRecordPageResponse(
                afterSequence, page, highest, hasMore, hasMore ? highest : null);
    }

    @Transactional
    @NonNull PersonalVaultRecordDeletionResponse deleteRecordHistory(
            @NonNull String ownerId, @NonNull String secretId) {
        if (secretId.isBlank() || secretId.length() > 256) {
            throw new InvalidPersonalVaultRecordException("Secret id is invalid");
        }
        VaultRecordEventEntity latest =
                events.findFirstByOwnerIdAndSecretIdOrderByServerSequenceDesc(ownerId, secretId)
                        .orElse(null);
        long deletedEvents = events.deleteByOwnerIdAndSecretId(ownerId, secretId);
        if (latest != null && deletedEvents > 0) {
            audit.recordPurged(ownerId, latest.fingerprint, secretId, deletedEvents);
        }
        events.flush();
        if (deletedEvents > 0 && !events.existsByOwnerId(ownerId)) {
            vaults.deleteById(ownerId);
        }
        return new PersonalVaultRecordDeletionResponse(secretId, deletedEvents);
    }

    private <T> void validate(@NonNull T request) {
        Set<ConstraintViolation<T>> violations = validator.validate(request);
        if (!violations.isEmpty()) {
            throw new InvalidPersonalVaultRecordException("Encrypted record event is invalid");
        }
    }

    private void validateEventId(@NonNull PersonalVaultRecordRequest request) {
        EncryptedSyncRecord record =
                new EncryptedSyncRecord(
                        request.fingerprint(),
                        request.secretId(),
                        request.revision(),
                        request.secretType(),
                        request.encryptedProfile(),
                        request.envelope(),
                        request.deleted(),
                        request.contentKey());
        if (!SyncRecordEventId.of(record).equals(request.eventId())) {
            throw new InvalidPersonalVaultRecordException(
                    "Record event id does not match its encrypted content");
        }
    }
}
