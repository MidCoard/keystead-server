package top.focess.keystead.server.record;

import java.time.Clock;
import java.util.List;
import java.util.Optional;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import top.focess.keystead.server.vault.VaultAccessGuard;

@Service
class EncryptedRecordService {

    private final EncryptedRecordRepository records;
    private final VaultAccessGuard accessGuard;
    private final Clock clock;

    EncryptedRecordService(
            @NonNull EncryptedRecordRepository records,
            @NonNull VaultAccessGuard accessGuard,
            @NonNull Clock clock) {
        this.records = records;
        this.accessGuard = accessGuard;
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
        StoredEncryptedRecord next =
                new StoredEncryptedRecord(
                        ownerId,
                        vaultId,
                        secretId,
                        request.revision(),
                        request.secretType(),
                        request.resolvedEncryptedProfile(),
                        request.resolvedEncryptedProfile(),
                        request.envelope(),
                        request.deleted(),
                        clock.instant());
        if (existing.isEmpty()) {
            records.insert(next);
            return StoreRecordResult.CREATED;
        }
        if (request.revision() <= existing.get().revision()) {
            throw new RevisionConflictException(
                    "Record revision must increase", existing.get().revision(), request.revision());
        }
        records.update(next);
        return StoreRecordResult.UPDATED;
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
        if (revision <= existing.revision()) {
            throw new RevisionConflictException(
                    "Record revision must increase", existing.revision(), revision);
        }
        records.update(
                new StoredEncryptedRecord(
                        ownerId,
                        vaultId,
                        secretId,
                        revision,
                        existing.secretType(),
                        existing.metadata(),
                        existing.encryptedProfile(),
                        "",
                        true,
                        clock.instant()));
    }

    @Transactional(readOnly = true)
    @NonNull Optional<StoredEncryptedRecord> find(
            @NonNull String ownerId, @NonNull String vaultId, @NonNull String secretId) {
        return records.find(ownerId, vaultId, secretId);
    }

    @Transactional(readOnly = true)
    @NonNull List<EncryptedRecordResponse> listSince(
            @NonNull String ownerId, @NonNull String vaultId, long sinceRevision) {
        accessGuard.requireOwnedVault(ownerId, vaultId);
        return records.listSince(ownerId, vaultId, sinceRevision).stream()
                .map(EncryptedRecordResponse::from)
                .toList();
    }
}
