package top.focess.keystead.server.record;

import java.time.Clock;
import java.util.List;
import java.util.Optional;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import top.focess.keystead.server.vault.VaultRepository;

@Service
class EncryptedRecordService {

    private final EncryptedRecordRepository records;
    private final VaultRepository vaults;
    private final Clock clock;

    EncryptedRecordService(
            @NonNull EncryptedRecordRepository records,
            @NonNull VaultRepository vaults,
            @NonNull Clock clock) {
        this.records = records;
        this.vaults = vaults;
        this.clock = clock;
    }

    @Transactional
    @NonNull StoreRecordResult store(
            @NonNull String ownerId,
            @NonNull String vaultId,
            @NonNull String secretId,
            @NonNull EncryptedRecordRequest request) {
        requireVault(ownerId, vaultId);
        Optional<StoredEncryptedRecord> existing = records.find(ownerId, vaultId, secretId);
        StoredEncryptedRecord next =
                new StoredEncryptedRecord(
                        ownerId,
                        vaultId,
                        secretId,
                        request.revision(),
                        request.secretType(),
                        request.metadata(),
                        request.envelope(),
                        request.deleted(),
                        clock.instant());
        if (existing.isEmpty()) {
            records.insert(next);
            return StoreRecordResult.CREATED;
        }
        if (request.revision() <= existing.get().revision()) {
            throw new RevisionConflictException("Record revision must increase");
        }
        records.update(next);
        return StoreRecordResult.UPDATED;
    }

    @Transactional(readOnly = true)
    @NonNull Optional<StoredEncryptedRecord> find(
            @NonNull String ownerId, @NonNull String vaultId, @NonNull String secretId) {
        return records.find(ownerId, vaultId, secretId);
    }

    @Transactional(readOnly = true)
    @NonNull List<EncryptedRecordResponse> listSince(
            @NonNull String ownerId, @NonNull String vaultId, long sinceRevision) {
        requireVault(ownerId, vaultId);
        return records.listSince(ownerId, vaultId, sinceRevision).stream()
                .map(EncryptedRecordResponse::from)
                .toList();
    }

    private void requireVault(@NonNull String ownerId, @NonNull String vaultId) {
        if (!vaults.exists(ownerId, vaultId)) {
            throw new VaultNotFoundException("Vault does not exist");
        }
    }
}
