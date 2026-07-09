package top.focess.keystead.server.vault;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.jspecify.annotations.NonNull;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
class VaultService {

    private final VaultRepository vaults;
    private final VaultAccessGuard accessGuard;
    private final Clock clock;

    VaultService(
            @NonNull VaultRepository vaults,
            @NonNull VaultAccessGuard accessGuard,
            @NonNull Clock clock) {
        this.vaults = vaults;
        this.accessGuard = accessGuard;
        this.clock = clock;
    }

    @Transactional
    void put(@NonNull String ownerId, @NonNull String vaultId, @NonNull VaultRequest request) {
        Optional<StoredVault> existing =
                accessGuard.findOwnedVaultOrRejectTakenId(ownerId, vaultId);
        Instant now = clock.instant();
        Instant createdAt = existing.map(StoredVault::createdAt).orElse(now);
        StoredVault next =
                new StoredVault(ownerId, vaultId, request.encryptedMetadata(), createdAt, now);
        try {
            if (existing.isEmpty()) {
                vaults.insert(next);
            } else {
                vaults.update(next);
            }
        } catch (DataIntegrityViolationException e) {
            throw new VaultNotFoundException("Vault does not exist", e);
        }
    }

    @Transactional(readOnly = true)
    @NonNull List<VaultResponse> list(@NonNull String ownerId) {
        return vaults.list(ownerId).stream().map(VaultResponse::from).toList();
    }
}
