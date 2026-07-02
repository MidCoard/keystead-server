package top.focess.keystead.server.vault;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
class VaultService {

    private final VaultRepository vaults;
    private final Clock clock;

    VaultService(@NonNull VaultRepository vaults, @NonNull Clock clock) {
        this.vaults = vaults;
        this.clock = clock;
    }

    @Transactional
    void put(@NonNull String ownerId, @NonNull String vaultId, @NonNull VaultRequest request) {
        Instant now = clock.instant();
        Instant createdAt = vaults.find(ownerId, vaultId).map(StoredVault::createdAt).orElse(now);
        vaults.upsert(
                new StoredVault(ownerId, vaultId, request.encryptedMetadata(), createdAt, now));
    }

    @Transactional(readOnly = true)
    @NonNull List<VaultResponse> list(@NonNull String ownerId) {
        return vaults.list(ownerId).stream().map(VaultResponse::from).toList();
    }
}
