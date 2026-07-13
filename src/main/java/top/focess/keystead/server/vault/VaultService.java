package top.focess.keystead.server.vault;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validator;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.jspecify.annotations.NonNull;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
class VaultService {

    private final VaultRepository vaults;
    private final VaultMemberRepository members;
    private final VaultKeyStateRepository keyStates;
    private final VaultAccessGuard accessGuard;
    private final Clock clock;
    private final Validator validator;

    VaultService(
            @NonNull VaultRepository vaults,
            @NonNull VaultMemberRepository members,
            @NonNull VaultKeyStateRepository keyStates,
            @NonNull VaultAccessGuard accessGuard,
            @NonNull Clock clock,
            @NonNull Validator validator) {
        this.vaults = vaults;
        this.members = members;
        this.keyStates = keyStates;
        this.accessGuard = accessGuard;
        this.clock = clock;
        this.validator = validator;
    }

    @Transactional
    void put(@NonNull String ownerId, @NonNull String vaultId, @NonNull VaultRequest request) {
        Optional<StoredVault> existing =
                accessGuard.findOwnedVaultOrRejectTakenId(ownerId, vaultId);
        validate(request);
        Instant now = clock.instant();
        Instant createdAt = existing.map(StoredVault::createdAt).orElse(now);
        StoredVault next =
                new StoredVault(ownerId, vaultId, request.encryptedMetadata(), createdAt, now);
        try {
            if (existing.isEmpty()) {
                vaults.insert(next);
                members.insertOwner(vaultId, ownerId, now);
            } else {
                vaults.update(next);
            }
        } catch (DataIntegrityViolationException e) {
            throw new VaultNotFoundException("Vault does not exist", e);
        }
    }

    @Transactional(readOnly = true)
    @NonNull List<VaultMembershipResponse> list(@NonNull String userId) {
        return members.findAllForUser(userId).stream().map(this::membership).toList();
    }

    private @NonNull VaultMembershipResponse membership(@NonNull VaultMemberEntity entity) {
        StoredVaultMember member = entity.toStored();
        StoredVault vault =
                vaults.findGlobally(member.vaultId())
                        .orElseThrow(() -> new VaultNotFoundException("Vault does not exist"));
        Optional<VaultKeyStateEntity> keyState =
                keyStates.findById(new VaultEntityId(vault.ownerId(), vault.vaultId()));
        return new VaultMembershipResponse(
                vault.vaultId(),
                vault.ownerId(),
                vault.encryptedMetadata(),
                member.role(),
                member.state(),
                keyState.map(state -> state.currentVaultKeyId).orElse(null),
                keyState.map(state -> state.lifecycleState).orElse(VaultKeyLifecycleState.STABLE),
                keyState.map(state -> state.lifecycleVersion).orElse(0L));
    }

    private void validate(@NonNull VaultRequest request) {
        Set<ConstraintViolation<VaultRequest>> violations = validator.validate(request);
        if (!violations.isEmpty()) {
            throw new InvalidVaultRequestException(
                    violations.iterator().next().getPropertyPath() + " is invalid");
        }
    }
}
