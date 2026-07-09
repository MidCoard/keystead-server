package top.focess.keystead.server.vault;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validator;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import top.focess.keystead.server.audit.AuditService;
import top.focess.keystead.server.crypto.ServerCryptoAlgorithmRegistry;
import top.focess.keystead.server.crypto.UnsupportedCryptoAlgorithmException;

@Service
class VaultKeyPackageService {

    private final VaultAccessGuard accessGuard;
    private final AuditService audit;
    private final VaultKeyPackageRepository keyPackages;
    private final Clock clock;
    private final Validator validator;

    VaultKeyPackageService(
            @NonNull VaultAccessGuard accessGuard,
            @NonNull AuditService audit,
            @NonNull VaultKeyPackageRepository keyPackages,
            @NonNull Clock clock,
            @NonNull Validator validator) {
        this.accessGuard = accessGuard;
        this.audit = audit;
        this.keyPackages = keyPackages;
        this.clock = clock;
        this.validator = validator;
    }

    @Transactional
    void put(
            @NonNull String ownerId,
            @NonNull String vaultId,
            @NonNull String deviceId,
            @NonNull VaultKeyPackageRequest request) {
        requireVaultAndDevice(ownerId, vaultId, deviceId);
        validate(request);
        if (!ServerCryptoAlgorithmRegistry.isApprovedVaultKeyPackageAlgorithm(
                request.keyAlgorithm())) {
            throw new UnsupportedCryptoAlgorithmException(
                    "Unsupported vault key package algorithm");
        }
        Instant now = clock.instant();
        StoredVaultKeyPackage existing = keyPackages.find(ownerId, vaultId, deviceId).orElse(null);
        Instant createdAt = existing == null ? now : existing.createdAt();
        StoredVaultKeyPackage next =
                new StoredVaultKeyPackage(
                        ownerId,
                        vaultId,
                        deviceId,
                        request.keyAlgorithm(),
                        request.encryptedVaultKey(),
                        createdAt,
                        now);
        if (existing == null) {
            keyPackages.insert(next);
        } else {
            keyPackages.update(next);
        }
        audit.keyPackageStored(ownerId, ownerId, vaultId, deviceId, request.keyAlgorithm());
    }

    @Transactional(readOnly = true)
    @NonNull List<VaultKeyPackageResponse> list(@NonNull String ownerId, @NonNull String vaultId) {
        accessGuard.requireOwnedVault(ownerId, vaultId);
        return keyPackages.list(ownerId, vaultId).stream()
                .map(VaultKeyPackageResponse::from)
                .toList();
    }

    private void requireVaultAndDevice(
            @NonNull String ownerId, @NonNull String vaultId, @NonNull String deviceId) {
        accessGuard.requireOwnedVault(ownerId, vaultId);
        if (!keyPackages.verifiedDeviceExists(ownerId, deviceId)) {
            throw new VaultKeyPackageNotFoundException("Device does not exist");
        }
    }

    private void validate(@NonNull VaultKeyPackageRequest request) {
        Set<ConstraintViolation<VaultKeyPackageRequest>> violations = validator.validate(request);
        if (!violations.isEmpty()) {
            throw new InvalidVaultKeyPackageRequestException(
                    violations.iterator().next().getPropertyPath() + " is invalid");
        }
    }
}
