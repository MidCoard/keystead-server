package top.focess.keystead.server.vault;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;

import jakarta.persistence.EntityManager;
import java.time.Instant;
import org.hibernate.exception.ConstraintViolationException;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

@SpringBootTest
@ActiveProfiles("test")
class CollaborativeLifecyclePersistenceTest {

    private static final Instant NOW = Instant.parse("2026-07-14T00:00:00Z");

    private final VaultRepository vaults;
    private final VaultKeyStateRepository keyStates;
    private final VaultRotationGenerationRepository generations;
    private final VaultRotationTargetRepository targets;
    private final VaultRotationPackageRepository packages;
    private final EntityManager entityManager;
    private final TransactionTemplate transactions;

    @Autowired
    CollaborativeLifecyclePersistenceTest(
            @NonNull VaultRepository vaults,
            @NonNull VaultKeyStateRepository keyStates,
            @NonNull VaultRotationGenerationRepository generations,
            @NonNull VaultRotationTargetRepository targets,
            @NonNull VaultRotationPackageRepository packages,
            @NonNull EntityManager entityManager,
            @NonNull PlatformTransactionManager transactionManager) {
        this.vaults = vaults;
        this.keyStates = keyStates;
        this.generations = generations;
        this.targets = targets;
        this.packages = packages;
        this.entityManager = entityManager;
        this.transactions = new TransactionTemplate(transactionManager);
    }

    @Test
    void repositoriesRoundTripPendingMembershipLifecycleTargetsAndOpaquePackages() {
        String suffix = Long.toUnsignedString(System.nanoTime());
        String ownerId = "owner-" + suffix;
        String vaultId = "vault-" + suffix;
        String generationId = "generation-" + suffix;
        vaults.saveAndFlush(
                VaultEntity.from(new StoredVault(ownerId, vaultId, "opaque-metadata", NOW, NOW)));

        VaultRotationGenerationEntity generation =
                generation(generationId, ownerId, vaultId, "target-key", 7L);
        generations.saveAndFlush(generation);
        VaultKeyStateEntity keyState = keyState(ownerId, vaultId, generationId, 7L);
        keyStates.saveAndFlush(keyState);
        VaultRotationTargetEntity target = deviceTarget(generationId, "target-device");
        targets.saveAndFlush(target);
        VaultRotationPackageEntity keyPackage = keyPackage(generationId, "target-device");
        packages.saveAndFlush(keyPackage);

        VaultKeyStateEntity storedState =
                keyStates.findById(new VaultEntityId(ownerId, vaultId)).orElseThrow();
        assertEquals(VaultKeyLifecycleState.ROTATING, storedState.lifecycleState);
        assertEquals(generationId, storedState.pendingGenerationId);
        assertEquals(7L, storedState.lifecycleVersion);
        assertEquals(
                VaultRotationGenerationState.OPEN,
                generations.findById(generationId).orElseThrow().state);
        assertEquals(
                VaultRotationTargetType.DEVICE,
                targets.findById(target.id()).orElseThrow().targetType);
        assertEquals(
                "opaque-vault-key-package",
                packages.findById(keyPackage.id()).orElseThrow().encryptedVaultKey);
    }

    @Test
    void databaseAllowsOnlyOnePendingGenerationPerVault() {
        String suffix = Long.toUnsignedString(System.nanoTime());
        String ownerId = "one-owner-" + suffix;
        String vaultId = "one-vault-" + suffix;
        vaults.saveAndFlush(
                VaultEntity.from(new StoredVault(ownerId, vaultId, "opaque-metadata", NOW, NOW)));
        generations.saveAndFlush(
                generation("one-generation-" + suffix, ownerId, vaultId, "key-2", 1L));

        ConstraintViolationException error =
                assertThrows(
                        ConstraintViolationException.class,
                        () ->
                                transactions.executeWithoutResult(
                                        ignored -> {
                                            entityManager.persist(
                                                    generation(
                                                            "two-generation-" + suffix,
                                                            ownerId,
                                                            vaultId,
                                                            "key-3",
                                                            1L));
                                            entityManager.flush();
                                        }));
        assertThat(error.getConstraintName())
                .containsIgnoringCase("ux_vault_rotation_pending_generation");
    }

    @Test
    void databaseRejectsNonPositiveLifecycleVersionAndGeneration() {
        String suffix = Long.toUnsignedString(System.nanoTime());
        String ownerId = "positive-owner-" + suffix;
        String vaultId = "positive-vault-" + suffix;
        vaults.saveAndFlush(
                VaultEntity.from(new StoredVault(ownerId, vaultId, "opaque-metadata", NOW, NOW)));

        assertConstraint(
                "ck_vault_key_state_lifecycle_version", keyState(ownerId, vaultId, null, 0L));
        assertConstraint(
                "ck_vault_rotation_generation_version",
                generation("zero-generation-" + suffix, ownerId, vaultId, "key-2", 0L));
    }

    @Test
    void databaseRejectsMixedTargetIdentityAndPackageWithoutTarget() {
        String suffix = Long.toUnsignedString(System.nanoTime());
        String ownerId = "target-owner-" + suffix;
        String vaultId = "target-vault-" + suffix;
        String generationId = "target-generation-" + suffix;
        vaults.saveAndFlush(
                VaultEntity.from(new StoredVault(ownerId, vaultId, "opaque-metadata", NOW, NOW)));
        generations.saveAndFlush(generation(generationId, ownerId, vaultId, "key-2", 1L));

        VaultRotationTargetEntity mixed = deviceTarget(generationId, "mixed-target");
        mixed.principalId = "automation-must-be-null";
        assertConstraint("ck_vault_rotation_target_identity", mixed);
        assertConstraint(
                "vault_rotation_package_target", keyPackage(generationId, "missing-target"));
    }

    private void assertConstraint(@NonNull String name, @NonNull Object entity) {
        ConstraintViolationException error =
                assertThrows(
                        ConstraintViolationException.class,
                        () ->
                                transactions.executeWithoutResult(
                                        ignored -> {
                                            entityManager.persist(entity);
                                            entityManager.flush();
                                        }));
        assertThat(error.getConstraintName()).containsIgnoringCase(name);
    }

    private static @NonNull VaultKeyStateEntity keyState(
            @NonNull String ownerId,
            @NonNull String vaultId,
            String pendingGenerationId,
            long lifecycleVersion) {
        VaultKeyStateEntity state = new VaultKeyStateEntity();
        state.id = new VaultEntityId(ownerId, vaultId);
        state.currentVaultKeyId = "key-1";
        state.lifecycleState =
                pendingGenerationId == null
                        ? VaultKeyLifecycleState.STABLE
                        : VaultKeyLifecycleState.ROTATING;
        state.lifecycleVersion = lifecycleVersion;
        state.pendingGenerationId = pendingGenerationId;
        state.updatedAt = NOW;
        return state;
    }

    private static @NonNull VaultRotationGenerationEntity generation(
            @NonNull String generationId,
            @NonNull String ownerId,
            @NonNull String vaultId,
            @NonNull String targetKeyId,
            long lifecycleVersion) {
        VaultRotationGenerationEntity generation = new VaultRotationGenerationEntity();
        generation.generationId = generationId;
        generation.ownerId = ownerId;
        generation.vaultId = vaultId;
        generation.sourceKeyId = "key-1";
        generation.targetKeyId = targetKeyId;
        generation.state = VaultRotationGenerationState.OPEN;
        generation.initiatorId = ownerId;
        generation.lifecycleVersion = lifecycleVersion;
        generation.pendingMarker = "P";
        generation.createdAt = NOW;
        generation.updatedAt = NOW;
        return generation;
    }

    private static @NonNull VaultRotationTargetEntity deviceTarget(
            @NonNull String generationId, @NonNull String targetId) {
        VaultRotationTargetEntity target = new VaultRotationTargetEntity();
        target.generationId = generationId;
        target.targetId = targetId;
        target.targetType = VaultRotationTargetType.DEVICE;
        target.recipientId = "recipient";
        target.deviceId = "device";
        target.keyAlgorithm = "TINK_ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM";
        target.publicKey = "public-wrapping-key";
        target.required = true;
        return target;
    }

    private static @NonNull VaultRotationPackageEntity keyPackage(
            @NonNull String generationId, @NonNull String targetId) {
        VaultRotationPackageEntity keyPackage = new VaultRotationPackageEntity();
        keyPackage.generationId = generationId;
        keyPackage.targetId = targetId;
        keyPackage.keyAlgorithm = "TINK_ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM";
        keyPackage.encryptedVaultKey = "opaque-vault-key-package";
        keyPackage.createdAt = NOW;
        return keyPackage;
    }
}
