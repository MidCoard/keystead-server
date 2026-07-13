package top.focess.keystead.server.vault;

import java.util.List;
import java.util.Optional;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import top.focess.keystead.server.crypto.ServerCryptoAlgorithmRegistry;

interface VaultKeyPackageRepository
        extends JpaRepository<VaultKeyPackageEntity, VaultKeyPackageEntityId>,
                VaultKeyPackageRepositoryWrites {

    default @NonNull Optional<StoredVaultKeyPackage> find(
            @NonNull String ownerId, @NonNull String vaultId, @NonNull String deviceId) {
        return find(ownerId, vaultId, ownerId, deviceId);
    }

    default @NonNull Optional<StoredVaultKeyPackage> find(
            @NonNull String ownerId,
            @NonNull String vaultId,
            @NonNull String recipientId,
            @NonNull String deviceId) {
        return findById(new VaultKeyPackageEntityId(ownerId, vaultId, recipientId, deviceId))
                .map(VaultKeyPackageEntity::toStored);
    }

    @Query(
            """
            select count(d)
              from DeviceEntity d
             where d.id.ownerId = :ownerId
               and d.id.deviceId = :deviceId
               and d.verifiedAt is not null
               and d.revokedAt is null
               and d.wrappingKeyAlgorithm is not null
               and d.wrappingPublicKey is not null
               and d.wrappingKeyAlgorithm in :approvedWrappingKeyAlgorithms
            """)
    long countVerifiedDevice(
            @Param("ownerId") @NonNull String ownerId,
            @Param("deviceId") @NonNull String deviceId,
            @Param("approvedWrappingKeyAlgorithms")
                    @NonNull List<String> approvedWrappingKeyAlgorithms);

    default boolean verifiedDeviceExists(@NonNull String ownerId, @NonNull String deviceId) {
        return countVerifiedDevice(
                        ownerId,
                        deviceId,
                        ServerCryptoAlgorithmRegistry.approvedDeviceWrappingPublicKeyAlgorithms())
                > 0;
    }

    @Query(
            """
            select k
              from VaultKeyPackageEntity k
              join DeviceEntity d
                on d.id.ownerId = k.id.recipientId
               and d.id.deviceId = k.id.deviceId
             where k.id.ownerId = :ownerId and k.id.vaultId = :vaultId
               and d.verifiedAt is not null
               and d.revokedAt is null
               and d.wrappingKeyAlgorithm is not null
               and d.wrappingPublicKey is not null
               and d.wrappingKeyAlgorithm in :approvedWrappingKeyAlgorithms
             order by k.id.deviceId
            """)
    @NonNull List<VaultKeyPackageEntity> listEntities(
            @Param("ownerId") @NonNull String ownerId,
            @Param("vaultId") @NonNull String vaultId,
            @Param("approvedWrappingKeyAlgorithms")
                    @NonNull List<String> approvedWrappingKeyAlgorithms);

    default @NonNull List<StoredVaultKeyPackage> list(
            @NonNull String ownerId, @NonNull String vaultId) {
        return listEntities(
                        ownerId,
                        vaultId,
                        ServerCryptoAlgorithmRegistry.approvedDeviceWrappingPublicKeyAlgorithms())
                .stream()
                .map(VaultKeyPackageEntity::toStored)
                .toList();
    }

    @Query(
            """
            select new top.focess.keystead.server.vault.VaultPackageRecipientDeviceResponse(
                m.id.userId,
                m.role,
                m.state,
                d.id.deviceId,
                d.wrappingKeyAlgorithm,
                d.wrappingPublicKey,
                case
                    when :currentVaultKeyId is not null
                     and k.vaultKeyId = :currentVaultKeyId then true
                    else false
                end)
              from VaultMemberEntity m
              join DeviceEntity d on d.id.ownerId = m.id.userId
              left join VaultKeyPackageEntity k
                on k.id.ownerId = :ownerId
               and k.id.vaultId = :vaultId
               and k.id.recipientId = m.id.userId
               and k.id.deviceId = d.id.deviceId
             where m.id.vaultId = :vaultId
               and m.state in (
                   top.focess.keystead.server.vault.VaultMemberState.ACCEPTED_PENDING_KEY,
                   top.focess.keystead.server.vault.VaultMemberState.ACTIVE)
               and d.verifiedAt is not null
               and d.revokedAt is null
               and d.wrappingKeyAlgorithm is not null
               and d.wrappingPublicKey is not null
               and d.wrappingKeyAlgorithm in :approvedWrappingKeyAlgorithms
             order by m.id.userId, d.id.deviceId
            """)
    @NonNull List<VaultPackageRecipientDeviceResponse> listRecipientDevices(
            @Param("ownerId") @NonNull String ownerId,
            @Param("vaultId") @NonNull String vaultId,
            @Param("currentVaultKeyId") @Nullable String currentVaultKeyId,
            @Param("approvedWrappingKeyAlgorithms")
                    @NonNull List<String> approvedWrappingKeyAlgorithms);

    default @NonNull List<VaultPackageRecipientDeviceResponse> listRecipientDevices(
            @NonNull String ownerId, @NonNull String vaultId, @Nullable String currentVaultKeyId) {
        return listRecipientDevices(
                ownerId,
                vaultId,
                currentVaultKeyId,
                ServerCryptoAlgorithmRegistry.approvedDeviceWrappingPublicKeyAlgorithms());
    }

    @Query(
            """
            select count(k) from VaultKeyPackageEntity k
              join VaultKeyStateEntity s
                on s.id.ownerId = k.id.ownerId
               and s.id.vaultId = k.id.vaultId
               and s.currentVaultKeyId = k.vaultKeyId
             where k.id.ownerId = :ownerId
               and k.id.vaultId = :vaultId
               and k.id.recipientId = :recipientId
            """)
    long countCurrentForRecipient(
            @Param("ownerId") @NonNull String ownerId,
            @Param("vaultId") @NonNull String vaultId,
            @Param("recipientId") @NonNull String recipientId);

    @Query(
            """
            select k from VaultKeyPackageEntity k
              join VaultKeyStateEntity s
                on s.id.ownerId = k.id.ownerId
               and s.id.vaultId = k.id.vaultId
               and s.currentVaultKeyId = k.vaultKeyId
             where k.id.recipientId = :recipientId
               and k.id.deviceId = :deviceId
            """)
    @NonNull List<VaultKeyPackageEntity> listCurrentForDevice(
            @Param("recipientId") @NonNull String recipientId,
            @Param("deviceId") @NonNull String deviceId);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query(
            """
            delete from VaultKeyPackageEntity k
             where k.id.ownerId = :ownerId
               and k.id.vaultId = :vaultId
               and k.id.recipientId = :recipientId
            """)
    int deleteForRecipient(
            @Param("ownerId") @NonNull String ownerId,
            @Param("vaultId") @NonNull String vaultId,
            @Param("recipientId") @NonNull String recipientId);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query(
            """
            delete from VaultKeyPackageEntity k
             where k.id.recipientId = :recipientId
               and k.id.deviceId = :deviceId
            """)
    int deleteForDevice(
            @Param("recipientId") @NonNull String recipientId,
            @Param("deviceId") @NonNull String deviceId);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query(
            """
            delete from VaultKeyPackageEntity k
             where k.id.ownerId = :ownerId
               and k.id.vaultId = :vaultId
            """)
    int deleteForVault(
            @Param("ownerId") @NonNull String ownerId, @Param("vaultId") @NonNull String vaultId);
}
