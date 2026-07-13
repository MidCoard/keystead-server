package top.focess.keystead.server.recovery;

import org.springframework.data.jpa.repository.JpaRepository;

interface RecoveryVaultPackageRepository
        extends JpaRepository<RecoveryVaultPackageEntity, RecoveryVaultPackageId> {}
