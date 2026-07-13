package top.focess.keystead.server.vault;

import org.springframework.data.jpa.repository.JpaRepository;

interface VaultRotationPackageRepository
        extends JpaRepository<VaultRotationPackageEntity, VaultRotationPackageEntity.Key> {}
