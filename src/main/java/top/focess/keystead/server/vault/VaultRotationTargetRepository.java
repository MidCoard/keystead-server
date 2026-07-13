package top.focess.keystead.server.vault;

import org.springframework.data.jpa.repository.JpaRepository;

interface VaultRotationTargetRepository
        extends JpaRepository<VaultRotationTargetEntity, VaultRotationTargetEntity.Key> {}
