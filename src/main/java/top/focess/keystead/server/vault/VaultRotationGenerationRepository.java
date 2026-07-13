package top.focess.keystead.server.vault;

import org.springframework.data.jpa.repository.JpaRepository;

interface VaultRotationGenerationRepository
        extends JpaRepository<VaultRotationGenerationEntity, String> {}
