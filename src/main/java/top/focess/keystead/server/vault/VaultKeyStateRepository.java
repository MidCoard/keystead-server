package top.focess.keystead.server.vault;

import org.springframework.data.jpa.repository.JpaRepository;

interface VaultKeyStateRepository extends JpaRepository<VaultKeyStateEntity, VaultEntityId> {}
