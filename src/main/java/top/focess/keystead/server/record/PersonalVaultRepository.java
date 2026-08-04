package top.focess.keystead.server.record;

import org.springframework.data.jpa.repository.JpaRepository;

interface PersonalVaultRepository extends JpaRepository<PersonalVaultEntity, String> {}
