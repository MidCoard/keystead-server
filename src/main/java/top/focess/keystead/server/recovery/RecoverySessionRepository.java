package top.focess.keystead.server.recovery;

import org.springframework.data.jpa.repository.JpaRepository;

interface RecoverySessionRepository extends JpaRepository<RecoverySessionEntity, String> {}
