package top.focess.keystead.server.recovery;

import org.springframework.data.jpa.repository.JpaRepository;

interface RecoveryRequestRepository extends JpaRepository<RecoveryRequestEntity, String> {}
