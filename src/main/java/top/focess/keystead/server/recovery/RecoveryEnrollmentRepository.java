package top.focess.keystead.server.recovery;

import org.springframework.data.jpa.repository.JpaRepository;

interface RecoveryEnrollmentRepository
        extends JpaRepository<RecoveryEnrollmentEntity, RecoveryEnrollmentId> {}
