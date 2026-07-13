package top.focess.keystead.server.recovery;

import org.springframework.data.jpa.repository.JpaRepository;

interface RecoveryChallengeRepository extends JpaRepository<RecoveryChallengeEntity, String> {}
