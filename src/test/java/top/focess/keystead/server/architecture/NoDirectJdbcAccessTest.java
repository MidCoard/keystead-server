package top.focess.keystead.server.architecture;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;

class NoDirectJdbcAccessTest {

    @Test
    void productionCodeDoesNotUseSpringJdbcDirectly() throws IOException {
        List<String> offenders =
                Files.walk(Path.of("src/main/java"))
                        .filter(path -> path.toString().endsWith(".java"))
                        .filter(
                                path -> {
                                    try {
                                        String source = Files.readString(path);
                                        return source.contains("org.springframework.jdbc")
                                                || source.contains("JdbcTemplate");
                                    } catch (IOException e) {
                                        throw new IllegalStateException(e);
                                    }
                                })
                        .map(Path::toString)
                        .sorted()
                        .toList();

        assertEquals(List.of(), offenders);
    }

    @Test
    void buildUsesSpringDataJpaInsteadOfSpringDataJdbc() throws IOException {
        String build = Files.readString(Path.of("build.gradle.kts"));

        assertEquals(false, build.contains("spring-boot-starter-data-jdbc"));
        assertEquals(true, build.contains("spring-boot-starter-data-jpa"));
    }

    @Test
    void encryptedRecordWritesFlushJpaConstraintsInsideServiceBoundary() throws IOException {
        String repository =
                Files.readString(
                        Path.of(
                                "src/main/java/top/focess/keystead/server/record/EncryptedRecordRepository.java"));
        String writes =
                Files.readString(
                        Path.of(
                                "src/main/java/top/focess/keystead/server/record/EncryptedRecordRepositoryWritesImpl.java"));

        assertEquals(
                false, repository.contains("saveAndFlush(EncryptedRecordEntity.from(record))"));
        assertEquals(false, repository.contains("save(EncryptedRecordEntity.from(record))"));
        assertEquals(
                true, writes.contains("entityManager.persist(EncryptedRecordEntity.from(record))"));
        assertEquals(
                true, writes.contains("entityManager.merge(EncryptedRecordEntity.from(record))"));
        assertEquals(true, writes.contains("entityManager.flush()"));
    }

    @Test
    void auditEventAppendFlushesJpaConstraintsInsideServiceBoundary() throws IOException {
        String repository =
                Files.readString(
                        Path.of(
                                "src/main/java/top/focess/keystead/server/audit/AuditEventRepository.java"));
        String writes =
                Files.readString(
                        Path.of(
                                "src/main/java/top/focess/keystead/server/audit/AuditEventRepositoryWritesImpl.java"));

        assertEquals(false, repository.contains("save(AuditEventEntity.from(event))"));
        assertEquals(true, writes.contains("entityManager.persist(AuditEventEntity.from(event))"));
        assertEquals(true, writes.contains("entityManager.flush()"));
    }

    @Test
    void refreshTokenWritesFlushJpaConstraintsInsideServiceBoundary() throws IOException {
        String repository =
                Files.readString(
                        Path.of(
                                "src/main/java/top/focess/keystead/server/auth/RefreshTokenRepository.java"));
        String writes =
                Files.readString(
                        Path.of(
                                "src/main/java/top/focess/keystead/server/auth/RefreshTokenRepositoryWritesImpl.java"));

        assertEquals(false, repository.contains("saveAndFlush(RefreshTokenEntity.from(token))"));
        assertEquals(
                true, writes.contains("entityManager.persist(RefreshTokenEntity.from(token))"));
        assertEquals(true, writes.contains("entityManager.merge(RefreshTokenEntity.from(token))"));
        assertEquals(true, writes.contains("entityManager.flush()"));
    }

    @Test
    void identityWritesFlushJpaConstraintsInsideServiceBoundary() throws IOException {
        String userRepository =
                Files.readString(
                        Path.of(
                                "src/main/java/top/focess/keystead/server/identity/UserRepository.java"));
        String deviceRepository =
                Files.readString(
                        Path.of(
                                "src/main/java/top/focess/keystead/server/identity/DeviceRepository.java"));
        String challengeRepository =
                Files.readString(
                        Path.of(
                                "src/main/java/top/focess/keystead/server/identity/DeviceChallengeRepository.java"));
        String userWrites =
                Files.readString(
                        Path.of(
                                "src/main/java/top/focess/keystead/server/identity/UserRepositoryWritesImpl.java"));
        String deviceWrites =
                Files.readString(
                        Path.of(
                                "src/main/java/top/focess/keystead/server/identity/DeviceRepositoryWritesImpl.java"));
        String challengeWrites =
                Files.readString(
                        Path.of(
                                "src/main/java/top/focess/keystead/server/identity/DeviceChallengeRepositoryWritesImpl.java"));

        assertEquals(false, userRepository.contains("save(UserEntity.from(user))"));
        assertEquals(false, deviceRepository.contains("save(DeviceEntity.from(device))"));
        assertEquals(
                false, challengeRepository.contains("save(DeviceChallengeEntity.from(challenge))"));
        assertEquals(true, userWrites.contains("entityManager.persist(UserEntity.from(user))"));
        assertEquals(true, userWrites.contains("entityManager.flush()"));
        assertEquals(
                true, deviceWrites.contains("entityManager.persist(DeviceEntity.from(device))"));
        assertEquals(true, deviceWrites.contains("entityManager.merge(DeviceEntity.from(device))"));
        assertEquals(true, deviceWrites.contains("entityManager.flush()"));
        assertEquals(
                true,
                challengeWrites.contains(
                        "entityManager.persist(DeviceChallengeEntity.from(challenge))"));
        assertEquals(true, challengeWrites.contains("entityManager.flush()"));
    }

    @Test
    void vaultWritesFlushJpaConstraintsInsideServiceBoundary() throws IOException {
        String vaultRepository =
                Files.readString(
                        Path.of(
                                "src/main/java/top/focess/keystead/server/vault/VaultRepository.java"));
        String keyPackageRepository =
                Files.readString(
                        Path.of(
                                "src/main/java/top/focess/keystead/server/vault/VaultKeyPackageRepository.java"));
        String vaultWrites =
                Files.readString(
                        Path.of(
                                "src/main/java/top/focess/keystead/server/vault/VaultRepositoryWritesImpl.java"));
        String keyPackageWrites =
                Files.readString(
                        Path.of(
                                "src/main/java/top/focess/keystead/server/vault/VaultKeyPackageRepositoryWritesImpl.java"));

        assertEquals(false, vaultRepository.contains("saveAndFlush(VaultEntity.from(vault))"));
        assertEquals(
                false,
                keyPackageRepository.contains("save(VaultKeyPackageEntity.from(keyPackage))"));
        assertEquals(true, vaultWrites.contains("entityManager.persist(VaultEntity.from(vault))"));
        assertEquals(true, vaultWrites.contains("entityManager.merge(VaultEntity.from(vault))"));
        assertEquals(true, vaultWrites.contains("entityManager.flush()"));
        assertEquals(
                true,
                keyPackageWrites.contains(
                        "entityManager.persist(VaultKeyPackageEntity.from(keyPackage))"));
        assertEquals(
                true,
                keyPackageWrites.contains(
                        "entityManager.merge(VaultKeyPackageEntity.from(keyPackage))"));
        assertEquals(true, keyPackageWrites.contains("entityManager.flush()"));
    }
}
