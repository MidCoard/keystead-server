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
        assertEquals(
                true,
                writes.contains(
                        "entityManager.persist(AuditEventEntity.from(event, correlationId, signature))"));
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
        String userWrites =
                Files.readString(
                        Path.of(
                                "src/main/java/top/focess/keystead/server/identity/UserRepositoryWritesImpl.java"));
        assertEquals(false, userRepository.contains("save(UserEntity.from(user))"));
        assertEquals(true, userWrites.contains("entityManager.persist(UserEntity.from(user))"));
        assertEquals(true, userWrites.contains("entityManager.flush()"));
    }

    @Test
    void legacyServerIdentityAndCollaborationPackagesAreAbsent() {
        assertEquals(
                false,
                Files.exists(
                        Path.of(
                                "src/main/java/top/focess/keystead/server/automation/AutomationController.java")));
        assertEquals(
                false,
                Files.exists(
                        Path.of(
                                "src/main/java/top/focess/keystead/server/vault/VaultMemberController.java")));
        assertEquals(
                false,
                Files.exists(
                        Path.of(
                                "src/main/java/top/focess/keystead/server/identity/DeviceController.java")));
    }
}
