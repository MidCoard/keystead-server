package top.focess.keystead.server.identity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import jakarta.persistence.EntityManager;
import java.time.Instant;
import org.hibernate.exception.ConstraintViolationException;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

@SpringBootTest
@ActiveProfiles("test")
class DeviceWrappingKeyDatabaseConstraintTest {

    private static final Instant CREATED_AT = Instant.parse("2026-07-13T00:00:00Z");
    private static final String CONSTRAINT_NAME = "ck_devices_wrapping_key_pair";

    private final EntityManager entityManager;
    private final TransactionTemplate transactions;

    @Autowired
    DeviceWrappingKeyDatabaseConstraintTest(
            @NonNull EntityManager entityManager,
            @NonNull PlatformTransactionManager transactionManager) {
        this.entityManager = entityManager;
        this.transactions = new TransactionTemplate(transactionManager);
    }

    @Test
    void databaseRejectsWrappingAlgorithmWithoutPublicKey() {
        DeviceEntity device = device("constraint-algorithm-only");
        device.wrappingKeyAlgorithm = "RSA_OAEP_SHA256";

        assertWrappingPairConstraintRejects(device);
    }

    @Test
    void databaseRejectsWrappingPublicKeyWithoutAlgorithm() {
        DeviceEntity device = device("constraint-public-key-only");
        device.wrappingPublicKey = "wrapping-public-key";

        assertWrappingPairConstraintRejects(device);
    }

    private void assertWrappingPairConstraintRejects(@NonNull DeviceEntity device) {
        ConstraintViolationException exception =
                assertThrows(
                        ConstraintViolationException.class,
                        () ->
                                transactions.executeWithoutResult(
                                        ignored -> {
                                            entityManager.persist(device);
                                            entityManager.flush();
                                        }));

        assertThat(exception.getConstraintName()).containsIgnoringCase(CONSTRAINT_NAME);
    }

    private static @NonNull DeviceEntity device(@NonNull String deviceId) {
        DeviceEntity device = new DeviceEntity();
        device.id = new DeviceEntityId("wrapping-constraint-owner", deviceId);
        device.keyAlgorithm = "ED25519";
        device.publicKey = "proof-public-key";
        device.createdAt = CREATED_AT;
        return device;
    }
}
