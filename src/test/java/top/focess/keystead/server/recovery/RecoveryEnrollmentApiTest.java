package top.focess.keystead.server.recovery;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.jayway.jsonpath.JsonPath;
import jakarta.persistence.EntityManager;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class RecoveryEnrollmentApiTest {

    private static final String PASSWORD = "correct horse battery staple";
    private static final String CREDENTIAL = "derived-account-recovery-credential";

    @Autowired private MockMvc mvc;
    @Autowired private EntityManager entityManager;
    @Autowired private PasswordEncoder passwordEncoder;
    @Autowired private PlatformTransactionManager transactionManager;

    @Test
    void recoveryRequestAndPackageTextRedactsCredentialsAndCiphertexts() {
        RecoveryEnrollmentRequest enrollment =
                new RecoveryEnrollmentRequest(
                        1L,
                        "credential-never-log",
                        "TINK_ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM",
                        "public-key",
                        "private-envelope-never-log");
        RecoveryVaultPackageRequest request =
                new RecoveryVaultPackageRequest(
                        1L,
                        "vault-key-1",
                        "TINK_ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM",
                        "package-never-log");
        RecoveryVaultPackageResponse response =
                new RecoveryVaultPackageResponse(
                        "enrollment-1",
                        1L,
                        "vault-1",
                        "vault-key-1",
                        "TINK_ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM",
                        "response-package-never-log",
                        Instant.EPOCH);

        assertFalse(enrollment.toString().contains("credential-never-log"));
        assertFalse(enrollment.toString().contains("private-envelope-never-log"));
        assertFalse(request.toString().contains("package-never-log"));
        assertFalse(response.toString().contains("response-package-never-log"));
    }

    @Test
    void authenticatedUserCreatesPendingEnrollmentAndServerStoresOnlyCredentialHash()
            throws Exception {
        String username = "recovery-enroll-alice";
        registerUser(username);

        String enrollmentId = createEnrollment(username, 1L, CREDENTIAL);

        mvc.perform(get("/api/v1/recovery/enrollments").with(httpBasic(username, PASSWORD)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].enrollmentId").value(enrollmentId))
                .andExpect(jsonPath("$[0].generation").value(1))
                .andExpect(jsonPath("$[0].state").value("PENDING"))
                .andExpect(jsonPath("$[0].accountCredential").doesNotExist())
                .andExpect(jsonPath("$[0].credentialHash").doesNotExist())
                .andExpect(jsonPath("$[0].encryptedPrivateKey").doesNotExist());

        Object[] stored =
                transaction(
                        () ->
                                entityManager
                                        .createQuery(
                                                "select e.credentialHash, e.wrappingPublicKey, e.encryptedPrivateKey from RecoveryEnrollmentEntity e where e.id.username = :username",
                                                Object[].class)
                                        .setParameter("username", username)
                                        .getSingleResult());
        assertNotEquals(CREDENTIAL, stored[0]);
        assertTrue(passwordEncoder.matches(CREDENTIAL, (String) stored[0]));
        assertEquals("recovery-public-key", stored[1]);
        assertEquals("opaque-encrypted-recovery-private-key", stored[2]);
    }

    @Test
    void replacementKeepsOldGenerationActiveUntilAtomicCommit() throws Exception {
        String username = "recovery-replace-alice";
        registerUser(username);
        String first = createEnrollment(username, 1L, CREDENTIAL + "-1");
        commitEnrollment(username, first, 1L);
        String second = createEnrollment(username, 2L, CREDENTIAL + "-2");

        mvc.perform(get("/api/v1/recovery/enrollments").with(httpBasic(username, PASSWORD)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[?(@.state == 'ACTIVE')].enrollmentId").value(first))
                .andExpect(jsonPath("$[?(@.state == 'PENDING')].enrollmentId").value(second));
        assertEquals(1L, countState(username, RecoveryEnrollmentState.ACTIVE));
        assertEquals(1L, countState(username, RecoveryEnrollmentState.PENDING));

        commitEnrollment(username, second, 2L);

        assertEquals(1L, countState(username, RecoveryEnrollmentState.ACTIVE));
        assertEquals(0L, countState(username, RecoveryEnrollmentState.PENDING));
        assertEquals(1L, countState(username, RecoveryEnrollmentState.SUPERSEDED));
        mvc.perform(get("/api/v1/recovery/enrollments").with(httpBasic(username, PASSWORD)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[?(@.state == 'ACTIVE')].enrollmentId").value(second));
    }

    @Test
    void vaultManagerStoresOpaqueCurrentKeyPackageForRecipientsEnrollment() throws Exception {
        String owner = "recovery-package-owner";
        String recipient = "recovery-package-recipient";
        String outsider = "recovery-package-outsider";
        String vaultId = "recovery-package-vault";
        registerUser(owner);
        registerUser(recipient);
        registerUser(outsider);
        createVault(owner, vaultId);
        inviteAndAccept(owner, recipient, vaultId);
        declareCurrentVaultKey(owner, vaultId, "vault-key-current");
        String enrollmentId = createEnrollment(recipient, 1L, CREDENTIAL);

        mvc.perform(
                        put(
                                        "/api/v1/recovery/users/{username}/enrollments/{enrollmentId}/vaults/{vaultId}",
                                        recipient,
                                        enrollmentId,
                                        vaultId)
                                .with(httpBasic(owner, PASSWORD))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(packageBody(1L, "vault-key-current")))
                .andExpect(status().isCreated());

        mvc.perform(
                        get(
                                        "/api/v1/recovery/enrollments/{enrollmentId}/vaults/{vaultId}",
                                        enrollmentId,
                                        vaultId)
                                .with(httpBasic(recipient, PASSWORD)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.vaultId").value(vaultId))
                .andExpect(jsonPath("$.vaultKeyId").value("vault-key-current"))
                .andExpect(jsonPath("$.encryptedVaultKey").value("opaque-recovery-package"));

        mvc.perform(
                        put(
                                        "/api/v1/recovery/users/{username}/enrollments/{enrollmentId}/vaults/{vaultId}",
                                        recipient,
                                        enrollmentId,
                                        vaultId)
                                .with(httpBasic(owner, PASSWORD))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(packageBody(1L, "vault-key-stale")))
                .andExpect(status().isBadRequest());

        mvc.perform(
                        put(
                                        "/api/v1/recovery/users/{username}/enrollments/{enrollmentId}/vaults/{vaultId}",
                                        recipient,
                                        enrollmentId,
                                        vaultId)
                                .with(httpBasic(outsider, PASSWORD))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(packageBody(1L, "vault-key-current")))
                .andExpect(status().isNotFound());
    }

    @Test
    void validationAndAuditNeverEchoRecoverySecretsOrCiphertexts() throws Exception {
        String username = "recovery-audit-alice";
        registerUser(username);

        mvc.perform(
                        post("/api/v1/recovery/enrollments")
                                .with(httpBasic(username, PASSWORD))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(enrollmentBody(0L, CREDENTIAL, "RAW_RSA")))
                .andExpect(status().isBadRequest());

        String enrollmentId = createEnrollment(username, 1L, CREDENTIAL);
        commitEnrollment(username, enrollmentId, 1L);
        List<String> details =
                transaction(
                        () ->
                                entityManager
                                        .createQuery(
                                                "select e.details from AuditEventEntity e where e.ownerId = :username and e.eventType like 'RECOVERY_%'",
                                                String.class)
                                        .setParameter("username", username)
                                        .getResultList());
        assertThat(details).isNotEmpty();
        assertThat(String.join("\n", details))
                .doesNotContain(CREDENTIAL)
                .doesNotContain("recovery-public-key")
                .doesNotContain("opaque-encrypted-recovery-private-key");
    }

    private String createEnrollment(String username, long generation, String credential)
            throws Exception {
        String json =
                mvc.perform(
                                post("/api/v1/recovery/enrollments")
                                        .with(httpBasic(username, PASSWORD))
                                        .contentType(MediaType.APPLICATION_JSON)
                                        .content(
                                                enrollmentBody(
                                                        generation,
                                                        credential,
                                                        "TINK_ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM")))
                        .andExpect(status().isCreated())
                        .andExpect(jsonPath("$.generation").value(generation))
                        .andExpect(jsonPath("$.state").value("PENDING"))
                        .andReturn()
                        .getResponse()
                        .getContentAsString();
        return JsonPath.read(json, "$.enrollmentId");
    }

    private void commitEnrollment(String username, String enrollmentId, long generation)
            throws Exception {
        mvc.perform(
                        post("/api/v1/recovery/enrollments/{enrollmentId}/commit", enrollmentId)
                                .with(httpBasic(username, PASSWORD))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"generation\":%d}".formatted(generation)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.state").value("ACTIVE"));
    }

    private long countState(String username, RecoveryEnrollmentState state) {
        return transaction(
                () ->
                        entityManager
                                .createQuery(
                                        "select count(e) from RecoveryEnrollmentEntity e where e.id.username = :username and e.state = :state",
                                        Long.class)
                                .setParameter("username", username)
                                .setParameter("state", state)
                                .getSingleResult());
    }

    private void registerUser(String username) throws Exception {
        mvc.perform(
                        post("/api/v1/users")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {"username":"%s","password":"%s"}
                                        """
                                                .formatted(username, PASSWORD)))
                .andExpect(status().isCreated());
    }

    private void createVault(String username, String vaultId) throws Exception {
        mvc.perform(
                        put("/api/v1/vaults/{vaultId}", vaultId)
                                .with(httpBasic(username, PASSWORD))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"encryptedMetadata\":\"opaque-vault-metadata\"}"))
                .andExpect(status().isCreated());
    }

    private void inviteAndAccept(String owner, String recipient, String vaultId) throws Exception {
        mvc.perform(
                        put("/api/v1/vaults/{vaultId}/members/{recipient}", vaultId, recipient)
                                .with(httpBasic(owner, PASSWORD))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"role\":\"VIEWER\"}"))
                .andExpect(status().isCreated());
        mvc.perform(
                        post("/api/v1/vaults/{vaultId}/members/accept", vaultId)
                                .with(httpBasic(recipient, PASSWORD)))
                .andExpect(status().isNoContent());
    }

    private void declareCurrentVaultKey(String owner, String vaultId, String vaultKeyId)
            throws Exception {
        mvc.perform(
                        put("/api/v1/vaults/{vaultId}/key-rotation", vaultId)
                                .with(httpBasic(owner, PASSWORD))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"vaultKeyId\":\"%s\"}".formatted(vaultKeyId)))
                .andExpect(status().isNoContent());
    }

    private static String enrollmentBody(long generation, String credential, String algorithm) {
        return """
        {
          "generation": %d,
          "accountCredential": "%s",
          "wrappingAlgorithm": "%s",
          "wrappingPublicKey": "recovery-public-key",
          "encryptedPrivateKey": "opaque-encrypted-recovery-private-key"
        }
        """
                .formatted(generation, credential, algorithm);
    }

    private static String packageBody(long generation, String vaultKeyId) {
        return """
        {
          "generation": %d,
          "vaultKeyId": "%s",
          "keyAlgorithm": "TINK_ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM",
          "encryptedVaultKey": "opaque-recovery-package"
        }
        """
                .formatted(generation, vaultKeyId);
    }

    private <T> T transaction(java.util.concurrent.Callable<T> action) {
        return new TransactionTemplate(transactionManager)
                .execute(
                        ignored -> {
                            try {
                                return action.call();
                            } catch (Exception e) {
                                throw new IllegalStateException(e);
                            }
                        });
    }
}
