package top.focess.keystead.server.recovery;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.jayway.jsonpath.JsonPath;
import jakarta.persistence.EntityManager;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class RecoveryCompletionApiTest {

    private static final String OLD_PASSWORD = "correct horse battery staple";
    private static final String NEW_PASSWORD = "new correct horse battery staple";
    private static final String CREDENTIAL = "completion-derived-recovery-credential";

    @Autowired private MockMvc mvc;
    @Autowired private EntityManager entityManager;
    @Autowired private PlatformTransactionManager transactionManager;

    @Test
    void completionResetsPasswordRevokesSessionsEnrollsDeviceAndConsumesKit() throws Exception {
        String username = "completion-success-alice";
        registerUser(username);
        String oldLogin = login(username, OLD_PASSWORD, null, 200);
        String oldAccess = JsonPath.read(oldLogin, "$.accessToken");
        String oldRefresh = JsonPath.read(oldLogin, "$.refreshToken");
        String recoveryToken = createKitSession(username);
        KeyPair replacement = rsaKeyPair();

        mvc.perform(
                        post("/api/v1/auth/recovery/complete")
                                .header(HttpHeaders.AUTHORIZATION, "Recovery " + recoveryToken)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        completionBody(
                                                NEW_PASSWORD,
                                                "replacement-laptop",
                                                replacement,
                                                "[]")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accountRecovered").value(true))
                .andExpect(jsonPath("$.deviceId").value("replacement-laptop"))
                .andExpect(jsonPath("$.recoveredVaultIds").isArray())
                .andExpect(jsonPath("$.pendingVaultIds").isArray())
                .andExpect(jsonPath("$.replacementKitRequired").value(true))
                .andExpect(jsonPath("$.newPassword").doesNotExist());

        login(username, OLD_PASSWORD, null, 401);
        login(username, NEW_PASSWORD, "replacement-laptop", 200);
        mvc.perform(
                        post("/api/v1/auth/refresh")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"refreshToken\":\"%s\"}".formatted(oldRefresh)))
                .andExpect(status().isUnauthorized());
        mvc.perform(get("/api/v1/vaults").header(HttpHeaders.AUTHORIZATION, "Bearer " + oldAccess))
                .andExpect(status().isUnauthorized());

        assertEquals(1L, tokenVersion(username));
        assertEquals(RecoveryEnrollmentState.CONSUMED, enrollmentState(username));
        assertNotNull(deviceVerifiedAt(username, "replacement-laptop"));
        assertEquals(1L, consumedSessionCount(username));
        String auditDetails = completionAuditDetails(username);
        assertFalse(auditDetails.contains(NEW_PASSWORD));
        assertFalse(auditDetails.contains(recoveryToken));

        mvc.perform(
                        post("/api/v1/auth/recovery/complete")
                                .header(HttpHeaders.AUTHORIZATION, "Recovery " + recoveryToken)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        completionBody(
                                                NEW_PASSWORD,
                                                "another-laptop",
                                                rsaKeyPair(),
                                                "[]")))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void deviceConflictRollsBackPasswordAuthorityAndSessionForRetry() throws Exception {
        String username = "completion-conflict-alice";
        registerUser(username);
        registerUnverifiedDevice(username, "existing-device", rsaKeyPair());
        String recoveryToken = createKitSession(username);

        mvc.perform(
                        post("/api/v1/auth/recovery/complete")
                                .header(HttpHeaders.AUTHORIZATION, "Recovery " + recoveryToken)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        completionBody(
                                                NEW_PASSWORD,
                                                "existing-device",
                                                rsaKeyPair(),
                                                "[]")))
                .andExpect(status().isConflict());

        login(username, OLD_PASSWORD, null, 200);
        login(username, NEW_PASSWORD, null, 401);
        assertEquals(0L, tokenVersion(username));
        assertEquals(RecoveryEnrollmentState.ACTIVE, enrollmentState(username));
        assertEquals(0L, consumedSessionCount(username));

        mvc.perform(
                        post("/api/v1/auth/recovery/complete")
                                .header(HttpHeaders.AUTHORIZATION, "Recovery " + recoveryToken)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        completionBody(
                                                NEW_PASSWORD, "retry-device", rsaKeyPair(), "[]")))
                .andExpect(status().isOk());
    }

    @Test
    void staleVaultPackageRollsBackEveryCompletionMutation() throws Exception {
        String username = "completion-package-alice";
        String vaultId = "completion-package-vault";
        registerUser(username);
        createVault(username, vaultId);
        declareCurrentVaultKey(username, vaultId, "vault-key-current");
        String recoveryToken = createKitSession(username);
        KeyPair replacement = rsaKeyPair();
        String packages =
                """
                [{
                  "vaultId": "%s",
                  "vaultKeyId": "vault-key-stale",
                  "keyAlgorithm": "TINK_ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM",
                  "encryptedVaultKey": "opaque-replacement-package"
                }]
                """
                        .formatted(vaultId);

        mvc.perform(
                        post("/api/v1/auth/recovery/complete")
                                .header(HttpHeaders.AUTHORIZATION, "Recovery " + recoveryToken)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        completionBody(
                                                NEW_PASSWORD,
                                                "package-device",
                                                replacement,
                                                packages)))
                .andExpect(status().isBadRequest());

        login(username, OLD_PASSWORD, null, 200);
        assertEquals(0L, tokenVersion(username));
        assertEquals(0L, deviceCount(username, "package-device"));
        assertEquals(0L, consumedSessionCount(username));
        assertEquals(RecoveryEnrollmentState.ACTIVE, enrollmentState(username));
    }

    @Test
    void deviceApprovalSessionAcceptsOnlyExactApprovedReplacementKeys() throws Exception {
        String username = "completion-device-approval-alice";
        String deviceId = "approved-replacement-device";
        registerUser(username);
        KeyPair approvedProof = rsaKeyPair();
        String approvedPublicKey =
                Base64.getEncoder().encodeToString(approvedProof.getPublic().getEncoded());
        String approvedWrappingKey =
                Base64.getEncoder()
                        .encodeToString(
                                ("wrapping-key-" + deviceId).getBytes(StandardCharsets.UTF_8));
        String recoveryToken = "device-approval-completion-token";
        persistDeviceApprovalSession(
                username, deviceId, approvedPublicKey, approvedWrappingKey, recoveryToken);

        mvc.perform(
                        post("/api/v1/auth/recovery/complete")
                                .header(HttpHeaders.AUTHORIZATION, "Recovery " + recoveryToken)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        completionBody(NEW_PASSWORD, deviceId, rsaKeyPair(), "[]")))
                .andExpect(status().isBadRequest());
        assertEquals(0L, consumedSessionCount(username));
        login(username, OLD_PASSWORD, null, 200);

        mvc.perform(
                        post("/api/v1/auth/recovery/complete")
                                .header(HttpHeaders.AUTHORIZATION, "Recovery " + recoveryToken)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        completionBody(
                                                NEW_PASSWORD, deviceId, approvedProof, "[]")))
                .andExpect(status().isOk());
        login(username, NEW_PASSWORD, deviceId, 200);
    }

    private String createKitSession(String username) throws Exception {
        String enrollment =
                mvc.perform(
                                post("/api/v1/recovery/enrollments")
                                        .with(httpBasic(username, OLD_PASSWORD))
                                        .contentType(MediaType.APPLICATION_JSON)
                                        .content(
                                                """
                                                {
                                                  "generation": 1,
                                                  "accountCredential": "%s",
                                                  "wrappingAlgorithm": "TINK_ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM",
                                                  "wrappingPublicKey": "recovery-public-key",
                                                  "encryptedPrivateKey": "opaque-encrypted-private-key"
                                                }
                                                """
                                                        .formatted(CREDENTIAL)))
                        .andExpect(status().isCreated())
                        .andReturn()
                        .getResponse()
                        .getContentAsString();
        String enrollmentId = JsonPath.read(enrollment, "$.enrollmentId");
        mvc.perform(
                        post("/api/v1/recovery/enrollments/{enrollmentId}/commit", enrollmentId)
                                .with(httpBasic(username, OLD_PASSWORD))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"generation\":1}"))
                .andExpect(status().isOk());
        String challenge =
                mvc.perform(
                                post("/api/v1/auth/recovery/challenges")
                                        .contentType(MediaType.APPLICATION_JSON)
                                        .content(
                                                """
                                                {"username":"%s","enrollmentId":"%s","generation":1}
                                                """
                                                        .formatted(username, enrollmentId)))
                        .andExpect(status().isCreated())
                        .andReturn()
                        .getResponse()
                        .getContentAsString();
        String challengeId = JsonPath.read(challenge, "$.challengeId");
        String session =
                mvc.perform(
                                post("/api/v1/auth/recovery/kit")
                                        .contentType(MediaType.APPLICATION_JSON)
                                        .content(
                                                "{\"challengeId\":\"%s\",\"accountCredential\":\"%s\"}"
                                                        .formatted(challengeId, CREDENTIAL)))
                        .andExpect(status().isOk())
                        .andReturn()
                        .getResponse()
                        .getContentAsString();
        return JsonPath.read(session, "$.token");
    }

    private String login(String username, String password, String deviceId, int statusCode)
            throws Exception {
        String device = deviceId == null ? "" : ",\"deviceId\":\"%s\"".formatted(deviceId);
        return mvc.perform(
                        post("/api/v1/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        "{\"username\":\"%s\",\"password\":\"%s\"%s}"
                                                .formatted(username, password, device)))
                .andExpect(status().is(statusCode))
                .andReturn()
                .getResponse()
                .getContentAsString();
    }

    private static String completionBody(
            String password, String deviceId, KeyPair proofKeys, String packages) {
        String proofPublicKey =
                Base64.getEncoder().encodeToString(proofKeys.getPublic().getEncoded());
        String wrappingPublicKey =
                Base64.getEncoder()
                        .encodeToString(
                                ("wrapping-key-" + deviceId).getBytes(StandardCharsets.UTF_8));
        return """
        {
          "newPassword": "%s",
          "deviceId": "%s",
          "proofKeyAlgorithm": "RSA_OAEP_SHA256",
          "proofPublicKey": "%s",
          "wrappingKeyAlgorithm": "TINK_ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM",
          "wrappingPublicKey": "%s",
          "vaultPackages": %s
        }
        """
                .formatted(password, deviceId, proofPublicKey, wrappingPublicKey, packages);
    }

    private void registerUser(String username) throws Exception {
        mvc.perform(
                        post("/api/v1/users")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        "{\"username\":\"%s\",\"password\":\"%s\"}"
                                                .formatted(username, OLD_PASSWORD)))
                .andExpect(status().isCreated());
    }

    private void registerUnverifiedDevice(String username, String deviceId, KeyPair proofKeys)
            throws Exception {
        mvc.perform(
                        post("/api/v1/devices")
                                .with(httpBasic(username, OLD_PASSWORD))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "deviceId":"%s",
                                          "keyAlgorithm":"RSA_OAEP_SHA256",
                                          "publicKey":"%s",
                                          "wrappingKeyAlgorithm":"TINK_ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM",
                                          "wrappingPublicKey":"%s"
                                        }
                                        """
                                                .formatted(
                                                        deviceId,
                                                        Base64.getEncoder()
                                                                .encodeToString(
                                                                        proofKeys
                                                                                .getPublic()
                                                                                .getEncoded()),
                                                        Base64.getEncoder()
                                                                .encodeToString(
                                                                        ("existing-wrapping-"
                                                                                        + deviceId)
                                                                                .getBytes(
                                                                                        StandardCharsets
                                                                                                .UTF_8)))))
                .andExpect(status().isCreated());
    }

    private void createVault(String username, String vaultId) throws Exception {
        mvc.perform(
                        put("/api/v1/vaults/{vaultId}", vaultId)
                                .with(httpBasic(username, OLD_PASSWORD))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"encryptedMetadata\":\"opaque\"}"))
                .andExpect(status().isCreated());
    }

    private void declareCurrentVaultKey(String username, String vaultId, String vaultKeyId)
            throws Exception {
        mvc.perform(
                        put("/api/v1/vaults/{vaultId}/key-rotation", vaultId)
                                .with(httpBasic(username, OLD_PASSWORD))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"vaultKeyId\":\"%s\"}".formatted(vaultKeyId)))
                .andExpect(status().isNoContent());
    }

    private long tokenVersion(String username) {
        return transaction(
                () ->
                        entityManager
                                .createQuery(
                                        "select u.tokenVersion from UserEntity u where u.username = :username",
                                        Long.class)
                                .setParameter("username", username)
                                .getSingleResult());
    }

    private RecoveryEnrollmentState enrollmentState(String username) {
        return transaction(
                () ->
                        entityManager
                                .createQuery(
                                        "select e.state from RecoveryEnrollmentEntity e where e.id.username = :username",
                                        RecoveryEnrollmentState.class)
                                .setParameter("username", username)
                                .getSingleResult());
    }

    private Object deviceVerifiedAt(String username, String deviceId) {
        return transaction(
                () ->
                        entityManager
                                .createQuery(
                                        "select d.verifiedAt from DeviceEntity d where d.id.ownerId = :username and d.id.deviceId = :deviceId")
                                .setParameter("username", username)
                                .setParameter("deviceId", deviceId)
                                .getSingleResult());
    }

    private long deviceCount(String username, String deviceId) {
        return transaction(
                () ->
                        entityManager
                                .createQuery(
                                        "select count(d) from DeviceEntity d where d.id.ownerId = :username and d.id.deviceId = :deviceId",
                                        Long.class)
                                .setParameter("username", username)
                                .setParameter("deviceId", deviceId)
                                .getSingleResult());
    }

    private long consumedSessionCount(String username) {
        return transaction(
                () ->
                        entityManager
                                .createQuery(
                                        "select count(s) from RecoverySessionEntity s where s.username = :username and s.consumedAt is not null",
                                        Long.class)
                                .setParameter("username", username)
                                .getSingleResult());
    }

    private String completionAuditDetails(String username) {
        return transaction(
                () ->
                        entityManager
                                .createQuery(
                                        "select e.details from AuditEventEntity e where e.ownerId = :username and e.eventType = 'RECOVERY_COMPLETED'",
                                        String.class)
                                .setParameter("username", username)
                                .getSingleResult());
    }

    private void persistDeviceApprovalSession(
            String username,
            String deviceId,
            String proofPublicKey,
            String wrappingPublicKey,
            String rawToken) {
        transaction(
                () -> {
                    Instant now = Instant.now();
                    RecoveryRequestEntity request = new RecoveryRequestEntity();
                    request.requestId = "completion-approved-request-" + username;
                    request.username = username;
                    request.nonce = "completion-device-approval-nonce";
                    request.fingerprint = "AAAA-BBBB-CCCC-DDDD-EEEE";
                    request.deviceId = deviceId;
                    request.proofKeyAlgorithm = "RSA_OAEP_SHA256";
                    request.proofPublicKey = proofPublicKey;
                    request.wrappingKeyAlgorithm = "TINK_ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM";
                    request.wrappingPublicKey = wrappingPublicKey;
                    request.state = RecoveryRequestState.CONSUMED;
                    request.expiresAt = now.plusSeconds(600);
                    request.approvedByDeviceId = "trusted-device";
                    request.approvedAt = now;
                    request.consumedAt = now;
                    request.createdAt = now;
                    entityManager.persist(request);

                    RecoverySessionEntity session = new RecoverySessionEntity();
                    session.tokenHash = sha256(rawToken);
                    session.username = username;
                    session.authority = RecoveryAuthority.DEVICE_APPROVAL;
                    session.requestId = request.requestId;
                    session.expiresAt = now.plusSeconds(600);
                    session.createdAt = now;
                    entityManager.persist(session);
                    entityManager.flush();
                    return null;
                });
    }

    private static String sha256(String value) throws Exception {
        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(
                        MessageDigest.getInstance("SHA-256")
                                .digest(value.getBytes(StandardCharsets.US_ASCII)));
    }

    private static KeyPair rsaKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
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
