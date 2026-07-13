package top.focess.keystead.server.recovery;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
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
import java.security.PrivateKey;
import java.security.Signature;
import java.time.Instant;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import top.focess.keystead.recovery.RecoveryDeviceRequest;
import top.focess.keystead.recovery.RecoveryDeviceRequestCodec;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class VerifiedDeviceRecoveryApiTest {

    private static final String PASSWORD = "correct horse battery staple";

    @Autowired private MockMvc mvc;
    @Autowired private EntityManager entityManager;
    @Autowired private PlatformTransactionManager transactionManager;

    @Test
    void verifiedDeviceApprovesCanonicalRequestAndNewDeviceClaimsRestrictedSession()
            throws Exception {
        String username = "device-recovery-alice";
        String trustedDevice = "trusted-laptop";
        String vaultId = "device-recovery-vault";
        registerUser(username);
        KeyPair trustedKeys = registerVerifiedDevice(username, trustedDevice);
        createVault(username, vaultId);
        declareCurrentVaultKey(username, vaultId, "vault-key-current");
        KeyPair replacementProof = rsaKeyPair();

        String requestJson = createRequest(username, "replacement-laptop", replacementProof);
        String requestId = JsonPath.read(requestJson, "$.requestId");
        String canonicalEncoded = JsonPath.read(requestJson, "$.canonicalRequest");
        byte[] canonical = Base64.getUrlDecoder().decode(canonicalEncoded);
        RecoveryDeviceRequest decoded = RecoveryDeviceRequestCodec.decode(canonical);
        assertEquals(requestId, decoded.requestId());
        assertEquals(
                RecoveryDeviceRequestCodec.fingerprint(decoded),
                JsonPath.read(requestJson, "$.fingerprint"));

        mvc.perform(get("/api/v1/recovery/device-requests").with(httpBasic(username, PASSWORD)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].requestId").value(requestId))
                .andExpect(jsonPath("$[0].state").value("PENDING"));

        String approvalSignature = signature(trustedKeys.getPrivate(), canonical);
        mvc.perform(
                        post("/api/v1/recovery/device-requests/{requestId}/approve", requestId)
                                .with(httpBasic(username, PASSWORD))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "deviceId": "%s",
                                          "signature": "%s",
                                          "vaultPackages": [{
                                            "vaultId": "%s",
                                            "vaultKeyId": "vault-key-current",
                                            "keyAlgorithm": "TINK_ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM",
                                            "encryptedVaultKey": "opaque-new-device-package"
                                          }]
                                        }
                                        """
                                                .formatted(
                                                        trustedDevice, approvalSignature, vaultId)))
                .andExpect(status().isNoContent());
        approveExpecting(username, requestId, trustedDevice, approvalSignature, 401);

        mvc.perform(get("/api/v1/auth/recovery/device-requests/{requestId}", requestId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.state").value("APPROVED"));

        String claimSignature = signature(replacementProof.getPrivate(), canonical);
        String sessionJson =
                mvc.perform(
                                post(
                                                "/api/v1/auth/recovery/device-requests/{requestId}/claim",
                                                requestId)
                                        .contentType(MediaType.APPLICATION_JSON)
                                        .content(
                                                "{\"signature\":\"%s\"}".formatted(claimSignature)))
                        .andExpect(status().isOk())
                        .andExpect(jsonPath("$.token").isNotEmpty())
                        .andReturn()
                        .getResponse()
                        .getContentAsString();
        String token = JsonPath.read(sessionJson, "$.token");
        assertFalse(databaseContainsToken(token));
        assertEquals(RecoveryAuthority.DEVICE_APPROVAL, sessionAuthority(username));
        assertEquals(1L, requestPackageCount(requestId));

        mvc.perform(
                        post("/api/v1/auth/recovery/device-requests/{requestId}/claim", requestId)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"signature\":\"%s\"}".formatted(claimSignature)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void approvalRequiresMatchingVerifiedNonRevokedDeviceAndExactSignature() throws Exception {
        String username = "device-recovery-guard-alice";
        registerUser(username);
        KeyPair trusted = registerVerifiedDevice(username, "trusted-device");
        KeyPair unverified = registerDevice(username, "unverified-device");
        KeyPair replacement = rsaKeyPair();
        String requestJson = createRequest(username, "replacement-device", replacement);
        String requestId = JsonPath.read(requestJson, "$.requestId");
        byte[] canonical =
                Base64.getUrlDecoder()
                        .decode((String) JsonPath.read(requestJson, "$.canonicalRequest"));

        approveExpecting(
                username,
                requestId,
                "unverified-device",
                signature(unverified.getPrivate(), canonical),
                401);
        approveExpecting(
                username,
                requestId,
                "trusted-device",
                signature(rsaKeyPair().getPrivate(), canonical),
                401);

        mvc.perform(
                        delete("/api/v1/devices/{deviceId}", "trusted-device")
                                .with(httpBasic(username, PASSWORD)))
                .andExpect(status().isNoContent());
        approveExpecting(
                username,
                requestId,
                "trusted-device",
                signature(trusted.getPrivate(), canonical),
                401);
    }

    @Test
    void requestsAreAccountScopedExpireAndDoNotAcceptReplacementKeySubstitution() throws Exception {
        String username = "device-recovery-scope-alice";
        String outsider = "device-recovery-scope-outsider";
        registerUser(username);
        registerUser(outsider);
        KeyPair trusted = registerVerifiedDevice(username, "trusted-device");
        registerVerifiedDevice(outsider, "outsider-device");
        KeyPair replacement = rsaKeyPair();
        String requestJson = createRequest(username, "replacement-device", replacement);
        String requestId = JsonPath.read(requestJson, "$.requestId");
        byte[] canonical =
                Base64.getUrlDecoder()
                        .decode((String) JsonPath.read(requestJson, "$.canonicalRequest"));

        mvc.perform(get("/api/v1/recovery/device-requests").with(httpBasic(outsider, PASSWORD)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isEmpty());
        approveExpecting(
                outsider,
                requestId,
                "outsider-device",
                signature(trusted.getPrivate(), canonical),
                401);

        transaction(
                () -> {
                    entityManager
                            .createQuery(
                                    "update RecoveryRequestEntity r set r.createdAt = :created, r.expiresAt = :expired where r.requestId = :requestId")
                            .setParameter("created", Instant.EPOCH)
                            .setParameter("expired", Instant.EPOCH.plusSeconds(1))
                            .setParameter("requestId", requestId)
                            .executeUpdate();
                    return null;
                });
        approveExpecting(
                username,
                requestId,
                "trusted-device",
                signature(trusted.getPrivate(), canonical),
                401);

        String secondJson = createRequest(username, "replacement-device-2", rsaKeyPair());
        String secondId = JsonPath.read(secondJson, "$.requestId");
        byte[] secondCanonical =
                Base64.getUrlDecoder()
                        .decode((String) JsonPath.read(secondJson, "$.canonicalRequest"));
        approveExpecting(
                username,
                secondId,
                "trusted-device",
                signature(trusted.getPrivate(), secondCanonical),
                204);
        mvc.perform(
                        post("/api/v1/auth/recovery/device-requests/{requestId}/claim", secondId)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        "{\"signature\":\"%s\"}"
                                                .formatted(
                                                        signature(
                                                                replacement.getPrivate(),
                                                                secondCanonical))))
                .andExpect(status().isUnauthorized());
    }

    private String createRequest(String username, String deviceId, KeyPair proofKeys)
            throws Exception {
        String proofPublicKey =
                Base64.getEncoder().encodeToString(proofKeys.getPublic().getEncoded());
        String wrappingPublicKey =
                Base64.getEncoder()
                        .encodeToString(
                                ("wrapping-key-for-" + deviceId).getBytes(StandardCharsets.UTF_8));
        return mvc.perform(
                        post("/api/v1/auth/recovery/device-requests")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "username": "%s",
                                          "deviceId": "%s",
                                          "proofKeyAlgorithm": "RSA_OAEP_SHA256",
                                          "proofPublicKey": "%s",
                                          "wrappingKeyAlgorithm": "TINK_ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM",
                                          "wrappingPublicKey": "%s"
                                        }
                                        """
                                                .formatted(
                                                        username,
                                                        deviceId,
                                                        proofPublicKey,
                                                        wrappingPublicKey)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.fingerprint").isNotEmpty())
                .andExpect(jsonPath("$.userExists").doesNotExist())
                .andReturn()
                .getResponse()
                .getContentAsString();
    }

    private void approveExpecting(
            String username,
            String requestId,
            String deviceId,
            String signature,
            int expectedStatus)
            throws Exception {
        mvc.perform(
                        post("/api/v1/recovery/device-requests/{requestId}/approve", requestId)
                                .with(httpBasic(username, PASSWORD))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {"deviceId":"%s","signature":"%s","vaultPackages":[]}
                                        """
                                                .formatted(deviceId, signature)))
                .andExpect(status().is(expectedStatus));
    }

    private KeyPair registerVerifiedDevice(String username, String deviceId) throws Exception {
        KeyPair keyPair = registerDevice(username, deviceId);
        String challengeJson =
                mvc.perform(
                                post("/api/v1/devices/{deviceId}/challenges", deviceId)
                                        .with(httpBasic(username, PASSWORD)))
                        .andExpect(status().isCreated())
                        .andReturn()
                        .getResponse()
                        .getContentAsString();
        String challengeId = JsonPath.read(challengeJson, "$.challengeId");
        String nonce = JsonPath.read(challengeJson, "$.nonce");
        byte[] payload =
                ("keystead-device-proof:v1:" + challengeId + ":" + nonce)
                        .getBytes(StandardCharsets.UTF_8);
        mvc.perform(
                        post("/api/v1/devices/{deviceId}/proof", deviceId)
                                .with(httpBasic(username, PASSWORD))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        "{\"challengeId\":\"%s\",\"signature\":\"%s\"}"
                                                .formatted(
                                                        challengeId,
                                                        signature(keyPair.getPrivate(), payload))))
                .andExpect(status().isNoContent());
        return keyPair;
    }

    private KeyPair registerDevice(String username, String deviceId) throws Exception {
        KeyPair keyPair = rsaKeyPair();
        String publicKey = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
        mvc.perform(
                        post("/api/v1/devices")
                                .with(httpBasic(username, PASSWORD))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "deviceId": "%s",
                                          "keyAlgorithm": "RSA_OAEP_SHA256",
                                          "publicKey": "%s",
                                          "wrappingKeyAlgorithm": "TINK_ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM",
                                          "wrappingPublicKey": "%s"
                                        }
                                        """
                                                .formatted(
                                                        deviceId,
                                                        publicKey,
                                                        Base64.getEncoder()
                                                                .encodeToString(
                                                                        ("wrapping-" + deviceId)
                                                                                .getBytes(
                                                                                        StandardCharsets
                                                                                                .UTF_8)))))
                .andExpect(status().isCreated());
        return keyPair;
    }

    private void registerUser(String username) throws Exception {
        mvc.perform(
                        post("/api/v1/users")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        "{\"username\":\"%s\",\"password\":\"%s\"}"
                                                .formatted(username, PASSWORD)))
                .andExpect(status().isCreated());
    }

    private void createVault(String username, String vaultId) throws Exception {
        mvc.perform(
                        put("/api/v1/vaults/{vaultId}", vaultId)
                                .with(httpBasic(username, PASSWORD))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"encryptedMetadata\":\"opaque\"}"))
                .andExpect(status().isCreated());
    }

    private void declareCurrentVaultKey(String username, String vaultId, String vaultKeyId)
            throws Exception {
        mvc.perform(
                        put("/api/v1/vaults/{vaultId}/key-rotation", vaultId)
                                .with(httpBasic(username, PASSWORD))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"vaultKeyId\":\"%s\"}".formatted(vaultKeyId)))
                .andExpect(status().isNoContent());
    }

    private boolean databaseContainsToken(String token) {
        return transaction(
                () ->
                        entityManager
                                        .createQuery(
                                                "select count(s) from RecoverySessionEntity s where s.tokenHash = :token",
                                                Long.class)
                                        .setParameter("token", token)
                                        .getSingleResult()
                                != 0L);
    }

    private RecoveryAuthority sessionAuthority(String username) {
        return transaction(
                () ->
                        entityManager
                                .createQuery(
                                        "select s.authority from RecoverySessionEntity s where s.username = :username",
                                        RecoveryAuthority.class)
                                .setParameter("username", username)
                                .getSingleResult());
    }

    private long requestPackageCount(String requestId) {
        return transaction(
                () ->
                        entityManager
                                .createQuery(
                                        "select count(p) from RecoveryRequestVaultPackageEntity p where p.id.requestId = :requestId",
                                        Long.class)
                                .setParameter("requestId", requestId)
                                .getSingleResult());
    }

    private static KeyPair rsaKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static String signature(PrivateKey privateKey, byte[] payload) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(payload);
        return Base64.getEncoder().encodeToString(signature.sign());
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
