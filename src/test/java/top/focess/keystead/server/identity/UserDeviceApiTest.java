package top.focess.keystead.server.identity;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.jayway.jsonpath.JsonPath;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class UserDeviceApiTest {

    @Autowired private MockMvc mvc;
    @Autowired private TombstoneCompactionEligibilityService compactionEligibility;

    @Test
    void userRegistrationCreatesBasicAuthIdentity() throws Exception {
        mvc.perform(
                        post("/api/v1/users")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "username": "auth-user",
                                          "password": "correct horse battery staple"
                                        }
                                        """))
                .andExpect(status().isCreated());

        mvc.perform(
                        get("/api/v1/devices")
                                .with(httpBasic("auth-user", "correct horse battery staple")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray());
    }

    @Test
    void verifiedDeviceCanAcknowledgePulledVaultRevision() throws Exception {
        String username = "device-sync-cursor-user";
        String password = "correct horse battery staple";
        registerUser(username);
        proveDeviceWithAlgorithm(
                username, "phone-sync-cursor", "RSA_OAEP_SHA256", rsaKeyPair(), "SHA256withRSA");
        mvc.perform(
                        put("/api/v1/vaults/vault-sync-cursor")
                                .with(httpBasic(username, password))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"encryptedMetadata\":\"opaque-vault-metadata\"}"))
                .andExpect(status().isCreated());

        mvc.perform(
                        put("/api/v1/devices/phone-sync-cursor/vaults/vault-sync-cursor/sync-cursor")
                                .with(httpBasic(username, password))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"pulledRevision\":7}"))
                .andExpect(status().isNoContent());
    }

    @Test
    void deviceSyncCursorCannotMoveBackwards() throws Exception {
        String username = "device-sync-cursor-monotonic-user";
        String password = "correct horse battery staple";
        String deviceId = "phone-sync-cursor-monotonic";
        String vaultId = "vault-sync-cursor-monotonic";
        registerUser(username);
        proveDeviceWithAlgorithm(
                username, deviceId, "RSA_OAEP_SHA256", rsaKeyPair(), "SHA256withRSA");
        createVault(username, password, vaultId);
        acknowledgePulledRevision(username, password, deviceId, vaultId, 7)
                .andExpect(status().isNoContent());

        acknowledgePulledRevision(username, password, deviceId, vaultId, 6)
                .andExpect(status().isBadRequest());
    }

    @Test
    void deviceSyncCursorAcknowledgementIsIdempotent() throws Exception {
        String username = "device-sync-cursor-idempotent-user";
        String password = "correct horse battery staple";
        String deviceId = "phone-sync-cursor-idempotent";
        String vaultId = "vault-sync-cursor-idempotent";
        registerUser(username);
        proveDeviceWithAlgorithm(
                username, deviceId, "RSA_OAEP_SHA256", rsaKeyPair(), "SHA256withRSA");
        createVault(username, password, vaultId);

        acknowledgePulledRevision(username, password, deviceId, vaultId, 7)
                .andExpect(status().isNoContent());
        acknowledgePulledRevision(username, password, deviceId, vaultId, 7)
                .andExpect(status().isNoContent());
    }

    @Test
    void unverifiedDeviceCannotAcknowledgePulledVaultRevision() throws Exception {
        String username = "device-sync-cursor-unverified-user";
        String password = "correct horse battery staple";
        String deviceId = "phone-sync-cursor-unverified";
        String vaultId = "vault-sync-cursor-unverified";
        registerUser(username);
        registerDevice(username, deviceId, "RSA_OAEP_SHA256", "public-key-material");
        createVault(username, password, vaultId);

        acknowledgePulledRevision(username, password, deviceId, vaultId, 7)
                .andExpect(status().isNotFound());
    }

    @Test
    void vaultOwnerBoundaryIsCheckedBeforeDeviceCursorRequestValidation() throws Exception {
        String alice = "device-sync-cursor-owner-alice";
        String bob = "device-sync-cursor-owner-bob";
        String password = "correct horse battery staple";
        registerUser(alice);
        createVault(alice, password, "vault-sync-cursor-owner-private");
        registerUser(bob);

        mvc.perform(
                        put("/api/v1/devices/device-not-owned/vaults/vault-sync-cursor-owner-private/sync-cursor")
                                .with(httpBasic(bob, password))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"pulledRevision\":-1}"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.pulledRevision").doesNotExist());
    }

    @Test
    void tombstoneEligibilityRequiresEveryActiveDeviceToAcknowledgeRevision() throws Exception {
        String username = "tombstone-eligibility-user";
        String password = "correct horse battery staple";
        String vaultId = "vault-tombstone-eligibility";
        String laptop = "laptop-tombstone-eligibility";
        String phone = "phone-tombstone-eligibility";
        registerUser(username);
        proveDeviceWithAlgorithm(
                username, laptop, "RSA_OAEP_SHA256", rsaKeyPair(), "SHA256withRSA");
        proveDeviceWithAlgorithm(username, phone, "RSA_OAEP_SHA256", rsaKeyPair(), "SHA256withRSA");
        createVault(username, password, vaultId);
        acknowledgePulledRevision(username, password, laptop, vaultId, 8)
                .andExpect(status().isNoContent());
        acknowledgePulledRevision(username, password, phone, vaultId, 7)
                .andExpect(status().isNoContent());

        assertTrue(compactionEligibility.isEligible(username, vaultId, 7L));
        assertFalse(compactionEligibility.isEligible(username, vaultId, 8L));
    }

    @Test
    void revokedDeviceDoesNotBlockTombstoneEligibility() throws Exception {
        String username = "tombstone-eligibility-revoked-user";
        String password = "correct horse battery staple";
        String vaultId = "vault-tombstone-eligibility-revoked";
        String laptop = "laptop-tombstone-eligibility-revoked";
        String phone = "phone-tombstone-eligibility-revoked";
        registerUser(username);
        proveDeviceWithAlgorithm(
                username, laptop, "RSA_OAEP_SHA256", rsaKeyPair(), "SHA256withRSA");
        proveDeviceWithAlgorithm(username, phone, "RSA_OAEP_SHA256", rsaKeyPair(), "SHA256withRSA");
        createVault(username, password, vaultId);
        acknowledgePulledRevision(username, password, laptop, vaultId, 7)
                .andExpect(status().isNoContent());

        mvc.perform(delete("/api/v1/devices/{deviceId}", phone).with(httpBasic(username, password)))
                .andExpect(status().isNoContent());

        assertTrue(compactionEligibility.isEligible(username, vaultId, 7L));
    }

    @Test
    void duplicateUserRegistrationIsConflict() throws Exception {
        String body =
                """
                {
                  "username": "duplicate-user",
                  "password": "correct horse battery staple"
                }
                """;

        mvc.perform(post("/api/v1/users").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isCreated());

        mvc.perform(post("/api/v1/users").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isConflict());
    }

    @Test
    void duplicateUserRegistrationDoesNotValidateReplacementPassword() throws Exception {
        registerUser("duplicate-shape-user");

        mvc.perform(
                        post("/api/v1/users")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "username": "duplicate-shape-user",
                                          "password": ""
                                        }
                                        """))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.password").doesNotExist());
    }

    @Test
    void authenticatedUserCanRegisterAndListDevicePublicKeys() throws Exception {
        registerUser("device-user");

        mvc.perform(
                        post("/api/v1/devices")
                                .with(httpBasic("device-user", "correct horse battery staple"))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "deviceId": "phone-1",
                                          "keyAlgorithm": "RSA_OAEP_SHA256",
                                          "publicKey": "public-key-material"
                                        }
                                        """))
                .andExpect(status().isCreated());

        mvc.perform(
                        get("/api/v1/devices")
                                .with(httpBasic("device-user", "correct horse battery staple")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].deviceId").value("phone-1"))
                .andExpect(jsonPath("$[0].keyAlgorithm").value("RSA_OAEP_SHA256"))
                .andExpect(jsonPath("$[0].publicKey").value("public-key-material"))
                .andExpect(jsonPath("$[0].verifiedAt").doesNotExist());
    }

    @Test
    void duplicateDeviceRegistrationIsConflictAndKeepsOriginalPublicKey() throws Exception {
        registerUser("device-duplicate-user");
        registerDevice(
                "device-duplicate-user",
                "phone-duplicate",
                "RSA_OAEP_SHA256",
                "original-public-key");

        mvc.perform(
                        post("/api/v1/devices")
                                .with(
                                        httpBasic(
                                                "device-duplicate-user",
                                                "correct horse battery staple"))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "deviceId": "phone-duplicate",
                                          "keyAlgorithm": "RSA_OAEP_SHA256",
                                          "publicKey": "replacement-public-key"
                                        }
                                        """))
                .andExpect(status().isConflict());

        mvc.perform(
                        get("/api/v1/devices")
                                .with(
                                        httpBasic(
                                                "device-duplicate-user",
                                                "correct horse battery staple")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].deviceId").value("phone-duplicate"))
                .andExpect(jsonPath("$[0].publicKey").value("original-public-key"));
    }

    @Test
    void duplicateDeviceRegistrationDoesNotValidateReplacementBody() throws Exception {
        registerUser("device-duplicate-shape-user");
        registerDevice(
                "device-duplicate-shape-user",
                "phone-duplicate-shape",
                "RSA_OAEP_SHA256",
                "original-public-key");

        mvc.perform(
                        post("/api/v1/devices")
                                .with(
                                        httpBasic(
                                                "device-duplicate-shape-user",
                                                "correct horse battery staple"))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "deviceId": "phone-duplicate-shape",
                                          "keyAlgorithm": "",
                                          "publicKey": "%s"
                                        }
                                        """
                                                .formatted("x".repeat(16_385))))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.keyAlgorithm").doesNotExist())
                .andExpect(jsonPath("$.publicKey").doesNotExist());

        mvc.perform(
                        get("/api/v1/devices")
                                .with(
                                        httpBasic(
                                                "device-duplicate-shape-user",
                                                "correct horse battery staple")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].deviceId").value("phone-duplicate-shape"))
                .andExpect(jsonPath("$[0].publicKey").value("original-public-key"));
    }

    @Test
    void deviceChallengeProofMarksDeviceVerified() throws Exception {
        registerUser("device-proof-user");
        KeyPair keyPair = rsaKeyPair();
        registerDevice(
                "device-proof-user",
                "phone-proof",
                "RSA_OAEP_SHA256",
                Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));

        String challengeJson =
                mvc.perform(
                                post("/api/v1/devices/phone-proof/challenges")
                                        .with(
                                                httpBasic(
                                                        "device-proof-user",
                                                        "correct horse battery staple")))
                        .andExpect(status().isCreated())
                        .andExpect(jsonPath("$.deviceId").value("phone-proof"))
                        .andExpect(jsonPath("$.challengeId").isNotEmpty())
                        .andExpect(jsonPath("$.nonce").isNotEmpty())
                        .andExpect(jsonPath("$.expiresAt").isNotEmpty())
                        .andReturn()
                        .getResponse()
                        .getContentAsString();

        String challengeId = JsonPath.read(challengeJson, "$.challengeId");
        String nonce = JsonPath.read(challengeJson, "$.nonce");
        String signature = signature(keyPair.getPrivate(), challengeId, nonce);

        mvc.perform(
                        post("/api/v1/devices/phone-proof/proof")
                                .with(
                                        httpBasic(
                                                "device-proof-user",
                                                "correct horse battery staple"))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "challengeId": "%s",
                                          "signature": "%s"
                                        }
                                        """
                                                .formatted(challengeId, signature)))
                .andExpect(status().isNoContent());

        String devicesJson =
                mvc.perform(
                                get("/api/v1/devices")
                                        .with(
                                                httpBasic(
                                                        "device-proof-user",
                                                        "correct horse battery staple")))
                        .andExpect(status().isOk())
                        .andExpect(jsonPath("$[0].deviceId").value("phone-proof"))
                        .andExpect(jsonPath("$[0].verifiedAt").isNotEmpty())
                        .andReturn()
                        .getResponse()
                        .getContentAsString();
        assertNotNull(JsonPath.read(devicesJson, "$[0].verifiedAt"));
    }

    @Test
    void wrongDeviceChallengeSignatureIsRejected() throws Exception {
        registerUser("device-proof-reject-user");
        KeyPair registeredKeyPair = rsaKeyPair();
        KeyPair wrongKeyPair = rsaKeyPair();
        registerDevice(
                "device-proof-reject-user",
                "phone-proof-reject",
                "RSA_OAEP_SHA256",
                Base64.getEncoder().encodeToString(registeredKeyPair.getPublic().getEncoded()));

        String challengeJson =
                mvc.perform(
                                post("/api/v1/devices/phone-proof-reject/challenges")
                                        .with(
                                                httpBasic(
                                                        "device-proof-reject-user",
                                                        "correct horse battery staple")))
                        .andExpect(status().isCreated())
                        .andReturn()
                        .getResponse()
                        .getContentAsString();

        String challengeId = JsonPath.read(challengeJson, "$.challengeId");
        String nonce = JsonPath.read(challengeJson, "$.nonce");
        String signature = signature(wrongKeyPair.getPrivate(), challengeId, nonce);

        mvc.perform(
                        post("/api/v1/devices/phone-proof-reject/proof")
                                .with(
                                        httpBasic(
                                                "device-proof-reject-user",
                                                "correct horse battery staple"))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "challengeId": "%s",
                                          "signature": "%s"
                                        }
                                        """
                                                .formatted(challengeId, signature)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void unauthorizedDeviceProofDoesNotValidateRequestBodyBeforeOwnership() throws Exception {
        registerUser("device-proof-shape-alice");
        registerUser("device-proof-shape-bob");
        registerDevice(
                "device-proof-shape-alice",
                "phone-proof-shape-private",
                "RSA_OAEP_SHA256",
                "alice-public-key-material");

        mvc.perform(
                        post("/api/v1/devices/phone-proof-shape-private/proof")
                                .with(
                                        httpBasic(
                                                "device-proof-shape-bob",
                                                "correct horse battery staple"))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "challengeId": "",
                                          "signature": "%s"
                                        }
                                        """
                                                .formatted("x".repeat(8193))))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.challengeId").doesNotExist())
                .andExpect(jsonPath("$.signature").doesNotExist());
    }

    @Test
    void revokedDeviceIsListedAsRevokedAndCannotStartNewChallenge() throws Exception {
        registerUser("device-revoke-user");
        proveDeviceWithAlgorithm(
                "device-revoke-user",
                "phone-revoke",
                "RSA_OAEP_SHA256",
                rsaKeyPair(),
                "SHA256withRSA");

        mvc.perform(
                        delete("/api/v1/devices/phone-revoke")
                                .with(
                                        httpBasic(
                                                "device-revoke-user",
                                                "correct horse battery staple")))
                .andExpect(status().isNoContent());

        mvc.perform(
                        get("/api/v1/devices")
                                .with(
                                        httpBasic(
                                                "device-revoke-user",
                                                "correct horse battery staple")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].deviceId").value("phone-revoke"))
                .andExpect(jsonPath("$[0].revokedAt").isNotEmpty());

        mvc.perform(
                        post("/api/v1/devices/phone-revoke/challenges")
                                .with(
                                        httpBasic(
                                                "device-revoke-user",
                                                "correct horse battery staple")))
                .andExpect(status().isNotFound());
    }

    @Test
    void revokedDeviceCannotBeReRegisteredToClearRevocation() throws Exception {
        registerUser("device-reregister-user");
        proveDeviceWithAlgorithm(
                "device-reregister-user",
                "phone-reregister",
                "RSA_OAEP_SHA256",
                rsaKeyPair(),
                "SHA256withRSA");

        mvc.perform(
                        delete("/api/v1/devices/phone-reregister")
                                .with(
                                        httpBasic(
                                                "device-reregister-user",
                                                "correct horse battery staple")))
                .andExpect(status().isNoContent());

        KeyPair replacementKeyPair = rsaKeyPair();
        mvc.perform(
                        post("/api/v1/devices")
                                .with(
                                        httpBasic(
                                                "device-reregister-user",
                                                "correct horse battery staple"))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "deviceId": "phone-reregister",
                                          "keyAlgorithm": "RSA_OAEP_SHA256",
                                          "publicKey": "%s"
                                        }
                                        """
                                                .formatted(
                                                        Base64.getEncoder()
                                                                .encodeToString(
                                                                        replacementKeyPair
                                                                                .getPublic()
                                                                                .getEncoded()))))
                .andExpect(status().isConflict());

        mvc.perform(
                        get("/api/v1/devices")
                                .with(
                                        httpBasic(
                                                "device-reregister-user",
                                                "correct horse battery staple")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].deviceId").value("phone-reregister"))
                .andExpect(jsonPath("$[0].revokedAt").isNotEmpty());
    }

    @Test
    void deviceChallengeProofAcceptsMainstreamSigningAlgorithms() throws Exception {
        registerUser("device-proof-algorithms");

        proveDeviceWithAlgorithm(
                "device-proof-algorithms",
                "phone-ecdsa",
                "ECDSA_P256_SHA256",
                ecdsaKeyPair("secp256r1"),
                "SHA256withECDSA");
        proveDeviceWithAlgorithm(
                "device-proof-algorithms",
                "phone-rsa-pss",
                "RSA_PSS_SHA256",
                rsaKeyPair(),
                "RSASSA-PSS");
        proveDeviceWithAlgorithm(
                "device-proof-algorithms", "phone-ed25519", "ED25519", ed25519KeyPair(), "Ed25519");

        mvc.perform(
                        get("/api/v1/devices")
                                .with(
                                        httpBasic(
                                                "device-proof-algorithms",
                                                "correct horse battery staple")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].verifiedAt").isNotEmpty())
                .andExpect(jsonPath("$[1].verifiedAt").isNotEmpty())
                .andExpect(jsonPath("$[2].verifiedAt").isNotEmpty());
    }

    @Test
    void oversizedDevicePublicKeyIsRejected() throws Exception {
        registerUser("device-sized-user");
        String oversized = "x".repeat(16_385);

        mvc.perform(
                        post("/api/v1/devices")
                                .with(
                                        httpBasic(
                                                "device-sized-user",
                                                "correct horse battery staple"))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "deviceId": "phone-oversized",
                                          "keyAlgorithm": "RSA_OAEP_SHA256",
                                          "publicKey": "%s"
                                        }
                                        """
                                                .formatted(oversized)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void unsupportedDeviceKeyAlgorithmIsRejected() throws Exception {
        registerUser("device-unsupported-algorithm-user");

        mvc.perform(
                        post("/api/v1/devices")
                                .with(
                                        httpBasic(
                                                "device-unsupported-algorithm-user",
                                                "correct horse battery staple"))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "deviceId": "phone-unsupported",
                                          "keyAlgorithm": "RAW_RSA",
                                          "publicKey": "public-key-material"
                                        }
                                        """))
                .andExpect(status().isBadRequest());
    }

    private void registerUser(String username) throws Exception {
        mvc.perform(
                        post("/api/v1/users")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "username": "%s",
                                          "password": "correct horse battery staple"
                                        }
                                        """
                                                .formatted(username)))
                .andExpect(status().isCreated());
    }

    private void createVault(String username, String password, String vaultId) throws Exception {
        mvc.perform(
                        put("/api/v1/vaults/{vaultId}", vaultId)
                                .with(httpBasic(username, password))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"encryptedMetadata\":\"opaque-vault-metadata\"}"))
                .andExpect(status().isCreated());
    }

    private org.springframework.test.web.servlet.ResultActions acknowledgePulledRevision(
            String username, String password, String deviceId, String vaultId, long pulledRevision)
            throws Exception {
        return mvc.perform(
                put("/api/v1/devices/{deviceId}/vaults/{vaultId}/sync-cursor", deviceId, vaultId)
                        .with(httpBasic(username, password))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"pulledRevision\":%d}".formatted(pulledRevision)));
    }

    private void registerDevice(
            String username, String deviceId, String keyAlgorithm, String publicKey)
            throws Exception {
        mvc.perform(
                        post("/api/v1/devices")
                                .with(httpBasic(username, "correct horse battery staple"))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "deviceId": "%s",
                                          "keyAlgorithm": "%s",
                                          "publicKey": "%s"
                                        }
                                        """
                                                .formatted(deviceId, keyAlgorithm, publicKey)))
                .andExpect(status().isCreated());
    }

    private void proveDeviceWithAlgorithm(
            String username,
            String deviceId,
            String keyAlgorithm,
            KeyPair keyPair,
            String signatureAlgorithm)
            throws Exception {
        registerDevice(
                username,
                deviceId,
                keyAlgorithm,
                Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
        String challengeJson =
                mvc.perform(
                                post("/api/v1/devices/{deviceId}/challenges", deviceId)
                                        .with(httpBasic(username, "correct horse battery staple")))
                        .andExpect(status().isCreated())
                        .andReturn()
                        .getResponse()
                        .getContentAsString();
        String challengeId = JsonPath.read(challengeJson, "$.challengeId");
        String nonce = JsonPath.read(challengeJson, "$.nonce");
        String signature = signature(keyPair.getPrivate(), challengeId, nonce, signatureAlgorithm);
        mvc.perform(
                        post("/api/v1/devices/{deviceId}/proof", deviceId)
                                .with(httpBasic(username, "correct horse battery staple"))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "challengeId": "%s",
                                          "signature": "%s"
                                        }
                                        """
                                                .formatted(challengeId, signature)))
                .andExpect(status().isNoContent());
    }

    private static KeyPair rsaKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static KeyPair ecdsaKeyPair(String curveName) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec(curveName));
        return generator.generateKeyPair();
    }

    private static KeyPair ed25519KeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519");
        return generator.generateKeyPair();
    }

    private static String signature(PrivateKey privateKey, String challengeId, String nonce)
            throws Exception {
        return signature(privateKey, challengeId, nonce, "SHA256withRSA");
    }

    private static String signature(
            PrivateKey privateKey, String challengeId, String nonce, String algorithm)
            throws Exception {
        Signature signature = Signature.getInstance(algorithm);
        if ("RSASSA-PSS".equals(algorithm)) {
            signature.setParameter(rsaPssSha256Parameters());
        }
        signature.initSign(privateKey);
        signature.update(proofPayload(challengeId, nonce).getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(signature.sign());
    }

    private static PSSParameterSpec rsaPssSha256Parameters() {
        return new PSSParameterSpec(
                "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, PSSParameterSpec.TRAILER_FIELD_BC);
    }

    private static String proofPayload(String challengeId, String nonce) {
        return "keystead-device-proof:v1:" + challengeId + ":" + nonce;
    }
}
