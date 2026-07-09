package top.focess.keystead.server.vault;

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
class VaultKeyPackageApiTest {

    @Autowired private MockMvc mvc;

    @Test
    void authenticatedUserCanStoreAndListDeviceVaultKeyPackages() throws Exception {
        registerUser("package-alice");
        registerVerifiedDevice("package-alice", "laptop-1");
        createVault("package-alice", "package-vault-a");

        mvc.perform(
                        put("/api/v1/vaults/package-vault-a/key-packages/laptop-1")
                                .with(httpBasic("package-alice", "correct horse battery staple"))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "keyAlgorithm": "RSA_OAEP_SHA256",
                                          "encryptedVaultKey": "opaque-device-wrapped-vault-key"
                                        }
                                        """))
                .andExpect(status().isCreated());

        mvc.perform(
                        get("/api/v1/vaults/package-vault-a/key-packages")
                                .with(httpBasic("package-alice", "correct horse battery staple")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].vaultId").value("package-vault-a"))
                .andExpect(jsonPath("$[0].deviceId").value("laptop-1"))
                .andExpect(jsonPath("$[0].keyAlgorithm").value("RSA_OAEP_SHA256"))
                .andExpect(
                        jsonPath("$[0].encryptedVaultKey")
                                .value("opaque-device-wrapped-vault-key"));
    }

    @Test
    void tinkEciesVaultKeyPackageAlgorithmIsAccepted() throws Exception {
        registerUser("package-tink-ecies");
        registerVerifiedDevice("package-tink-ecies", "laptop-1");
        createVault("package-tink-ecies", "package-vault-tink-ecies");

        mvc.perform(
                        put("/api/v1/vaults/package-vault-tink-ecies/key-packages/laptop-1")
                                .with(
                                        httpBasic(
                                                "package-tink-ecies",
                                                "correct horse battery staple"))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "keyAlgorithm": "TINK_ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM",
                                          "encryptedVaultKey": "opaque-device-wrapped-vault-key"
                                        }
                                        """))
                .andExpect(status().isCreated());

        mvc.perform(
                        get("/api/v1/vaults/package-vault-tink-ecies/key-packages")
                                .with(
                                        httpBasic(
                                                "package-tink-ecies",
                                                "correct horse battery staple")))
                .andExpect(status().isOk())
                .andExpect(
                        jsonPath("$[0].keyAlgorithm")
                                .value("TINK_ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM"));
    }

    @Test
    void oversizedVaultKeyPackageIsRejected() throws Exception {
        registerUser("package-sized");
        registerVerifiedDevice("package-sized", "laptop-1");
        createVault("package-sized", "package-vault-sized");
        String oversized = "x".repeat(16_385);

        mvc.perform(
                        put("/api/v1/vaults/package-vault-sized/key-packages/laptop-1")
                                .with(httpBasic("package-sized", "correct horse battery staple"))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "keyAlgorithm": "RSA_OAEP_SHA256",
                                          "encryptedVaultKey": "%s"
                                        }
                                        """
                                                .formatted(oversized)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void unsupportedVaultKeyPackageAlgorithmIsRejected() throws Exception {
        registerUser("package-unsupported-algorithm");
        registerVerifiedDevice("package-unsupported-algorithm", "laptop-1");
        createVault("package-unsupported-algorithm", "package-vault-unsupported-algorithm");

        mvc.perform(
                        put("/api/v1/vaults/package-vault-unsupported-algorithm/key-packages/laptop-1")
                                .with(
                                        httpBasic(
                                                "package-unsupported-algorithm",
                                                "correct horse battery staple"))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "keyAlgorithm": "RAW_RSA",
                                          "encryptedVaultKey": "opaque-device-wrapped-vault-key"
                                        }
                                        """))
                .andExpect(status().isBadRequest());
    }

    @Test
    void keyPackageRequiresOwnedVaultAndRegisteredDevice() throws Exception {
        registerUser("package-owner");
        createVault("package-owner", "package-vault-owned");

        mvc.perform(
                        put("/api/v1/vaults/package-vault-owned/key-packages/missing-device")
                                .with(httpBasic("package-owner", "correct horse battery staple"))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(packageBody()))
                .andExpect(status().isNotFound());

        registerDevice("package-owner", "laptop-1");

        mvc.perform(
                        put("/api/v1/vaults/missing-vault/key-packages/laptop-1")
                                .with(httpBasic("package-owner", "correct horse battery staple"))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(packageBody()))
                .andExpect(status().isNotFound());
    }

    @Test
    void keyPackageRequiresVerifiedDevice() throws Exception {
        registerUser("package-unverified");
        registerDevice("package-unverified", "unverified-laptop");
        createVault("package-unverified", "package-vault-unverified");

        mvc.perform(
                        put("/api/v1/vaults/package-vault-unverified/key-packages/unverified-laptop")
                                .with(
                                        httpBasic(
                                                "package-unverified",
                                                "correct horse battery staple"))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(packageBody()))
                .andExpect(status().isNotFound());

        mvc.perform(
                        get("/api/v1/vaults/package-vault-unverified/key-packages")
                                .with(
                                        httpBasic(
                                                "package-unverified",
                                                "correct horse battery staple")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isEmpty());
    }

    @Test
    void keyPackageRequiresNonRevokedDevice() throws Exception {
        registerUser("package-revoked");
        registerVerifiedDevice("package-revoked", "revoked-laptop");
        createVault("package-revoked", "package-vault-revoked");

        mvc.perform(
                        delete("/api/v1/devices/revoked-laptop")
                                .with(httpBasic("package-revoked", "correct horse battery staple")))
                .andExpect(status().isNoContent());

        mvc.perform(
                        put("/api/v1/vaults/package-vault-revoked/key-packages/revoked-laptop")
                                .with(httpBasic("package-revoked", "correct horse battery staple"))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(packageBody()))
                .andExpect(status().isNotFound());

        mvc.perform(
                        get("/api/v1/vaults/package-vault-revoked/key-packages")
                                .with(httpBasic("package-revoked", "correct horse battery staple")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isEmpty());
    }

    @Test
    void userCannotReadAnotherUsersVaultKeyPackages() throws Exception {
        registerUser("package-alice-private");
        registerUser("package-bob-private");
        registerVerifiedDevice("package-alice-private", "laptop-1");
        createVault("package-alice-private", "package-vault-private");

        mvc.perform(
                        put("/api/v1/vaults/package-vault-private/key-packages/laptop-1")
                                .with(
                                        httpBasic(
                                                "package-alice-private",
                                                "correct horse battery staple"))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(packageBody()))
                .andExpect(status().isCreated());

        mvc.perform(
                        get("/api/v1/vaults/package-vault-private/key-packages")
                                .with(
                                        httpBasic(
                                                "package-bob-private",
                                                "correct horse battery staple")))
                .andExpect(status().isNotFound());
    }

    @Test
    void userCannotPublishVaultKeyPackageForAnotherUsersVault() throws Exception {
        registerUser("package-alice-write-private");
        registerUser("package-bob-write-private");
        registerDevice("package-alice-write-private", "alice-laptop");
        registerDevice("package-bob-write-private", "bob-laptop");
        createVault("package-alice-write-private", "vault-write-private");

        mvc.perform(
                        put("/api/v1/vaults/vault-write-private/key-packages/bob-laptop")
                                .with(
                                        httpBasic(
                                                "package-bob-write-private",
                                                "correct horse battery staple"))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(packageBody()))
                .andExpect(status().isNotFound());

        mvc.perform(
                        get("/api/v1/vaults/vault-write-private/key-packages")
                                .with(
                                        httpBasic(
                                                "package-alice-write-private",
                                                "correct horse battery staple")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isEmpty());
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

    private void registerDevice(String username, String deviceId) throws Exception {
        mvc.perform(
                        post("/api/v1/devices")
                                .with(httpBasic(username, "correct horse battery staple"))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "deviceId": "%s",
                                          "keyAlgorithm": "RSA_OAEP_SHA256",
                                          "publicKey": "public-key-material"
                                        }
                                        """
                                                .formatted(deviceId)))
                .andExpect(status().isCreated());
    }

    private void registerVerifiedDevice(String username, String deviceId) throws Exception {
        KeyPair keyPair = rsaKeyPair();
        registerDevice(
                username,
                deviceId,
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
        String signature = signature(keyPair.getPrivate(), challengeId, nonce);
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

    private void registerDevice(String username, String deviceId, String publicKey)
            throws Exception {
        mvc.perform(
                        post("/api/v1/devices")
                                .with(httpBasic(username, "correct horse battery staple"))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "deviceId": "%s",
                                          "keyAlgorithm": "RSA_OAEP_SHA256",
                                          "publicKey": "%s"
                                        }
                                        """
                                                .formatted(deviceId, publicKey)))
                .andExpect(status().isCreated());
    }

    private void createVault(String username, String vaultId) throws Exception {
        mvc.perform(
                        put("/api/v1/vaults/{vaultId}", vaultId)
                                .with(httpBasic(username, "correct horse battery staple"))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "encryptedMetadata": "opaque-vault-metadata"
                                        }
                                        """))
                .andExpect(status().isCreated());
    }

    private String packageBody() {
        return """
        {
          "keyAlgorithm": "RSA_OAEP_SHA256",
          "encryptedVaultKey": "opaque-device-wrapped-vault-key"
        }
        """;
    }

    private static KeyPair rsaKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static String signature(PrivateKey privateKey, String challengeId, String nonce)
            throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(proofPayload(challengeId, nonce).getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(signature.sign());
    }

    private static String proofPayload(String challengeId, String nonce) {
        return "keystead-device-proof:v1:" + challengeId + ":" + nonce;
    }
}
