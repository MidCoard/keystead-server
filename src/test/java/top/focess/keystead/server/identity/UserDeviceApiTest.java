package top.focess.keystead.server.identity;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.jayway.jsonpath.JsonPath;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
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
    void deviceChallengeProofAcceptsMainstreamSigningAlgorithms() throws Exception {
        registerUser("device-proof-algorithms");

        proveDeviceWithAlgorithm(
                "device-proof-algorithms",
                "phone-ecdsa",
                "ECDSA_P256_SHA256",
                ecdsaKeyPair("secp256r1"),
                "SHA256withECDSA");
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
                .andExpect(jsonPath("$[1].verifiedAt").isNotEmpty());
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
        signature.initSign(privateKey);
        signature.update(proofPayload(challengeId, nonce).getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(signature.sign());
    }

    private static String proofPayload(String challengeId, String nonce) {
        return "keystead-device-proof:v1:" + challengeId + ":" + nonce;
    }
}
