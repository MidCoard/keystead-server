package top.focess.keystead.server.auth;

import static org.hamcrest.Matchers.blankOrNullString;
import static org.hamcrest.Matchers.not;
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
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AuthApiTest {

    @Autowired private MockMvc mvc;

    @Test
    void loginReturnsTokensAndBearerTokenAuthenticatesApi() throws Exception {
        register("token-alice");

        MvcResult login =
                mvc.perform(
                                post("/api/v1/auth/login")
                                        .contentType(MediaType.APPLICATION_JSON)
                                        .content(
                                                """
                                                {
                                                  "username": "token-alice",
                                                  "password": "correct horse battery staple"
                                                }
                                                """))
                        .andExpect(status().isOk())
                        .andExpect(jsonPath("$.accessToken", not(blankOrNullString())))
                        .andExpect(jsonPath("$.refreshToken", not(blankOrNullString())))
                        .andExpect(jsonPath("$.accessTokenExpiresAt", not(blankOrNullString())))
                        .andExpect(jsonPath("$.refreshTokenExpiresAt", not(blankOrNullString())))
                        .andReturn();
        String accessToken = JsonStrings.field(login, "accessToken");

        mvc.perform(
                        put("/api/v1/vaults/token-vault")
                                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "encryptedMetadata": "opaque-vault-metadata"
                                        }
                                        """))
                .andExpect(status().isCreated());

        mvc.perform(
                        get("/api/v1/vaults")
                                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].vaultId").value("token-vault"));
    }

    @Test
    void refreshTokenCanRefreshThenBeRevoked() throws Exception {
        register("refresh-alice");
        String refreshToken = login("refresh-alice");

        mvc.perform(
                        post("/api/v1/auth/refresh")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(refreshBody(refreshToken)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken", not(blankOrNullString())))
                .andExpect(jsonPath("$.refreshToken").doesNotExist());

        mvc.perform(
                        post("/api/v1/auth/revoke")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(refreshBody(refreshToken)))
                .andExpect(status().isNoContent());

        mvc.perform(
                        post("/api/v1/auth/refresh")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(refreshBody(refreshToken)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void logoutAllRevokesAllUserRefreshTokens() throws Exception {
        register("logout-all-alice");
        MvcResult firstLogin = loginResult("logout-all-alice");
        MvcResult secondLogin = loginResult("logout-all-alice");
        String accessToken = JsonStrings.field(firstLogin, "accessToken");
        String firstRefreshToken = JsonStrings.field(firstLogin, "refreshToken");
        String secondRefreshToken = JsonStrings.field(secondLogin, "refreshToken");

        mvc.perform(
                        post("/api/v1/auth/logout-all")
                                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken))
                .andExpect(status().isNoContent());

        mvc.perform(
                        post("/api/v1/auth/refresh")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(refreshBody(firstRefreshToken)))
                .andExpect(status().isUnauthorized());
        mvc.perform(
                        post("/api/v1/auth/refresh")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(refreshBody(secondRefreshToken)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void logoutAllInvalidatesAlreadyIssuedAccessTokens() throws Exception {
        register("logout-access-alice");
        MvcResult firstLogin = loginResult("logout-access-alice");
        MvcResult secondLogin = loginResult("logout-access-alice");
        String logoutToken = JsonStrings.field(firstLogin, "accessToken");
        String staleAccessToken = JsonStrings.field(secondLogin, "accessToken");

        mvc.perform(
                        post("/api/v1/auth/logout-all")
                                .header(HttpHeaders.AUTHORIZATION, "Bearer " + logoutToken))
                .andExpect(status().isNoContent());

        mvc.perform(
                        get("/api/v1/vaults")
                                .header(HttpHeaders.AUTHORIZATION, "Bearer " + staleAccessToken))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void loginFailureIsGeneric() throws Exception {
        register("failed-login-alice");

        mvc.perform(
                        post("/api/v1/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "username": "failed-login-alice",
                                          "password": "wrong password value"
                                        }
                                        """))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Authentication failed"));
    }

    @Test
    void loginWithUnknownDeviceIdFailsGenerically() throws Exception {
        register("device-login-alice");

        mvc.perform(
                        post("/api/v1/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "username": "device-login-alice",
                                          "password": "correct horse battery staple",
                                          "deviceId": "missing-device"
                                        }
                                        """))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Authentication failed"));
    }

    @Test
    void deviceRevocationInvalidatesAlreadyIssuedDeviceAccessToken() throws Exception {
        register("device-token-alice");
        registerVerifiedDevice("device-token-alice", "phone-token");
        MvcResult login = loginResult("device-token-alice", "phone-token");
        String accessToken = JsonStrings.field(login, "accessToken");

        mvc.perform(
                        get("/api/v1/vaults")
                                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken))
                .andExpect(status().isOk());

        mvc.perform(
                        delete("/api/v1/devices/phone-token")
                                .header(
                                        HttpHeaders.AUTHORIZATION,
                                        "Basic "
                                                + Base64.getEncoder()
                                                        .encodeToString(
                                                                "device-token-alice:correct horse battery staple"
                                                                        .getBytes(
                                                                                StandardCharsets
                                                                                        .UTF_8))))
                .andExpect(status().isNoContent());

        mvc.perform(
                        get("/api/v1/vaults")
                                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void deviceRevocationRejectsDeviceBoundRefreshToken() throws Exception {
        register("device-refresh-alice");
        registerVerifiedDevice("device-refresh-alice", "phone-refresh");
        MvcResult login = loginResult("device-refresh-alice", "phone-refresh");
        String refreshToken = JsonStrings.field(login, "refreshToken");

        mvc.perform(
                        delete("/api/v1/devices/phone-refresh")
                                .header(
                                        HttpHeaders.AUTHORIZATION,
                                        basic(
                                                "device-refresh-alice",
                                                "correct horse battery staple")))
                .andExpect(status().isNoContent());

        mvc.perform(
                        post("/api/v1/auth/refresh")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(refreshBody(refreshToken)))
                .andExpect(status().isUnauthorized());
    }

    private void register(String username) throws Exception {
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

    private String login(String username) throws Exception {
        return JsonStrings.field(loginResult(username), "refreshToken");
    }

    private MvcResult loginResult(String username) throws Exception {
        return loginResult(username, null);
    }

    private MvcResult loginResult(String username, String deviceId) throws Exception {
        String deviceLine = deviceId == null ? "" : ",\n  \"deviceId\": \"%s\"".formatted(deviceId);
        return mvc.perform(
                        post("/api/v1/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "username": "%s",
                                          "password": "correct horse battery staple"%s
                                        }
                                        """
                                                .formatted(username, deviceLine)))
                .andExpect(status().isOk())
                .andReturn();
    }

    private void registerVerifiedDevice(String username, String deviceId) throws Exception {
        KeyPair keyPair = rsaKeyPair();
        mvc.perform(
                        post("/api/v1/devices")
                                .header(
                                        HttpHeaders.AUTHORIZATION,
                                        basic(username, "correct horse battery staple"))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "deviceId": "%s",
                                          "keyAlgorithm": "RSA_OAEP_SHA256",
                                          "publicKey": "%s"
                                        }
                                        """
                                                .formatted(
                                                        deviceId,
                                                        Base64.getEncoder()
                                                                .encodeToString(
                                                                        keyPair.getPublic()
                                                                                .getEncoded()))))
                .andExpect(status().isCreated());
        String challengeJson =
                mvc.perform(
                                post("/api/v1/devices/{deviceId}/challenges", deviceId)
                                        .header(
                                                HttpHeaders.AUTHORIZATION,
                                                basic(username, "correct horse battery staple")))
                        .andExpect(status().isCreated())
                        .andReturn()
                        .getResponse()
                        .getContentAsString();
        String challengeId = JsonPath.read(challengeJson, "$.challengeId");
        String nonce = JsonPath.read(challengeJson, "$.nonce");
        mvc.perform(
                        post("/api/v1/devices/{deviceId}/proof", deviceId)
                                .header(
                                        HttpHeaders.AUTHORIZATION,
                                        basic(username, "correct horse battery staple"))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "challengeId": "%s",
                                          "signature": "%s"
                                        }
                                        """
                                                .formatted(
                                                        challengeId,
                                                        signature(
                                                                keyPair.getPrivate(),
                                                                challengeId,
                                                                nonce))))
                .andExpect(status().isNoContent());
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

    private static String basic(String username, String password) {
        return "Basic "
                + Base64.getEncoder()
                        .encodeToString(
                                (username + ":" + password).getBytes(StandardCharsets.UTF_8));
    }

    private static String refreshBody(String refreshToken) {
        return """
                {
                  "refreshToken": "%s"
                }
                """
                .formatted(refreshToken);
    }
}
