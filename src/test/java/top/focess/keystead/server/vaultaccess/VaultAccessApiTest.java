package top.focess.keystead.server.vaultaccess;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.jayway.jsonpath.JsonPath;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import top.focess.keystead.access.VaultAccessRequest;
import top.focess.keystead.access.VaultAccessRequestCodec;
import top.focess.keystead.crypto.DefaultCryptoService;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class VaultAccessApiTest {

    private static final String PASSWORD = "correct horse battery staple";
    private static final String REQUEST_ID = "550e8400-e29b-41d4-a716-446655440000";

    @Autowired private MockMvc mvc;

    @Test
    void loginSessionPublishesEphemeralRequestAndAnotherSessionApprovesTheDek() throws Exception {
        String username = "ephemeral-access-alice";
        byte[] publicKey = "one-login-only-public-key".getBytes(StandardCharsets.UTF_8);
        registerUser(username);

        String created = createRequest(username, publicKey);
        byte[] canonical =
                Base64.getUrlDecoder()
                        .decode((String) JsonPath.read(created, "$.canonicalRequest"));
        VaultAccessRequest decoded = VaultAccessRequestCodec.decode(canonical);
        assertEquals(username, decoded.accountId());
        assertEquals("https://vault.example", decoded.serverOrigin());
        assertArrayEquals(publicKey, decoded.exchangePublicKey());
        assertEquals(
                VaultAccessRequestCodec.fingerprint(decoded),
                JsonPath.read(created, "$.fingerprint"));

        mvc.perform(get("/api/v1/vault-access-requests").with(httpBasic(username, PASSWORD)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].requestId").value(REQUEST_ID))
                .andExpect(jsonPath("$[0].state").value("PENDING"));

        mvc.perform(
                        post("/api/v1/vault-access-requests/{requestId}/approve", REQUEST_ID)
                                .with(httpBasic(username, PASSWORD))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "vaultFingerprint":"6000000000000001",
                                          "vaultKeyId":"vault-key-current",
                                          "keyAlgorithm":"TINK_DEVICE_KEY_PACKAGE",
                                          "encryptedVaultKey":"opaque-encrypted-dek"
                                        }
                                        """))
                .andExpect(status().isNoContent());

        mvc.perform(
                        get("/api/v1/vault-access-requests/{requestId}", REQUEST_ID)
                                .with(httpBasic(username, PASSWORD)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.state").value("APPROVED"))
                .andExpect(jsonPath("$.approvedPackage.vaultFingerprint").value("6000000000000001"))
                .andExpect(jsonPath("$.approvedPackage.vaultKeyId").value("vault-key-current"))
                .andExpect(
                        jsonPath("$.approvedPackage.encryptedVaultKey")
                                .value("opaque-encrypted-dek"));
    }

    @Test
    void accessRequestNeedsOnlyAccountLoginAndEphemeralPublicMaterial() throws Exception {
        String username = "ephemeral-access-guards";
        registerUser(username);
        String body = requestBody("temporary-public-key".getBytes(StandardCharsets.UTF_8));

        mvc.perform(
                        post("/api/v1/vault-access-requests")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(body))
                .andExpect(status().isUnauthorized());

        mvc.perform(
                        post("/api/v1/vault-access-requests")
                                .with(httpBasic(username, PASSWORD))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(body))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.requestId").value(REQUEST_ID));
    }

    @Test
    void anotherAccountCannotSeeOrApproveTheRequest() throws Exception {
        String owner = "ephemeral-access-owner";
        String outsider = "ephemeral-access-outsider";
        registerUser(owner);
        registerUser(outsider);
        createRequest(owner, "owner-public-key".getBytes(StandardCharsets.UTF_8));

        mvc.perform(
                        get("/api/v1/vault-access-requests/{requestId}", REQUEST_ID)
                                .with(httpBasic(outsider, PASSWORD)))
                .andExpect(status().isNotFound());

        mvc.perform(
                        post("/api/v1/vault-access-requests/{requestId}/approve", REQUEST_ID)
                                .with(httpBasic(outsider, PASSWORD))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {"vaultFingerprint":"6000000000000001","vaultKeyId":"key","keyAlgorithm":"TINK_DEVICE_KEY_PACKAGE","encryptedVaultKey":"opaque"}
                                        """))
                .andExpect(status().isNotFound());
    }

    private String createRequest(String username, byte[] publicKey) throws Exception {
        return mvc.perform(
                        post("/api/v1/vault-access-requests")
                                .with(httpBasic(username, PASSWORD))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(requestBody(publicKey)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.fingerprint").isNotEmpty())
                .andReturn()
                .getResponse()
                .getContentAsString();
    }

    private static String requestBody(byte[] publicKey) {
        return """
                {
                  "requestId":"%s",
                  "serverOrigin":"https://vault.example",
                  "keyAlgorithm":"%s",
                  "exchangePublicKey":"%s"
                }
                """
                .formatted(
                        REQUEST_ID,
                        DefaultCryptoService.DEVICE_KEY_ALGORITHM,
                        Base64.getEncoder().encodeToString(publicKey));
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
}
