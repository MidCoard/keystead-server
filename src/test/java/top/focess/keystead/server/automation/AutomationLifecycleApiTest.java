package top.focess.keystead.server.automation;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.jayway.jsonpath.JsonPath;
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
class AutomationLifecycleApiTest {

    @Autowired private MockMvc mvc;

    @Test
    void revokingPrincipalRejectsPreviouslyIssuedAutomationToken() throws Exception {
        String user = "automation-owner";
        String vault = "automation-vault";
        String principal = "build-agent";
        registerUser(user);
        createVault(user, vault);
        mvc.perform(
                        put(
                                        "/api/v1/vaults/{vault}/automation-principals/{principal}",
                                        vault,
                                        principal)
                                .with(httpBasic(user, "correct horse battery staple"))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        "{\"publicKeyAlgorithm\":\"RSA_OAEP_SHA256\",\"publicKey\":\"opaque-public-key\"}"))
                .andExpect(status().isCreated());
        mvc.perform(
                        put(
                                        "/api/v1/vaults/{vault}/automation-principals/{principal}/key-package",
                                        vault,
                                        principal)
                                .with(httpBasic(user, "correct horse battery staple"))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        "{\"vaultKeyId\":\"vault-key-2\",\"keyAlgorithm\":\"RSA_OAEP_SHA256\",\"encryptedVaultKey\":\"opaque-wrapped-key\"}"))
                .andExpect(status().isCreated());
        String response =
                mvc.perform(
                                post(
                                                "/api/v1/vaults/{vault}/automation-principals/{principal}/tokens",
                                                vault,
                                                principal)
                                        .with(httpBasic(user, "correct horse battery staple"))
                                        .contentType(MediaType.APPLICATION_JSON)
                                        .content(
                                                "{\"expiresAt\":\"2030-01-01T00:00:00Z\",\"scopes\":[\"READ_VAULT_KEY_PACKAGE\"]}"))
                        .andExpect(status().isOk())
                        .andReturn()
                        .getResponse()
                        .getContentAsString();
        String token = JsonPath.read(response, "$.token");
        mvc.perform(
                        get("/api/v1/automation/key-package")
                                .header("Authorization", "Automation " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.vaultKeyId").value("vault-key-2"));
        mvc.perform(
                        delete(
                                        "/api/v1/vaults/{vault}/automation-principals/{principal}",
                                        vault,
                                        principal)
                                .with(httpBasic(user, "correct horse battery staple")))
                .andExpect(status().isNoContent());
        mvc.perform(
                        get("/api/v1/automation/key-package")
                                .header("Authorization", "Automation " + token))
                .andExpect(status().isUnauthorized());
    }

    private void registerUser(String user) throws Exception {
        mvc.perform(
                        post("/api/v1/users")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        "{\"username\":\""
                                                + user
                                                + "\",\"password\":\"correct horse battery staple\"}"))
                .andExpect(status().isCreated());
    }

    private void createVault(String user, String vault) throws Exception {
        mvc.perform(
                        put("/api/v1/vaults/{vault}", vault)
                                .with(httpBasic(user, "correct horse battery staple"))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"encryptedMetadata\":\"opaque\"}"))
                .andExpect(status().isCreated());
    }
}
