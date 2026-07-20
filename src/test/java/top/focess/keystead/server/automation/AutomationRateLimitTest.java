package top.focess.keystead.server.automation;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.jayway.jsonpath.JsonPath;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

/**
 * Slice 8 rate limiting: a per-token ceiling on automation endpoint requests. The class sets a
 * tight ceiling (2/minute) via a dedicated property source so its own Spring context is isolated
 * from the default-context automation tests.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@TestPropertySource(properties = "keystead.automation.rate-limit-requests-per-minute=2")
class AutomationRateLimitTest {

    @Autowired private MockMvc mvc;

    @Test
    void overLimitRequestsAreThrottled() throws Exception {
        String user = "rate-limit-user";
        String vault = "rate-limit-vault";
        registerUser(user);
        createVault(user, vault);
        putPrincipal(user, vault, "agent");
        String token = issueToken(user, vault, "agent");
        mvc.perform(
                        get("/api/v1/automation/records")
                                .header("Authorization", "Automation " + token))
                .andExpect(status().isOk());
        mvc.perform(
                        get("/api/v1/automation/records")
                                .header("Authorization", "Automation " + token))
                .andExpect(status().isOk());
        mvc.perform(
                        get("/api/v1/automation/records")
                                .header("Authorization", "Automation " + token))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().string("Retry-After", "60"));
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

    private void putPrincipal(String user, String vault, String principal) throws Exception {
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
    }

    private String issueToken(String user, String vault, String principal) throws Exception {
        String expiresAt = Instant.now().plus(Duration.ofDays(30)).toString();
        MvcResult result =
                mvc.perform(
                                post(
                                                "/api/v1/vaults/{vault}/automation-principals/{principal}/tokens",
                                                vault,
                                                principal)
                                        .with(httpBasic(user, "correct horse battery staple"))
                                        .contentType(MediaType.APPLICATION_JSON)
                                        .content(
                                                "{\"expiresAt\":\""
                                                        + expiresAt
                                                        + "\",\"scopes\":[\"READ_ENCRYPTED_RECORDS\"]}"))
                        .andExpect(status().isOk())
                        .andReturn();
        return JsonPath.read(result.getResponse().getContentAsString(), "$.token");
    }
}
