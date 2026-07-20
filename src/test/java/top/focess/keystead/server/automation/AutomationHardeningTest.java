package top.focess.keystead.server.automation;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
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
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

/**
 * Slice 8 automation hardening: bounded TTL ceiling, token ids + listing, revoke-by-id, and
 * per-secret grants. The test profile sets a lenient {@code token-max-ttl} of P3650D so the
 * boundary tests use dates comfortably inside/outside that window regardless of the wall clock.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AutomationHardeningTest {

    @Autowired private MockMvc mvc;

    @Test
    void ttlCeilingRejectsExpiryBeyondMax() throws Exception {
        String user = "hardening-ttl-reject";
        String vault = "vault-ttl-reject";
        registerUser(user);
        createVault(user, vault);
        putPrincipal(user, vault, "agent");
        String beyondMax = Instant.now().plus(Duration.ofDays(365L * 11)).toString();
        mvc.perform(
                        post(
                                        "/api/v1/vaults/{vault}/automation-principals/{principal}/tokens",
                                        vault,
                                        "agent")
                                .with(httpBasic(user, "correct horse battery staple"))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        tokenRequestBody(
                                                beyondMax, "READ_VAULT_KEY_PACKAGE", null)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void ttlCeilingAcceptsExpiryWithinMax() throws Exception {
        String user = "hardening-ttl-accept";
        String vault = "vault-ttl-accept";
        registerUser(user);
        createVault(user, vault);
        putPrincipal(user, vault, "agent");
        String withinMax = Instant.now().plus(Duration.ofDays(365L * 5)).toString();
        mvc.perform(
                        post(
                                        "/api/v1/vaults/{vault}/automation-principals/{principal}/tokens",
                                        vault,
                                        "agent")
                                .with(httpBasic(user, "correct horse battery staple"))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        tokenRequestBody(
                                                withinMax, "READ_VAULT_KEY_PACKAGE", null)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.tokenId").isNotEmpty());
    }

    @Test
    void listTokensReturnsIssuedTokenId() throws Exception {
        String user = "hardening-list";
        String vault = "vault-list";
        registerUser(user);
        createVault(user, vault);
        putPrincipal(user, vault, "agent");
        IssuedToken issued = issueToken(user, vault, "agent", "READ_VAULT_KEY_PACKAGE", null);
        mvc.perform(
                        get(
                                        "/api/v1/vaults/{vault}/automation-principals/{principal}/tokens",
                                        vault,
                                        "agent")
                                .with(httpBasic(user, "correct horse battery staple")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].tokenId").value(issued.tokenId()))
                .andExpect(jsonPath("$[0].principalId").value("agent"))
                .andExpect(jsonPath("$[0].scopes[0]").value("READ_VAULT_KEY_PACKAGE"));
    }

    @Test
    void revokeTokenByIdRevokesBearer() throws Exception {
        String user = "hardening-revoke-id";
        String vault = "vault-revoke-id";
        registerUser(user);
        createVault(user, vault);
        putPrincipal(user, vault, "agent");
        IssuedToken issued = issueToken(user, vault, "agent", "READ_ENCRYPTED_RECORDS", null);
        mvc.perform(
                        get("/api/v1/automation/records")
                                .header("Authorization", "Automation " + issued.rawToken()))
                .andExpect(status().isOk());
        mvc.perform(
                        delete(
                                        "/api/v1/vaults/{vault}/automation-principals/{principal}/tokens/{tokenId}",
                                        vault,
                                        "agent",
                                        issued.tokenId())
                                .with(httpBasic(user, "correct horse battery staple")))
                .andExpect(status().isNoContent());
        mvc.perform(
                        get("/api/v1/automation/records")
                                .header("Authorization", "Automation " + issued.rawToken()))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void perSecretGrantsRestrictRecords() throws Exception {
        String user = "hardening-grants";
        String vault = "vault-grants";
        registerUser(user);
        createVault(user, vault);
        storeRecord(user, vault, "secret-a", 1);
        storeRecord(user, vault, "secret-b", 2);
        putPrincipal(user, vault, "agent");
        IssuedToken issued =
                issueToken(
                        user, vault, "agent", "READ_ENCRYPTED_RECORDS", new String[] {"secret-a"});
        mvc.perform(
                        get("/api/v1/automation/records")
                                .header("Authorization", "Automation " + issued.rawToken()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].secretId").value("secret-a"));
    }

    @Test
    void vaultWideTokenReturnsAllRecords() throws Exception {
        String user = "hardening-wide";
        String vault = "vault-wide";
        registerUser(user);
        createVault(user, vault);
        storeRecord(user, vault, "secret-a", 1);
        storeRecord(user, vault, "secret-b", 2);
        putPrincipal(user, vault, "agent");
        IssuedToken issued = issueToken(user, vault, "agent", "READ_ENCRYPTED_RECORDS", null);
        mvc.perform(
                        get("/api/v1/automation/records")
                                .header("Authorization", "Automation " + issued.rawToken()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(2));
    }

    @Test
    void crossPrincipalIsolationHidesTokensAcrossPrincipals() throws Exception {
        String user = "hardening-xprinc";
        String vault = "vault-xprinc";
        registerUser(user);
        createVault(user, vault);
        putPrincipal(user, vault, "agent-a");
        putPrincipal(user, vault, "agent-b");
        IssuedToken issuedA = issueToken(user, vault, "agent-a", "READ_ENCRYPTED_RECORDS", null);
        IssuedToken issuedB = issueToken(user, vault, "agent-b", "READ_ENCRYPTED_RECORDS", null);

        // agent-a's listing must not leak agent-b's token id, and vice versa.
        mvc.perform(
                        get(
                                        "/api/v1/vaults/{vault}/automation-principals/{principal}/tokens",
                                        vault,
                                        "agent-a")
                                .with(httpBasic(user, "correct horse battery staple")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].tokenId").value(issuedA.tokenId()));
        mvc.perform(
                        get(
                                        "/api/v1/vaults/{vault}/automation-principals/{principal}/tokens",
                                        vault,
                                        "agent-b")
                                .with(httpBasic(user, "correct horse battery staple")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].tokenId").value(issuedB.tokenId()));

        // revoking agent-b's token via agent-a's path (and vice versa) must 404, not revoke.
        mvc.perform(
                        delete(
                                        "/api/v1/vaults/{vault}/automation-principals/{principal}/tokens/{tokenId}",
                                        vault,
                                        "agent-a",
                                        issuedB.tokenId())
                                .with(httpBasic(user, "correct horse battery staple")))
                .andExpect(status().isNotFound());
        mvc.perform(
                        delete(
                                        "/api/v1/vaults/{vault}/automation-principals/{principal}/tokens/{tokenId}",
                                        vault,
                                        "agent-b",
                                        issuedA.tokenId())
                                .with(httpBasic(user, "correct horse battery staple")))
                .andExpect(status().isNotFound());

        // the cross-principal revoke attempts must not have revoked either bearer.
        mvc.perform(
                        get("/api/v1/automation/records")
                                .header("Authorization", "Automation " + issuedA.rawToken()))
                .andExpect(status().isOk());
        mvc.perform(
                        get("/api/v1/automation/records")
                                .header("Authorization", "Automation " + issuedB.rawToken()))
                .andExpect(status().isOk());
    }

    @Test
    void crossOwnerIsolationDeniesAccessToOtherOwnersVault() throws Exception {
        String ownerA = "hardening-xowner-a";
        String ownerB = "hardening-xowner-b";
        String vault = "vault-xowner";
        registerUser(ownerA);
        registerUser(ownerB);
        createVault(ownerA, vault);
        putPrincipal(ownerA, vault, "agent");
        IssuedToken issued = issueToken(ownerA, vault, "agent", "READ_VAULT_KEY_PACKAGE", null);

        // ownerB does not own the vault, so listing/revoke must 404 without leaking existence.
        mvc.perform(
                        get(
                                        "/api/v1/vaults/{vault}/automation-principals/{principal}/tokens",
                                        vault,
                                        "agent")
                                .with(httpBasic(ownerB, "correct horse battery staple")))
                .andExpect(status().isNotFound());
        mvc.perform(
                        delete(
                                        "/api/v1/vaults/{vault}/automation-principals/{principal}/tokens/{tokenId}",
                                        vault,
                                        "agent",
                                        issued.tokenId())
                                .with(httpBasic(ownerB, "correct horse battery staple")))
                .andExpect(status().isNotFound());

        // ownerA still owns the resource and can list it.
        mvc.perform(
                        get(
                                        "/api/v1/vaults/{vault}/automation-principals/{principal}/tokens",
                                        vault,
                                        "agent")
                                .with(httpBasic(ownerA, "correct horse battery staple")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].tokenId").value(issued.tokenId()));
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

    private void storeRecord(String user, String vault, String secretId, long revision)
            throws Exception {
        mvc.perform(
                        put("/api/v1/vaults/{vault}/records/{secretId}", vault, secretId)
                                .with(httpBasic(user, "correct horse battery staple"))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        "{"
                                                + "\"revision\":"
                                                + revision
                                                + ","
                                                + "\"secretType\":\"SECURE_NOTE\","
                                                + "\"metadata\":\"bWV0YQ\","
                                                + "\"envelope\":\"ZW52ZWxvcGU\","
                                                + "\"deleted\":false"
                                                + "}"))
                .andExpect(status().isCreated());
    }

    private IssuedToken issueToken(
            String user, String vault, String principal, String scope, String[] grantedSecretIds)
            throws Exception {
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
                                                tokenRequestBody(
                                                        expiresAt, scope, grantedSecretIds)))
                        .andExpect(status().isOk())
                        .andReturn();
        String body = result.getResponse().getContentAsString();
        return new IssuedToken(JsonPath.read(body, "$.token"), JsonPath.read(body, "$.tokenId"));
    }

    private static String tokenRequestBody(
            String expiresAt, String scope, String[] grantedSecretIds) {
        StringBuilder json =
                new StringBuilder("{\"expiresAt\":\"")
                        .append(expiresAt)
                        .append("\",\"scopes\":[\"")
                        .append(scope)
                        .append("\"]");
        if (grantedSecretIds != null && grantedSecretIds.length > 0) {
            json.append(",\"grantedSecretIds\":[");
            for (int i = 0; i < grantedSecretIds.length; i++) {
                if (i > 0) json.append(',');
                json.append('"').append(grantedSecretIds[i]).append('"');
            }
            json.append("]");
        }
        return json.append("}").toString();
    }

    private record IssuedToken(String rawToken, String tokenId) {}
}
