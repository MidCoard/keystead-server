package top.focess.keystead.server.vault;

import static org.hamcrest.Matchers.hasItem;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

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
class VaultMembershipLifecycleApiTest {

    private static final String PASSWORD = "correct horse battery staple";

    @Autowired private MockMvc mvc;

    @Test
    void invitationsAreDiscoverablePrivateAndAcceptOnlyIntoPendingKeyState() throws Exception {
        String suffix = Long.toUnsignedString(System.nanoTime());
        String owner = "membership-owner-" + suffix;
        String invitee = "membership-invitee-" + suffix;
        String outsider = "membership-outsider-" + suffix;
        String vaultId = "membership-vault-" + suffix;
        registerUser(owner);
        registerUser(invitee);
        registerUser(outsider);
        createVault(owner, vaultId);
        declareCurrentKey(owner, vaultId, "current-key-1");
        invite(owner, invitee, vaultId, "VIEWER");

        mvc.perform(get("/api/v1/vaults").with(httpBasic(invitee, PASSWORD)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].vaultId").value(vaultId))
                .andExpect(jsonPath("$[0].ownerId").value(owner))
                .andExpect(jsonPath("$[0].encryptedMetadata").value("opaque-vault-metadata"))
                .andExpect(jsonPath("$[0].role").value("VIEWER"))
                .andExpect(jsonPath("$[0].membershipState").value("INVITED"))
                .andExpect(jsonPath("$[0].currentVaultKeyId").value("current-key-1"))
                .andExpect(jsonPath("$[0].keyLifecycleState").value("STABLE"))
                .andExpect(jsonPath("$[0].lifecycleVersion").value(1));
        mvc.perform(get("/api/v1/vaults").with(httpBasic(outsider, PASSWORD)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isEmpty());

        accept(invitee, vaultId);
        accept(invitee, vaultId);

        mvc.perform(get("/api/v1/vaults").with(httpBasic(invitee, PASSWORD)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].membershipState").value("ACCEPTED_PENDING_KEY"));
        mvc.perform(
                        get("/api/v1/vaults/{vaultId}/records", vaultId)
                                .with(httpBasic(invitee, PASSWORD)))
                .andExpect(status().isNotFound());
        mvc.perform(
                        get("/api/v1/vaults/{vaultId}/members", vaultId)
                                .with(httpBasic(invitee, PASSWORD)))
                .andExpect(status().isNotFound());

        mvc.perform(
                        get("/api/v1/vaults/{vaultId}/members", vaultId)
                                .with(httpBasic(owner, PASSWORD)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[*].userId").value(hasItem(invitee)))
                .andExpect(
                        jsonPath("$[?(@.userId == '%s')].state".formatted(invitee))
                                .value(hasItem("ACCEPTED_PENDING_KEY")));
    }

    @Test
    void declineIsIdempotentHiddenAndRemovedMemberCanBeReinvited() throws Exception {
        String suffix = Long.toUnsignedString(System.nanoTime());
        String owner = "decline-owner-" + suffix;
        String invitee = "decline-invitee-" + suffix;
        String vaultId = "decline-vault-" + suffix;
        registerUser(owner);
        registerUser(invitee);
        createVault(owner, vaultId);
        invite(owner, invitee, vaultId, "VIEWER");

        decline(invitee, vaultId);
        decline(invitee, vaultId);
        mvc.perform(get("/api/v1/vaults").with(httpBasic(invitee, PASSWORD)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isEmpty());

        invite(owner, invitee, vaultId, "VIEWER");
        accept(invitee, vaultId);
        decline(invitee, vaultId);
        mvc.perform(get("/api/v1/vaults").with(httpBasic(invitee, PASSWORD)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isEmpty());

        invite(owner, invitee, vaultId, "EDITOR");
        mvc.perform(get("/api/v1/vaults").with(httpBasic(invitee, PASSWORD)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].role").value("EDITOR"))
                .andExpect(jsonPath("$[0].membershipState").value("INVITED"));
    }

    @Test
    void ownerCannotAcceptDeclineOrBeReinvited() throws Exception {
        String suffix = Long.toUnsignedString(System.nanoTime());
        String owner = "protected-owner-" + suffix;
        String vaultId = "protected-vault-" + suffix;
        registerUser(owner);
        createVault(owner, vaultId);

        mvc.perform(
                        post("/api/v1/vaults/{vaultId}/members/accept", vaultId)
                                .with(httpBasic(owner, PASSWORD)))
                .andExpect(status().isNotFound());
        mvc.perform(
                        post("/api/v1/vaults/{vaultId}/members/decline", vaultId)
                                .with(httpBasic(owner, PASSWORD)))
                .andExpect(status().isNotFound());
        mvc.perform(
                        put("/api/v1/vaults/{vaultId}/members/{userId}", vaultId, owner)
                                .with(httpBasic(owner, PASSWORD))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"role\":\"VIEWER\"}"))
                .andExpect(status().isNotFound());
    }

    private void registerUser(String username) throws Exception {
        mvc.perform(
                        post("/api/v1/users")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "username": "%s",
                                          "password": "%s"
                                        }
                                        """
                                                .formatted(username, PASSWORD)))
                .andExpect(status().isCreated());
    }

    private void createVault(String username, String vaultId) throws Exception {
        mvc.perform(
                        put("/api/v1/vaults/{vaultId}", vaultId)
                                .with(httpBasic(username, PASSWORD))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"encryptedMetadata\":\"opaque-vault-metadata\"}"))
                .andExpect(status().isCreated());
    }

    private void declareCurrentKey(String username, String vaultId, String keyId) throws Exception {
        mvc.perform(
                        put("/api/v1/vaults/{vaultId}/key-rotation", vaultId)
                                .with(httpBasic(username, PASSWORD))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"vaultKeyId\":\"%s\"}".formatted(keyId)))
                .andExpect(status().isNoContent());
    }

    private void invite(String owner, String invitee, String vaultId, String role)
            throws Exception {
        mvc.perform(
                        put("/api/v1/vaults/{vaultId}/members/{userId}", vaultId, invitee)
                                .with(httpBasic(owner, PASSWORD))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"role\":\"%s\"}".formatted(role)))
                .andExpect(status().isCreated());
    }

    private void accept(String invitee, String vaultId) throws Exception {
        mvc.perform(
                        post("/api/v1/vaults/{vaultId}/members/accept", vaultId)
                                .with(httpBasic(invitee, PASSWORD)))
                .andExpect(status().isNoContent());
    }

    private void decline(String invitee, String vaultId) throws Exception {
        mvc.perform(
                        post("/api/v1/vaults/{vaultId}/members/decline", vaultId)
                                .with(httpBasic(invitee, PASSWORD)))
                .andExpect(status().isNoContent());
    }
}
