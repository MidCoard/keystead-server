package top.focess.keystead.server.record;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class EncryptedRecordApiTest {

    @Autowired private MockMvc mvc;

    @Test
    void healthIsPublic() throws Exception {
        mvc.perform(get("/actuator/health")).andExpect(status().isOk());
    }

    @Test
    @WithMockUser(username = "alice")
    void authenticatedUserCanCreateAndFetchEncryptedRecord() throws Exception {
        createVault("alice", "vault-1");

        mvc.perform(
                        put("/api/v1/vaults/vault-1/records/secret-1")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "revision": 1,
                                          "secretType": "LOGIN_PASSWORD",
                                          "metadata": "eyJ0aXRsZSI6IkdpdEh1YiJ9",
                                          "envelope": "eyJjaXBoZXJ0ZXh0IjoiYmxvYiJ9",
                                          "deleted": false
                                        }
                                        """))
                .andExpect(status().isCreated());

        mvc.perform(get("/api/v1/vaults/vault-1/records/secret-1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.vaultId").value("vault-1"))
                .andExpect(jsonPath("$.secretId").value("secret-1"))
                .andExpect(jsonPath("$.revision").value(1))
                .andExpect(jsonPath("$.secretType").value("LOGIN_PASSWORD"))
                .andExpect(jsonPath("$.metadata").value("eyJ0aXRsZSI6IkdpdEh1YiJ9"))
                .andExpect(jsonPath("$.envelope").value("eyJjaXBoZXJ0ZXh0IjoiYmxvYiJ9"))
                .andExpect(jsonPath("$.deleted").value(false));
    }

    @Test
    @WithMockUser(username = "alice")
    void duplicateOrOlderRevisionIsConflict() throws Exception {
        createVault("alice", "vault-1");
        String body =
                """
                {
                  "revision": 2,
                  "secretType": "SECURE_NOTE",
                  "metadata": "bWV0YQ",
                  "envelope": "ZW52ZWxvcGU",
                  "deleted": false
                }
                """;

        mvc.perform(
                        put("/api/v1/vaults/vault-1/records/secret-2")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(body))
                .andExpect(status().isCreated());

        mvc.perform(
                        put("/api/v1/vaults/vault-1/records/secret-2")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(body))
                .andExpect(status().isConflict());
    }

    @Test
    @WithMockUser(username = "alice")
    void newerRevisionReplacesStoredEncryptedRecord() throws Exception {
        createVault("alice", "vault-1");

        mvc.perform(
                        put("/api/v1/vaults/vault-1/records/secret-3")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "revision": 1,
                                          "secretType": "SECURE_NOTE",
                                          "metadata": "bWV0YQ",
                                          "envelope": "dmVyc2lvbi0x",
                                          "deleted": false
                                        }
                                        """))
                .andExpect(status().isCreated());

        mvc.perform(
                        put("/api/v1/vaults/vault-1/records/secret-3")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "revision": 2,
                                          "secretType": "SECURE_NOTE",
                                          "metadata": "bWV0YQ",
                                          "envelope": "dmVyc2lvbi0y",
                                          "deleted": true
                                        }
                                        """))
                .andExpect(status().isOk());

        mvc.perform(get("/api/v1/vaults/vault-1/records/secret-3"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.revision").value(2))
                .andExpect(jsonPath("$.envelope").value("dmVyc2lvbi0y"))
                .andExpect(jsonPath("$.deleted").value(true));
    }

    @Test
    @WithMockUser(username = "alice")
    void recordCannotBeStoredForMissingVault() throws Exception {
        mvc.perform(
                        put("/api/v1/vaults/missing-vault/records/secret-404")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "revision": 1,
                                          "secretType": "LOGIN_PASSWORD",
                                          "metadata": "bWV0YQ",
                                          "envelope": "ZW52ZWxvcGU",
                                          "deleted": false
                                        }
                                        """))
                .andExpect(status().isNotFound());
    }

    @Test
    @WithMockUser(username = "alice")
    void recordsCanBeListedForSyncSinceRevision() throws Exception {
        createVault("alice", "vault-sync");
        putRecord("vault-sync", "secret-old", 1, "old-envelope");
        putRecord("vault-sync", "secret-new", 3, "new-envelope");

        mvc.perform(get("/api/v1/vaults/vault-sync/records").param("sinceRevision", "1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].secretId").value("secret-new"))
                .andExpect(jsonPath("$[0].revision").value(3));
    }

    @Test
    void unauthenticatedRequestsAreRejected() throws Exception {
        mvc.perform(get("/api/v1/vaults/vault-1/records/secret-1"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void userCannotReadAnotherUsersRecord() throws Exception {
        createVault("alice", "vault-1");

        mvc.perform(
                        put("/api/v1/vaults/vault-1/records/secret-4")
                                .with(user("alice"))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "revision": 1,
                                          "secretType": "LOGIN_PASSWORD",
                                          "metadata": "bWV0YQ",
                                          "envelope": "ZW52ZWxvcGU",
                                          "deleted": false
                                        }
                                        """))
                .andExpect(status().isCreated());

        mvc.perform(get("/api/v1/vaults/vault-1/records/secret-4").with(user("bob")))
                .andExpect(status().isNotFound());
    }

    private void createVault(String username, String vaultId) throws Exception {
        mvc.perform(
                        put("/api/v1/vaults/{vaultId}", vaultId)
                                .with(user(username))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "encryptedMetadata": "vault-metadata"
                                        }
                                        """))
                .andExpect(status().isCreated());
    }

    private void putRecord(String vaultId, String secretId, long revision, String envelope)
            throws Exception {
        mvc.perform(
                        put("/api/v1/vaults/{vaultId}/records/{secretId}", vaultId, secretId)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "revision": %d,
                                          "secretType": "SECURE_NOTE",
                                          "metadata": "bWV0YQ",
                                          "envelope": "%s",
                                          "deleted": false
                                        }
                                        """
                                                .formatted(revision, envelope)))
                .andExpect(status().isCreated());
    }
}
