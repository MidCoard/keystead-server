package top.focess.keystead.server.record;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
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
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("REVISION_CONFLICT"))
                .andExpect(jsonPath("$.message").value("Record revision must increase"))
                .andExpect(jsonPath("$.latestRevision").value(2))
                .andExpect(jsonPath("$.rejectedRevision").value(2))
                .andExpect(jsonPath("$.vaultId").value("vault-1"))
                .andExpect(jsonPath("$.secretId").value("secret-2"))
                .andExpect(jsonPath("$.serverRevision").value(2))
                .andExpect(jsonPath("$.clientRevision").value(2))
                .andExpect(jsonPath("$.serverDeleted").value(false))
                .andExpect(jsonPath("$.serverUpdatedAt").exists())
                .andExpect(jsonPath("$.envelope").doesNotExist())
                .andExpect(jsonPath("$.metadata").doesNotExist())
                .andExpect(jsonPath("$.encryptedProfile").doesNotExist());
    }

    @Test
    @WithMockUser(username = "alice")
    void encryptedProfileIsStoredForClientSideClassification() throws Exception {
        createVault("alice", "vault-profile");

        mvc.perform(
                        put("/api/v1/vaults/vault-profile/records/secret-profile")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "revision": 1,
                                          "secretType": "LOGIN_PASSWORD",
                                          "encryptedProfile": "encrypted-profile-development-github",
                                          "envelope": "encrypted-secret-payload",
                                          "deleted": false
                                        }
                                        """))
                .andExpect(status().isCreated());

        mvc.perform(get("/api/v1/vaults/vault-profile/records/secret-profile"))
                .andExpect(status().isOk())
                .andExpect(
                        jsonPath("$.encryptedProfile")
                                .value("encrypted-profile-development-github"))
                .andExpect(jsonPath("$.metadata").value("encrypted-profile-development-github"));
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
                .andExpect(jsonPath("$.metadata").doesNotExist())
                .andExpect(jsonPath("$.encryptedProfile").doesNotExist())
                .andExpect(jsonPath("$.envelope").doesNotExist())
                .andExpect(jsonPath("$.deleted").value(true));
    }

    @Test
    @WithMockUser(username = "alice")
    void tombstoneCanBeStoredWithoutEncryptedProfileOrPayload() throws Exception {
        createVault("alice", "vault-tombstone-upload");

        mvc.perform(
                        put("/api/v1/vaults/vault-tombstone-upload/records/secret-tombstone")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "revision": 1,
                                          "secretType": "SECURE_NOTE",
                                          "deleted": true
                                        }
                                        """))
                .andExpect(status().isCreated());

        mvc.perform(get("/api/v1/vaults/vault-tombstone-upload/records/secret-tombstone"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.revision").value(1))
                .andExpect(jsonPath("$.metadata").doesNotExist())
                .andExpect(jsonPath("$.encryptedProfile").doesNotExist())
                .andExpect(jsonPath("$.envelope").doesNotExist())
                .andExpect(jsonPath("$.deleted").value(true));
    }

    @Test
    @WithMockUser(username = "alice")
    void oversizedEncryptedRecordPayloadIsRejected() throws Exception {
        createVault("alice", "vault-oversized");
        String oversized = "x".repeat(262_145);

        mvc.perform(
                        put("/api/v1/vaults/vault-oversized/records/secret-oversized")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "revision": 1,
                                          "secretType": "LOGIN_PASSWORD",
                                          "encryptedProfile": "%s",
                                          "envelope": "%s",
                                          "deleted": false
                                        }
                                        """
                                                .formatted(oversized, oversized)))
                .andExpect(status().isBadRequest());
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
    @WithMockUser(username = "alice")
    void listSyncRejectsNegativeSinceRevision() throws Exception {
        createVault("alice", "vault-sync-negative");

        mvc.perform(get("/api/v1/vaults/vault-sync-negative/records").param("sinceRevision", "-1"))
                .andExpect(status().isBadRequest());
    }

    @Test
    @WithMockUser(username = "alice")
    void recordsCanBePagedForDatabaseStyleSyncCursor() throws Exception {
        createVault("alice", "vault-sync-page");
        putRecord("vault-sync-page", "secret-a", 1, "envelope-a");
        putRecord("vault-sync-page", "secret-b", 2, "envelope-b");
        putRecord("vault-sync-page", "secret-c", 3, "envelope-c");

        mvc.perform(
                        get("/api/v1/vaults/vault-sync-page/records/page")
                                .param("sinceRevision", "0")
                                .param("limit", "2"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.vaultId").value("vault-sync-page"))
                .andExpect(jsonPath("$.sinceRevision").value(0))
                .andExpect(jsonPath("$.records[0].secretId").value("secret-a"))
                .andExpect(jsonPath("$.records[0].revision").value(1))
                .andExpect(jsonPath("$.records[1].secretId").value("secret-b"))
                .andExpect(jsonPath("$.records[1].revision").value(2))
                .andExpect(jsonPath("$.highestRevision").value(2))
                .andExpect(jsonPath("$.hasMore").value(true))
                .andExpect(jsonPath("$.nextSinceRevision").value(2));
    }

    @Test
    @WithMockUser(username = "alice")
    void pageSyncRejectsNegativeSinceRevision() throws Exception {
        createVault("alice", "vault-sync-page-negative");

        mvc.perform(
                        get("/api/v1/vaults/vault-sync-page-negative/records/page")
                                .param("sinceRevision", "-1"))
                .andExpect(status().isBadRequest());
    }

    @Test
    @WithMockUser(username = "alice")
    void recordPageLimitIsBounded() throws Exception {
        createVault("alice", "vault-sync-page-limit");

        mvc.perform(get("/api/v1/vaults/vault-sync-page-limit/records/page").param("limit", "501"))
                .andExpect(status().isBadRequest());
    }

    @Test
    @WithMockUser(username = "alice")
    void deleteMarksRecordAsTombstoneForSync() throws Exception {
        createVault("alice", "vault-delete");
        putRecord("vault-delete", "secret-delete", 1, "delete-envelope");

        mvc.perform(
                        delete("/api/v1/vaults/vault-delete/records/secret-delete")
                                .param("revision", "2"))
                .andExpect(status().isNoContent());

        mvc.perform(get("/api/v1/vaults/vault-delete/records/secret-delete"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.revision").value(2))
                .andExpect(jsonPath("$.metadata").doesNotExist())
                .andExpect(jsonPath("$.encryptedProfile").doesNotExist())
                .andExpect(jsonPath("$.envelope").doesNotExist())
                .andExpect(jsonPath("$.deleted").value(true));

        mvc.perform(get("/api/v1/vaults/vault-delete/records").param("sinceRevision", "1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].secretId").value("secret-delete"))
                .andExpect(jsonPath("$[0].metadata").doesNotExist())
                .andExpect(jsonPath("$[0].encryptedProfile").doesNotExist())
                .andExpect(jsonPath("$[0].envelope").doesNotExist())
                .andExpect(jsonPath("$[0].deleted").value(true));
    }

    @Test
    @WithMockUser(username = "alice")
    void staleDeleteRevisionIsConflictWithRevisionDetails() throws Exception {
        createVault("alice", "vault-delete-conflict");
        putRecord("vault-delete-conflict", "secret-delete-conflict", 3, "delete-envelope");

        mvc.perform(
                        delete(
                                        "/api/v1/vaults/vault-delete-conflict/records/secret-delete-conflict")
                                .param("revision", "2"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("REVISION_CONFLICT"))
                .andExpect(jsonPath("$.message").value("Record revision must increase"))
                .andExpect(jsonPath("$.latestRevision").value(3))
                .andExpect(jsonPath("$.rejectedRevision").value(2))
                .andExpect(jsonPath("$.vaultId").value("vault-delete-conflict"))
                .andExpect(jsonPath("$.secretId").value("secret-delete-conflict"))
                .andExpect(jsonPath("$.serverRevision").value(3))
                .andExpect(jsonPath("$.clientRevision").value(2))
                .andExpect(jsonPath("$.serverDeleted").value(false))
                .andExpect(jsonPath("$.serverUpdatedAt").exists())
                .andExpect(jsonPath("$.envelope").doesNotExist())
                .andExpect(jsonPath("$.metadata").doesNotExist())
                .andExpect(jsonPath("$.encryptedProfile").doesNotExist());
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

    @Test
    void userCannotWriteListOrDeleteAnotherUsersRecords() throws Exception {
        createVault("record-private-alice", "vault-record-private");
        mvc.perform(
                        put("/api/v1/vaults/vault-record-private/records/secret-private")
                                .with(user("record-private-alice"))
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

        mvc.perform(
                        put("/api/v1/vaults/vault-record-private/records/secret-private")
                                .with(user("record-private-bob"))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "revision": 2,
                                          "secretType": "LOGIN_PASSWORD",
                                          "metadata": "Ym9iLW1ldGE",
                                          "envelope": "Ym9iLWVudmVsb3Bl",
                                          "deleted": false
                                        }
                                        """))
                .andExpect(status().isNotFound());

        mvc.perform(
                        get("/api/v1/vaults/vault-record-private/records")
                                .with(user("record-private-bob")))
                .andExpect(status().isNotFound());

        mvc.perform(
                        delete("/api/v1/vaults/vault-record-private/records/secret-private")
                                .with(user("record-private-bob"))
                                .param("revision", "3"))
                .andExpect(status().isNotFound());

        mvc.perform(
                        get("/api/v1/vaults/vault-record-private/records/secret-private")
                                .with(user("record-private-alice")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.revision").value(1))
                .andExpect(jsonPath("$.envelope").value("ZW52ZWxvcGU"))
                .andExpect(jsonPath("$.deleted").value(false));
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
