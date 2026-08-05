package top.focess.keystead.server.record;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import top.focess.keystead.service.EncryptedSyncRecord;
import top.focess.keystead.service.SyncRecordEventId;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class PersonalVaultRecordApiTest {

    @Autowired private MockMvc mvc;

    @Test
    void appendOnlyStreamKeepsMultipleCiphertextEventsForTheSameSecret() throws Exception {
        append("stream-alice", "secret-1", 1, "profile-1", "payload-1")
                .andExpect(status().isCreated());
        append("stream-alice", "secret-1", 2, "profile-2", "payload-2")
                .andExpect(status().isCreated());

        mvc.perform(
                        get("/api/v1/vault/records")
                                .with(user("stream-alice"))
                                .param("afterSequence", "0")
                                .param("limit", "10"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.records[0].revision").value(1))
                .andExpect(jsonPath("$.records[1].revision").value(2))
                .andExpect(jsonPath("$.records[0].serverSequence").isNumber())
                .andExpect(jsonPath("$.records[1].serverSequence").isNumber())
                .andExpect(jsonPath("$.hasMore").value(false));
    }

    @Test
    void reuploadingAnUnchangedRecordWithAFreshProfileNonceIsANoOp() throws Exception {
        append("idempotent-alice", "secret-1", 1, "profile-nonce-1", "payload-1", "content-key-1")
                .andExpect(status().isCreated());
        // KVE2 hashes the content key, not the ciphertext, so re-exporting the same logical
        // record with a fresh profile nonce yields the same event id: the second push is
        // deduplicated and returns the originally stored event.
        append("idempotent-alice", "secret-1", 1, "profile-nonce-2", "payload-1", "content-key-1")
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.encryptedProfile").value("profile-nonce-1"));

        mvc.perform(get("/api/v1/vault/records").with(user("idempotent-alice")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.records.length()").value(1));
    }

    @Test
    void sameRevisionWithDifferentPayloadStillAppends() throws Exception {
        append("diverged-alice", "secret-1", 1, "profile-1", "payload-1", "content-key-1")
                .andExpect(status().isCreated());
        append("diverged-alice", "secret-1", 1, "profile-1", "payload-diverged", "content-key-2")
                .andExpect(status().isCreated());

        mvc.perform(get("/api/v1/vault/records").with(user("diverged-alice")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.records.length()").value(2));
    }

    @Test
    void equalLocalRevisionsForDifferentSecretsDoNotConflict() throws Exception {
        append("equal-revision", "secret-a", 7, "profile-a", "payload-a")
                .andExpect(status().isCreated());
        append("equal-revision", "secret-b", 7, "profile-b", "payload-b")
                .andExpect(status().isCreated());

        mvc.perform(get("/api/v1/vault/records").with(user("equal-revision")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.records.length()").value(2));
    }

    @Test
    void ownerCanRemoveAllServerHistoryForOnlyTheSelectedRecord() throws Exception {
        append("remove-owner", "secret-selected", 1, "profile-1", "payload-1")
                .andExpect(status().isCreated());
        append("remove-owner", "secret-selected", 2, "profile-2", "payload-2")
                .andExpect(status().isCreated());
        append("remove-owner", "secret-retained", 3, "profile-3", "payload-3")
                .andExpect(status().isCreated());
        append("remove-other", "secret-selected", 1, "other-profile", "other-payload")
                .andExpect(status().isCreated());

        mvc.perform(
                        delete("/api/v1/vault/records/{secretId}", "secret-selected")
                                .with(user("remove-owner")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.secretId").value("secret-selected"))
                .andExpect(jsonPath("$.deletedEvents").value(2));

        mvc.perform(get("/api/v1/vault/records").with(user("remove-owner")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.records.length()").value(1))
                .andExpect(jsonPath("$.records[0].secretId").value("secret-retained"));
        mvc.perform(get("/api/v1/vault/records").with(user("remove-other")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.records.length()").value(1))
                .andExpect(jsonPath("$.records[0].secretId").value("secret-selected"));
    }

    @Test
    void removingTheLastRecordReleasesTheEmptyStreamFingerprint() throws Exception {
        append("remove-last", "only-secret", 1, "profile", "payload")
                .andExpect(status().isCreated());
        mvc.perform(
                        delete("/api/v1/vault/records/{secretId}", "only-secret")
                                .with(user("remove-last")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.deletedEvents").value(1));

        String replacementFingerprint = "7000000000000002";
        mvc.perform(
                        post("/api/v1/vault/records")
                                .with(user("remove-last"))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        body(
                                                eventId(
                                                        replacementFingerprint,
                                                        "replacement-secret",
                                                        1,
                                                        "replacement-profile",
                                                        "replacement-payload",
                                                        "replacement-content-key"),
                                                "replacement-secret",
                                                1,
                                                replacementFingerprint,
                                                "replacement-profile",
                                                "replacement-payload",
                                                "replacement-content-key")))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.fingerprint").value(replacementFingerprint));
    }

    @Test
    void streamIsAccountScopedAndUsesOneDeclaredVaultFingerprint() throws Exception {
        append("owner-stream", "secret-owner", 1, "profile", "payload")
                .andExpect(status().isCreated());

        mvc.perform(get("/api/v1/vault/records").with(user("other-stream")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.records").isEmpty());

        mvc.perform(
                        post("/api/v1/vault/records")
                                .with(user("owner-stream"))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        body(
                                                eventId(
                                                        "wrong-fingerprint",
                                                        "secret-wrong",
                                                        2,
                                                        "p",
                                                        "e",
                                                        "key-e"),
                                                "secret-wrong",
                                                2,
                                                "wrong-fingerprint",
                                                "p",
                                                "e",
                                                "key-e")))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("PERSONAL_VAULT_MISMATCH"))
                .andExpect(jsonPath("$.serverFingerprint").value("6000000000000001"))
                .andExpect(jsonPath("$.submittedFingerprint").value("wrong-fingerprint"));
    }

    @Test
    void deletionMustCarryAnAuthenticatedControlEnvelope() throws Exception {
        mvc.perform(
                        post("/api/v1/vault/records")
                                .with(user("delete-stream"))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "eventId":"delete-1",
                                          "fingerprint":"6000000000000001",
                                          "secretId":"secret-delete",
                                          "revision":2,
                                          "secretType":"SECURE_NOTE",
                                          "encryptedProfile":"",
                                          "envelope":"",
                                          "deleted":true,
                                          "contentKey":"key-delete"
                                        }
                                        """))
                .andExpect(status().isBadRequest());
    }

    @Test
    void appendRejectsAnEventIdThatDoesNotMatchTheEncryptedRecordContent() throws Exception {
        mvc.perform(
                        post("/api/v1/vault/records")
                                .with(user("hash-mismatch"))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        body(
                                                "not-the-content-hash",
                                                "secret-hash",
                                                1,
                                                "6000000000000001",
                                                "profile",
                                                "payload",
                                                "content-key")))
                .andExpect(status().isBadRequest());
    }

    @Test
    void appendRejectsAContentKeyThatDoesNotMatchTheClaimedEventId() throws Exception {
        append("content-key-alice", "secret-key", 1, "profile", "payload", "content-key-real")
                .andExpect(status().isCreated());

        // The event id is the valid KVE2 hash of a different content key than the one
        // submitted, so the append is rejected.
        mvc.perform(
                        post("/api/v1/vault/records")
                                .with(user("content-key-alice"))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        body(
                                                eventId(
                                                        "6000000000000001",
                                                        "secret-key",
                                                        2,
                                                        "profile",
                                                        "payload",
                                                        "content-key-real"),
                                                "secret-key",
                                                2,
                                                "6000000000000001",
                                                "profile",
                                                "payload",
                                                "content-key-forged")))
                .andExpect(status().isBadRequest());
    }

    private org.springframework.test.web.servlet.ResultActions append(
            String username, String secretId, long revision, String profile, String envelope)
            throws Exception {
        return append(username, secretId, revision, profile, envelope, "key-" + envelope);
    }

    private org.springframework.test.web.servlet.ResultActions append(
            String username,
            String secretId,
            long revision,
            String profile,
            String envelope,
            String contentKey)
            throws Exception {
        return mvc.perform(
                post("/api/v1/vault/records")
                        .with(user(username))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(
                                body(
                                        eventId(
                                                "6000000000000001",
                                                secretId,
                                                revision,
                                                profile,
                                                envelope,
                                                contentKey),
                                        secretId,
                                        revision,
                                        "6000000000000001",
                                        profile,
                                        envelope,
                                        contentKey)));
    }

    private static String eventId(
            String fingerprint,
            String secretId,
            long revision,
            String profile,
            String envelope,
            String contentKey) {
        return SyncRecordEventId.of(
                new EncryptedSyncRecord(
                        fingerprint,
                        secretId,
                        revision,
                        "SECURE_NOTE",
                        profile,
                        envelope,
                        false,
                        contentKey));
    }

    private static String body(
            String eventId,
            String secretId,
            long revision,
            String fingerprint,
            String profile,
            String envelope,
            String contentKey) {
        return """
                {
                  "eventId":"%s",
                  "fingerprint":"%s",
                  "secretId":"%s",
                  "revision":%d,
                  "secretType":"SECURE_NOTE",
                  "encryptedProfile":"%s",
                  "envelope":"%s",
                  "deleted":false,
                  "contentKey":"%s"
                }
                """
                .formatted(eventId, fingerprint, secretId, revision, profile, envelope, contentKey);
    }
}
