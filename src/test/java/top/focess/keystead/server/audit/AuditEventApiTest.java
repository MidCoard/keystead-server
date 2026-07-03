package top.focess.keystead.server.audit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;
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
class AuditEventApiTest {

    @Autowired private MockMvc mvc;

    @Autowired private AuditEventRepository auditEvents;

    @Test
    void recordWriteCreatesRedactedAuditEvent() throws Exception {
        createVault("audit-write-alice", "vault-audit");

        mvc.perform(
                        put("/api/v1/vaults/vault-audit/records/secret-audit")
                                .with(user("audit-write-alice"))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "revision": 7,
                                          "secretType": "API_TOKEN",
                                          "encryptedProfile": "encrypted-profile-sentinel",
                                          "envelope": "encrypted-envelope-sentinel",
                                          "deleted": false
                                        }
                                        """))
                .andExpect(status().isCreated());

        List<StoredAuditEvent> events = auditEvents.listForOwner("audit-write-alice");

        assertThat(events).hasSize(1);
        StoredAuditEvent event = events.getFirst();
        assertThat(event.eventType()).isEqualTo(AuditEventType.RECORD_STORED.name());
        assertThat(event.ownerId()).isEqualTo("audit-write-alice");
        assertThat(event.actorId()).isEqualTo("audit-write-alice");
        assertThat(event.vaultId()).isEqualTo("vault-audit");
        assertThat(event.targetType()).isEqualTo("record");
        assertThat(event.targetId()).isEqualTo("secret-audit");
        assertThat(event.revision()).isEqualTo(7);
        assertThat(event.details()).contains("API_TOKEN");
        assertThat(event.details()).doesNotContain("encrypted-profile-sentinel");
        assertThat(event.details()).doesNotContain("encrypted-envelope-sentinel");
    }

    @Test
    void recordDeleteCreatesRedactedAuditEvent() throws Exception {
        createVault("audit-delete-alice", "vault-delete-audit");
        putRecord(
                "audit-delete-alice",
                "vault-delete-audit",
                "secret-delete-audit",
                1,
                "LOGIN_PASSWORD",
                "encrypted-profile-delete-sentinel",
                "encrypted-envelope-delete-sentinel");

        mvc.perform(
                        delete("/api/v1/vaults/vault-delete-audit/records/secret-delete-audit")
                                .with(user("audit-delete-alice"))
                                .param("revision", "2"))
                .andExpect(status().isNoContent());

        List<StoredAuditEvent> events = auditEvents.listForOwner("audit-delete-alice");

        assertThat(events).hasSize(2);
        StoredAuditEvent event = events.get(1);
        assertThat(event.eventType()).isEqualTo(AuditEventType.RECORD_DELETED.name());
        assertThat(event.ownerId()).isEqualTo("audit-delete-alice");
        assertThat(event.actorId()).isEqualTo("audit-delete-alice");
        assertThat(event.vaultId()).isEqualTo("vault-delete-audit");
        assertThat(event.targetType()).isEqualTo("record");
        assertThat(event.targetId()).isEqualTo("secret-delete-audit");
        assertThat(event.revision()).isEqualTo(2);
        assertThat(event.details()).contains("\"deleted\":true");
        assertThat(event.details()).doesNotContain("encrypted-profile-delete-sentinel");
        assertThat(event.details()).doesNotContain("encrypted-envelope-delete-sentinel");
    }

    private void putRecord(
            String username,
            String vaultId,
            String secretId,
            long revision,
            String secretType,
            String encryptedProfile,
            String envelope)
            throws Exception {
        mvc.perform(
                        put("/api/v1/vaults/{vaultId}/records/{secretId}", vaultId, secretId)
                                .with(user(username))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "revision": %d,
                                          "secretType": "%s",
                                          "encryptedProfile": "%s",
                                          "envelope": "%s",
                                          "deleted": false
                                        }
                                        """
                                                .formatted(
                                                        revision,
                                                        secretType,
                                                        encryptedProfile,
                                                        envelope)))
                .andExpect(status().isCreated());
    }

    private void createVault(String username, String vaultId) throws Exception {
        mvc.perform(
                        put("/api/v1/vaults/{vaultId}", vaultId)
                                .with(user(username))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "encryptedMetadata": "encrypted-vault-metadata"
                                        }
                                        """))
                .andExpect(status().isCreated());
    }
}
