package top.focess.keystead.server.audit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.jayway.jsonpath.JsonPath;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataIntegrityViolationException;
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
    void databaseAppendRejectsDuplicateAuditEventId() {
        auditEvents.append(auditEvent("duplicate-audit-event"));

        assertThrows(
                DataIntegrityViolationException.class,
                () -> auditEvents.append(auditEvent("duplicate-audit-event")));
    }

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

    @Test
    void recordRevisionConflictCreatesRedactedAuditEvent() throws Exception {
        createVault("audit-conflict-alice", "vault-conflict-audit");
        putRecord(
                "audit-conflict-alice",
                "vault-conflict-audit",
                "secret-conflict-audit",
                4,
                "API_TOKEN",
                "encrypted-profile-existing-sentinel",
                "encrypted-envelope-existing-sentinel");

        mvc.perform(
                        put("/api/v1/vaults/vault-conflict-audit/records/secret-conflict-audit")
                                .with(user("audit-conflict-alice"))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "revision": 3,
                                          "secretType": "API_TOKEN",
                                          "encryptedProfile": "encrypted-profile-rejected-sentinel",
                                          "envelope": "encrypted-envelope-rejected-sentinel",
                                          "deleted": false
                                        }
                                        """))
                .andExpect(status().isConflict());

        List<StoredAuditEvent> events = auditEvents.listForOwner("audit-conflict-alice");

        assertThat(events).hasSize(2);
        StoredAuditEvent event = events.get(1);
        assertThat(event.eventType()).isEqualTo(AuditEventType.RECORD_REVISION_CONFLICT.name());
        assertThat(event.ownerId()).isEqualTo("audit-conflict-alice");
        assertThat(event.actorId()).isEqualTo("audit-conflict-alice");
        assertThat(event.vaultId()).isEqualTo("vault-conflict-audit");
        assertThat(event.targetType()).isEqualTo("record");
        assertThat(event.targetId()).isEqualTo("secret-conflict-audit");
        assertThat(event.revision()).isEqualTo(3);
        assertThat(event.outcome()).isEqualTo("CONFLICT");
        assertThat(event.details()).contains("\"latestRevision\":4");
        assertThat(event.details()).contains("\"rejectedRevision\":3");
        assertThat(event.details()).doesNotContain("encrypted-profile-rejected-sentinel");
        assertThat(event.details()).doesNotContain("encrypted-envelope-rejected-sentinel");
    }

    @Test
    void staleRecordDeleteCreatesRedactedConflictAuditEvent() throws Exception {
        createVault("audit-delete-conflict-alice", "vault-delete-conflict-audit");
        putRecord(
                "audit-delete-conflict-alice",
                "vault-delete-conflict-audit",
                "secret-delete-conflict-audit",
                5,
                "LOGIN_PASSWORD",
                "encrypted-profile-delete-conflict-sentinel",
                "encrypted-envelope-delete-conflict-sentinel");

        mvc.perform(
                        delete(
                                        "/api/v1/vaults/vault-delete-conflict-audit/records/secret-delete-conflict-audit")
                                .with(user("audit-delete-conflict-alice"))
                                .param("revision", "4"))
                .andExpect(status().isConflict());

        List<StoredAuditEvent> events = auditEvents.listForOwner("audit-delete-conflict-alice");

        assertThat(events).hasSize(2);
        StoredAuditEvent event = events.get(1);
        assertThat(event.eventType()).isEqualTo(AuditEventType.RECORD_REVISION_CONFLICT.name());
        assertThat(event.ownerId()).isEqualTo("audit-delete-conflict-alice");
        assertThat(event.actorId()).isEqualTo("audit-delete-conflict-alice");
        assertThat(event.vaultId()).isEqualTo("vault-delete-conflict-audit");
        assertThat(event.targetType()).isEqualTo("record");
        assertThat(event.targetId()).isEqualTo("secret-delete-conflict-audit");
        assertThat(event.revision()).isEqualTo(4);
        assertThat(event.outcome()).isEqualTo("CONFLICT");
        assertThat(event.details()).contains("\"latestRevision\":5");
        assertThat(event.details()).contains("\"rejectedRevision\":4");
        assertThat(event.details()).doesNotContain("encrypted-profile-delete-conflict-sentinel");
        assertThat(event.details()).doesNotContain("encrypted-envelope-delete-conflict-sentinel");
    }

    @Test
    void keyPackageWriteCreatesRedactedAuditEvent() throws Exception {
        registerUser("audit-package-alice");
        registerVerifiedDevice("audit-package-alice", "audit-laptop-1");
        createVaultWithPasswordUser("audit-package-alice", "vault-package-audit");

        mvc.perform(
                        put("/api/v1/vaults/vault-package-audit/key-packages/audit-laptop-1")
                                .with(
                                        httpBasic(
                                                "audit-package-alice",
                                                "correct horse battery staple"))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "keyAlgorithm": "RSA_OAEP_SHA256",
                                          "encryptedVaultKey": "wrapped-vault-key-audit-sentinel"
                                        }
                                        """))
                .andExpect(status().isCreated());

        List<StoredAuditEvent> events = auditEvents.listForOwner("audit-package-alice");

        assertThat(events).hasSize(1);
        StoredAuditEvent event = events.getFirst();
        assertThat(event.eventType()).isEqualTo(AuditEventType.KEY_PACKAGE_STORED.name());
        assertThat(event.ownerId()).isEqualTo("audit-package-alice");
        assertThat(event.actorId()).isEqualTo("audit-package-alice");
        assertThat(event.vaultId()).isEqualTo("vault-package-audit");
        assertThat(event.targetType()).isEqualTo("key_package");
        assertThat(event.targetId()).isEqualTo("audit-laptop-1");
        assertThat(event.revision()).isNull();
        assertThat(event.details()).contains("vaultKeyId");
        assertThat(event.details()).contains("RSA_OAEP_SHA256");
        assertThat(event.details()).doesNotContain("wrapped-vault-key-audit-sentinel");
    }

    @Test
    void deviceRevocationCreatesRedactedAuditEvent() throws Exception {
        registerUser("audit-revoke-alice");
        registerVerifiedDevice("audit-revoke-alice", "audit-revoke-laptop");

        mvc.perform(
                        delete("/api/v1/devices/audit-revoke-laptop")
                                .with(
                                        httpBasic(
                                                "audit-revoke-alice",
                                                "correct horse battery staple")))
                .andExpect(status().isNoContent());

        List<StoredAuditEvent> events = auditEvents.listForOwner("audit-revoke-alice");

        assertThat(events).hasSize(1);
        StoredAuditEvent event = events.getFirst();
        assertThat(event.eventType()).isEqualTo(AuditEventType.DEVICE_REVOKED.name());
        assertThat(event.ownerId()).isEqualTo("audit-revoke-alice");
        assertThat(event.actorId()).isEqualTo("audit-revoke-alice");
        assertThat(event.vaultId()).isNull();
        assertThat(event.targetType()).isEqualTo("device");
        assertThat(event.targetId()).isEqualTo("audit-revoke-laptop");
        assertThat(event.revision()).isNull();
        assertThat(event.details()).contains("\"revoked\":true");
        assertThat(event.details()).doesNotContain("public-key");
        assertThat(event.details()).doesNotContain("PRIVATE KEY");
    }

    @Test
    void loginFailureCreatesRedactedAuditEvent() throws Exception {
        registerUser("audit-login-alice");

        mvc.perform(
                        get("/api/v1/devices")
                                .with(httpBasic("audit-login-alice", "wrong-password-sentinel")))
                .andExpect(status().isUnauthorized());

        List<StoredAuditEvent> events = auditEvents.listForOwner("audit-login-alice");

        assertThat(events).hasSize(1);
        StoredAuditEvent event = events.getFirst();
        assertThat(event.eventType()).isEqualTo(AuditEventType.LOGIN_FAILED.name());
        assertThat(event.ownerId()).isEqualTo("audit-login-alice");
        assertThat(event.actorId()).isEqualTo("audit-login-alice");
        assertThat(event.vaultId()).isNull();
        assertThat(event.targetType()).isEqualTo("auth");
        assertThat(event.targetId()).isEqualTo("audit-login-alice");
        assertThat(event.revision()).isNull();
        assertThat(event.details()).contains("\"reason\":\"BAD_CREDENTIALS\"");
        assertThat(event.details()).doesNotContain("wrong-password-sentinel");
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

    private void registerUser(String username) throws Exception {
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

    private void registerVerifiedDevice(String username, String deviceId) throws Exception {
        KeyPair keyPair = rsaKeyPair();
        registerDevice(
                username,
                deviceId,
                Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
        String challengeJson =
                mvc.perform(
                                post("/api/v1/devices/{deviceId}/challenges", deviceId)
                                        .with(httpBasic(username, "correct horse battery staple")))
                        .andExpect(status().isCreated())
                        .andReturn()
                        .getResponse()
                        .getContentAsString();
        String challengeId = JsonPath.read(challengeJson, "$.challengeId");
        String nonce = JsonPath.read(challengeJson, "$.nonce");
        String signature = signature(keyPair.getPrivate(), challengeId, nonce);
        mvc.perform(
                        post("/api/v1/devices/{deviceId}/proof", deviceId)
                                .with(httpBasic(username, "correct horse battery staple"))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "challengeId": "%s",
                                          "signature": "%s"
                                        }
                                        """
                                                .formatted(challengeId, signature)))
                .andExpect(status().isNoContent());
    }

    private void registerDevice(String username, String deviceId, String publicKey)
            throws Exception {
        mvc.perform(
                        post("/api/v1/devices")
                                .with(httpBasic(username, "correct horse battery staple"))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "deviceId": "%s",
                                          "keyAlgorithm": "RSA_OAEP_SHA256",
                                          "publicKey": "%s"
                                        }
                                        """
                                                .formatted(deviceId, publicKey)))
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

    private void createVaultWithPasswordUser(String username, String vaultId) throws Exception {
        mvc.perform(
                        put("/api/v1/vaults/{vaultId}", vaultId)
                                .with(httpBasic(username, "correct horse battery staple"))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "encryptedMetadata": "encrypted-vault-metadata"
                                        }
                                        """))
                .andExpect(status().isCreated());
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

    private static StoredAuditEvent auditEvent(String eventId) {
        return new StoredAuditEvent(
                eventId,
                "audit-db-owner",
                "audit-db-actor",
                AuditEventType.RECORD_STORED.name(),
                "record",
                "secret-a",
                "vault-a",
                1L,
                "SUCCESS",
                "{}",
                java.time.Instant.parse("2026-07-09T00:00:00Z"));
    }
}
