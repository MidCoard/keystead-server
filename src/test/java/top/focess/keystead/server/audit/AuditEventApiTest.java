package top.focess.keystead.server.audit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.jayway.jsonpath.JsonPath;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.Base64;
import java.util.List;
import java.util.regex.Pattern;
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

    private static final Pattern GENERATED_CORRELATION_ID =
            Pattern.compile("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$");

    @Test
    void databaseAppendRejectsDuplicateAuditEventId() {
        auditEvents.append(auditEvent("duplicate-audit-event"), null);

        assertThrows(
                DataIntegrityViolationException.class,
                () -> auditEvents.append(auditEvent("duplicate-audit-event"), null));
    }

    @Test
    void auditEventsAreQueryableByOwnerAndVaultWithoutCrossOwnerLeakage() {
        auditEvents.append(auditEvent("vault-query-a"), null);
        auditEvents.append(
                new StoredAuditEvent(
                        "vault-query-b",
                        "other-owner",
                        "other-actor",
                        AuditEventType.RECORD_STORED.name(),
                        "record",
                        "secret-a",
                        "vault-a",
                        1L,
                        "SUCCESS",
                        "{}",
                        java.time.Instant.parse("2026-07-09T00:00:01Z")),
                null);

        assertThat(auditEvents.listForOwnerAndVault("audit-db-owner", "vault-a"))
                .extracting(StoredAuditEvent::eventId)
                .contains("vault-query-a")
                .doesNotContain("vault-query-b");
        assertThat(auditEvents.listForOwnerAndVault("other-owner", "vault-a"))
                .extracting(StoredAuditEvent::eventId)
                .contains("vault-query-b")
                .doesNotContain("vault-query-a");
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
    void repeatedDeviceRevocationCreatesExactlyOneRedactedAuditEvent() throws Exception {
        registerUser("audit-revoke-alice");
        registerVerifiedDevice("audit-revoke-alice", "audit-revoke-laptop");

        mvc.perform(
                        delete("/api/v1/devices/audit-revoke-laptop")
                                .with(
                                        httpBasic(
                                                "audit-revoke-alice",
                                                "correct horse battery staple")))
                .andExpect(status().isNoContent());
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

    @Test
    void auditEventCarriesInboundCorrelationIdHeader() throws Exception {
        createVault("corr-header-alice", "vault-corr-header");

        mvc.perform(
                        put("/api/v1/vaults/vault-corr-header/records/secret-corr-header")
                                .with(user("corr-header-alice"))
                                .header(CorrelationIdFilter.CORRELATION_ID_HEADER, "corr-abc-123")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "revision": 1,
                                          "secretType": "API_TOKEN",
                                          "encryptedProfile": "encrypted-profile-corr-sentinel",
                                          "envelope": "encrypted-envelope-corr-sentinel",
                                          "deleted": false
                                        }
                                        """))
                .andExpect(status().isCreated())
                .andExpect(
                        header().string(CorrelationIdFilter.CORRELATION_ID_HEADER, "corr-abc-123"));

        List<AuditEventEntity> entities = auditEvents.listEntitiesForOwner("corr-header-alice");
        assertThat(entities).hasSize(1);
        assertThat(entities.getFirst().correlationId).isEqualTo("corr-abc-123");
    }

    @Test
    void auditEventGeneratesCorrelationIdWhenHeaderAbsent() throws Exception {
        createVault("corr-gen-alice", "vault-corr-gen");

        mvc.perform(
                        put("/api/v1/vaults/vault-corr-gen/records/secret-corr-gen")
                                .with(user("corr-gen-alice"))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "revision": 1,
                                          "secretType": "API_TOKEN",
                                          "encryptedProfile": "encrypted-profile-gen-sentinel",
                                          "envelope": "encrypted-envelope-gen-sentinel",
                                          "deleted": false
                                        }
                                        """))
                .andExpect(status().isCreated())
                .andExpect(header().exists(CorrelationIdFilter.CORRELATION_ID_HEADER));

        List<AuditEventEntity> entities = auditEvents.listEntitiesForOwner("corr-gen-alice");
        assertThat(entities).hasSize(1);
        assertThat(entities.getFirst().correlationId).matches(GENERATED_CORRELATION_ID);
    }

    @Test
    void loginFailureAuditCarriesInboundCorrelationIdHeader() throws Exception {
        registerUser("corr-login-alice");

        mvc.perform(
                        get("/api/v1/devices")
                                .with(httpBasic("corr-login-alice", "wrong-password-corr-sentinel"))
                                .header(CorrelationIdFilter.CORRELATION_ID_HEADER, "corr-login-1"))
                .andExpect(status().isUnauthorized())
                .andExpect(
                        header().string(CorrelationIdFilter.CORRELATION_ID_HEADER, "corr-login-1"));

        List<AuditEventEntity> entities = auditEvents.listEntitiesForOwner("corr-login-alice");
        assertThat(entities).hasSize(1);
        assertThat(entities.getFirst().correlationId).isEqualTo("corr-login-1");
    }

    @Test
    void membershipLifecycleCreatesRedactedAuditEvents() throws Exception {
        String suffix = Long.toUnsignedString(System.nanoTime());
        String owner = "member-audit-owner-" + suffix;
        String invitee = "member-audit-invitee-" + suffix;
        String vaultId = "member-audit-vault-" + suffix;
        registerUser(owner);
        registerUser(invitee);
        createVaultWithPasswordUser(owner, vaultId);

        invite(owner, invitee, vaultId, "VIEWER");
        accept(invitee, vaultId);
        changeRole(owner, invitee, vaultId, "EDITOR");
        removeMember(owner, invitee, vaultId);

        List<StoredAuditEvent> events = auditEvents.listForOwner(owner);
        assertThat(events).hasSize(4);

        StoredAuditEvent invited = singleEvent(events, AuditEventType.VAULT_MEMBER_INVITED);
        assertThat(invited.ownerId()).isEqualTo(owner);
        assertThat(invited.actorId()).isEqualTo(owner);
        assertThat(invited.targetType()).isEqualTo("vault_member");
        assertThat(invited.targetId()).isEqualTo(invitee);
        assertThat(invited.vaultId()).isEqualTo(vaultId);
        assertThat(invited.revision()).isNull();
        assertThat(invited.outcome()).isEqualTo("SUCCESS");
        assertThat(invited.details()).contains("\"role\":\"VIEWER\"");

        StoredAuditEvent accepted = singleEvent(events, AuditEventType.VAULT_MEMBER_ACCEPTED);
        assertThat(accepted.ownerId()).isEqualTo(owner);
        assertThat(accepted.actorId()).isEqualTo(invitee);
        assertThat(accepted.targetId()).isEqualTo(invitee);
        assertThat(accepted.details()).contains("\"accepted\":true");

        StoredAuditEvent roleChanged =
                singleEvent(events, AuditEventType.VAULT_MEMBER_ROLE_CHANGED);
        assertThat(roleChanged.actorId()).isEqualTo(owner);
        assertThat(roleChanged.details()).contains("\"fromRole\":\"VIEWER\"");
        assertThat(roleChanged.details()).contains("\"toRole\":\"EDITOR\"");

        StoredAuditEvent removed = singleEvent(events, AuditEventType.VAULT_MEMBER_REMOVED);
        assertThat(removed.actorId()).isEqualTo(owner);
        assertThat(removed.details()).contains("\"removed\":true");
    }

    @Test
    void membershipDeclineCreatesRedactedAuditEvent() throws Exception {
        String suffix = Long.toUnsignedString(System.nanoTime());
        String owner = "decline-audit-owner-" + suffix;
        String invitee = "decline-audit-invitee-" + suffix;
        String vaultId = "decline-audit-vault-" + suffix;
        registerUser(owner);
        registerUser(invitee);
        createVaultWithPasswordUser(owner, vaultId);

        invite(owner, invitee, vaultId, "VIEWER");
        decline(invitee, vaultId);

        List<StoredAuditEvent> events = auditEvents.listForOwner(owner);
        assertThat(events).hasSize(2);

        StoredAuditEvent invited = singleEvent(events, AuditEventType.VAULT_MEMBER_INVITED);
        assertThat(invited.actorId()).isEqualTo(owner);

        StoredAuditEvent declined = singleEvent(events, AuditEventType.VAULT_MEMBER_DECLINED);
        assertThat(declined.ownerId()).isEqualTo(owner);
        assertThat(declined.actorId()).isEqualTo(invitee);
        assertThat(declined.targetType()).isEqualTo("vault_member");
        assertThat(declined.targetId()).isEqualTo(invitee);
        assertThat(declined.vaultId()).isEqualTo(vaultId);
        assertThat(declined.outcome()).isEqualTo("SUCCESS");
        assertThat(declined.details()).contains("\"declined\":true");
    }

    @Test
    void idempotentReinviteDoesNotDuplicateAuditEvent() throws Exception {
        String suffix = Long.toUnsignedString(System.nanoTime());
        String owner = "reinvite-audit-owner-" + suffix;
        String invitee = "reinvite-audit-invitee-" + suffix;
        String vaultId = "reinvite-audit-vault-" + suffix;
        registerUser(owner);
        registerUser(invitee);
        createVaultWithPasswordUser(owner, vaultId);

        invite(owner, invitee, vaultId, "VIEWER");
        invite(owner, invitee, vaultId, "VIEWER");

        List<StoredAuditEvent> events = auditEvents.listForOwner(owner);
        assertThat(events).hasSize(1);
        assertThat(events.getFirst().eventType())
                .isEqualTo(AuditEventType.VAULT_MEMBER_INVITED.name());
    }

    private StoredAuditEvent singleEvent(List<StoredAuditEvent> events, AuditEventType type) {
        List<StoredAuditEvent> matches =
                events.stream().filter(e -> e.eventType().equals(type.name())).toList();
        assertThat(matches).hasSize(1);
        return matches.getFirst();
    }

    private void invite(String owner, String invitee, String vaultId, String role)
            throws Exception {
        mvc.perform(
                        put("/api/v1/vaults/{vaultId}/members/{userId}", vaultId, invitee)
                                .with(httpBasic(owner, "correct horse battery staple"))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"role\":\"%s\"}".formatted(role)))
                .andExpect(status().isCreated());
    }

    private void accept(String invitee, String vaultId) throws Exception {
        mvc.perform(
                        post("/api/v1/vaults/{vaultId}/members/accept", vaultId)
                                .with(httpBasic(invitee, "correct horse battery staple")))
                .andExpect(status().isNoContent());
    }

    private void decline(String invitee, String vaultId) throws Exception {
        mvc.perform(
                        post("/api/v1/vaults/{vaultId}/members/decline", vaultId)
                                .with(httpBasic(invitee, "correct horse battery staple")))
                .andExpect(status().isNoContent());
    }

    private void changeRole(String owner, String invitee, String vaultId, String role)
            throws Exception {
        mvc.perform(
                        put("/api/v1/vaults/{vaultId}/members/{userId}/role", vaultId, invitee)
                                .with(httpBasic(owner, "correct horse battery staple"))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"role\":\"%s\"}".formatted(role)))
                .andExpect(status().isNoContent());
    }

    private void removeMember(String owner, String invitee, String vaultId) throws Exception {
        mvc.perform(
                        delete("/api/v1/vaults/{vaultId}/members/{userId}", vaultId, invitee)
                                .with(httpBasic(owner, "correct horse battery staple")))
                .andExpect(status().isNoContent());
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
                                          "publicKey": "%s",
                                          "wrappingKeyAlgorithm": "RSA_OAEP_SHA256",
                                          "wrappingPublicKey": "wrapping-public-key-material-%s"
                                        }
                                        """
                                                .formatted(deviceId, publicKey, deviceId)))
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
