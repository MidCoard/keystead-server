package top.focess.keystead.server.vault;

import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.doThrow;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import jakarta.persistence.EntityManager;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.util.Base64;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class VaultPackageCoverageApiTest {

    private static final String KEY_ALGORITHM = "RSA_OAEP_SHA256";

    @Autowired private MockMvc mvc;
    @Autowired private EntityManager entityManager;
    @Autowired private PlatformTransactionManager transactionManager;
    @Autowired private VaultKeyPackageService service;
    @Autowired private VaultMemberRepository members;
    @MockitoSpyBean private VaultKeyPackageRepository keyPackages;

    @Test
    void managersSeeOnlyEligibleVaultRecipientsAndExactCurrentCoverage() throws Exception {
        String suffix = Long.toUnsignedString(System.nanoTime());
        String owner = "coverage-owner-" + suffix;
        String admin = "coverage-admin-" + suffix;
        String viewer = "coverage-viewer-" + suffix;
        String pending = "coverage-pending-" + suffix;
        String invited = "coverage-invited-" + suffix;
        String outsider = "coverage-outsider-" + suffix;
        String vaultId = "coverage-vault-" + suffix;
        for (String userId : new String[] {owner, admin, viewer, pending, invited, outsider}) {
            registerUser(userId);
            registerDevice(userId, userId + "-device", true);
        }
        registerDevice(pending, pending + "-unverified", false);
        registerDevice(pending, pending + "-revoked", true);
        revoke(pending, pending + "-revoked");
        createVault(owner, vaultId);
        putOwnerPackage(owner, vaultId, owner + "-device", "key-current");
        inviteAndAccept(owner, admin, vaultId, "ADMIN");
        putRecipientPackage(owner, vaultId, admin, admin + "-device", "key-current", 201);
        inviteAndAccept(owner, viewer, vaultId, "VIEWER");
        putRecipientPackage(owner, vaultId, viewer, viewer + "-device", "key-current", 201);
        registerDevice(viewer, viewer + "-second-device", true);
        inviteAndAccept(owner, pending, vaultId, "EDITOR");
        invite(owner, invited, vaultId, "VIEWER");

        mvc.perform(get("/api/v1/vaults/{vaultId}/package-recipients", vaultId).with(user(owner)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.currentVaultKeyId").value("key-current"))
                .andExpect(jsonPath("$.keyLifecycleState").value("STABLE"))
                .andExpect(jsonPath("$.lifecycleVersion").value(1))
                .andExpect(jsonPath("$.devices[*].userId").value(hasItem(owner)))
                .andExpect(jsonPath("$.devices[*].userId").value(hasItem(admin)))
                .andExpect(jsonPath("$.devices[*].userId").value(hasItem(viewer)))
                .andExpect(jsonPath("$.devices[*].userId").value(hasItem(pending)))
                .andExpect(jsonPath("$.devices[*].userId").value(not(hasItem(invited))))
                .andExpect(jsonPath("$.devices[*].userId").value(not(hasItem(outsider))))
                .andExpect(
                        jsonPath(
                                        "$.devices[?(@.deviceId == '%s')].covered"
                                                .formatted(owner + "-device"))
                                .value(hasItem(true)))
                .andExpect(
                        jsonPath(
                                        "$.devices[?(@.deviceId == '%s')].covered"
                                                .formatted(viewer + "-second-device"))
                                .value(hasItem(false)))
                .andExpect(
                        jsonPath(
                                        "$.devices[?(@.deviceId == '%s')].memberState"
                                                .formatted(pending + "-device"))
                                .value(hasItem("ACCEPTED_PENDING_KEY")))
                .andExpect(
                        jsonPath("$.devices[*].deviceId")
                                .value(not(hasItem(pending + "-unverified"))))
                .andExpect(
                        jsonPath("$.devices[*].deviceId").value(not(hasItem(pending + "-revoked"))))
                .andExpect(jsonPath("$.devices[0].encryptedVaultKey").doesNotExist());

        mvc.perform(get("/api/v1/vaults/{vaultId}/package-recipients", vaultId).with(user(admin)))
                .andExpect(status().isOk());
        for (String denied : new String[] {viewer, pending, outsider}) {
            mvc.perform(
                            get("/api/v1/vaults/{vaultId}/package-recipients", vaultId)
                                    .with(user(denied)))
                    .andExpect(status().isNotFound());
        }
    }

    @Test
    void firstExactCurrentPackageAtomicallyActivatesPendingMember() throws Exception {
        String suffix = Long.toUnsignedString(System.nanoTime());
        String owner = "activation-owner-" + suffix;
        String recipient = "activation-recipient-" + suffix;
        String outsider = "activation-outsider-" + suffix;
        String vaultId = "activation-vault-" + suffix;
        registerUser(owner);
        registerUser(recipient);
        registerUser(outsider);
        registerDevice(owner, owner + "-device", true);
        registerDevice(recipient, recipient + "-device", true);
        registerDevice(outsider, outsider + "-device", true);
        createVault(owner, vaultId);
        putOwnerPackage(owner, vaultId, owner + "-device", "key-current");
        inviteAndAccept(owner, recipient, vaultId, "EDITOR");

        putRecipientPackage(owner, vaultId, recipient, recipient + "-device", "key-stale", 400);
        assertMembershipState(recipient, vaultId, "ACCEPTED_PENDING_KEY");
        putRecipientPackage(owner, vaultId, recipient, outsider + "-device", "key-current", 404);
        assertMembershipState(recipient, vaultId, "ACCEPTED_PENDING_KEY");

        putRecipientPackage(owner, vaultId, recipient, recipient + "-device", "key-current", 201);
        assertMembershipState(recipient, vaultId, "ACTIVE");
        mvc.perform(get("/api/v1/vaults/{vaultId}/records", vaultId).with(user(recipient)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isEmpty());
    }

    @Test
    void ownerFirstPackageEstablishesKeyAndInvalidPackageLeavesMemberPending() throws Exception {
        String suffix = Long.toUnsignedString(System.nanoTime());
        String owner = "initial-owner-" + suffix;
        String recipient = "initial-recipient-" + suffix;
        String vaultId = "initial-vault-" + suffix;
        registerUser(owner);
        registerUser(recipient);
        registerDevice(owner, owner + "-device", true);
        registerDevice(recipient, recipient + "-device", true);
        createVault(owner, vaultId);

        putOwnerPackage(owner, vaultId, owner + "-device", "first-key");
        mvc.perform(get("/api/v1/vaults").with(user(owner)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].currentVaultKeyId").value("first-key"))
                .andExpect(jsonPath("$[0].lifecycleVersion").value(1));

        inviteAndAccept(owner, recipient, vaultId, "VIEWER");
        mvc.perform(
                        put(
                                        "/api/v1/vaults/{vaultId}/key-packages/recipients/{recipientId}/devices/{deviceId}",
                                        vaultId,
                                        recipient,
                                        recipient + "-device")
                                .with(user(owner))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "vaultKeyId": "first-key",
                                          "keyAlgorithm": "RSA_OAEP_SHA256",
                                          "encryptedVaultKey": "%s"
                                        }
                                        """
                                                .formatted("x".repeat(16_385))))
                .andExpect(status().isBadRequest());
        assertMembershipState(recipient, vaultId, "ACCEPTED_PENDING_KEY");
    }

    @Test
    void packageInsertFailureRollsBackPendingMemberActivation() throws Exception {
        String suffix = Long.toUnsignedString(System.nanoTime());
        String owner = "rollback-owner-" + suffix;
        String recipient = "rollback-recipient-" + suffix;
        String vaultId = "rollback-vault-" + suffix;
        String ownerDevice = owner + "-device";
        String recipientDevice = recipient + "-device";
        registerUser(owner);
        registerUser(recipient);
        registerDevice(owner, ownerDevice, true);
        registerDevice(recipient, recipientDevice, true);
        createVault(owner, vaultId);
        putOwnerPackage(owner, vaultId, ownerDevice, "rollback-key");
        inviteAndAccept(owner, recipient, vaultId, "VIEWER");
        doThrow(new DataIntegrityViolationException("injected package insert failure"))
                .when(keyPackages)
                .insert(argThat(value -> value.recipientId().equals(recipient)));

        assertThrows(
                DataIntegrityViolationException.class,
                () ->
                        service.putForRecipient(
                                owner,
                                vaultId,
                                recipient,
                                recipientDevice,
                                new VaultKeyPackageRequest(
                                        "rollback-key",
                                        KEY_ALGORITHM,
                                        "opaque-device-wrapped-vault-key")));

        assertEquals(
                VaultMemberState.ACCEPTED_PENDING_KEY,
                members.find(vaultId, recipient).orElseThrow().state());
        assertEquals(
                0, keyPackages.find(owner, vaultId, recipient, recipientDevice).stream().count());
    }

    private void registerUser(@NonNull String username) throws Exception {
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

    private void registerDevice(@NonNull String username, @NonNull String deviceId, boolean verify)
            throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        String proofPublicKey =
                Base64.getEncoder()
                        .encodeToString(generator.generateKeyPair().getPublic().getEncoded());
        mvc.perform(
                        post("/api/v1/devices")
                                .with(user(username))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "deviceId": "%s",
                                          "keyAlgorithm": "RSA_OAEP_SHA256",
                                          "publicKey": "%s",
                                          "wrappingKeyAlgorithm": "RSA_OAEP_SHA256",
                                          "wrappingPublicKey": "wrapping-public-%s"
                                        }
                                        """
                                                .formatted(deviceId, proofPublicKey, deviceId)))
                .andExpect(status().isCreated());
        if (verify) {
            updateDevice(username, deviceId, true, false);
        }
    }

    private void revoke(@NonNull String username, @NonNull String deviceId) throws Exception {
        mvc.perform(delete("/api/v1/devices/{deviceId}", deviceId).with(user(username)))
                .andExpect(status().isNoContent());
    }

    private void updateDevice(
            @NonNull String username, @NonNull String deviceId, boolean verified, boolean revoked) {
        new TransactionTemplate(transactionManager)
                .executeWithoutResult(
                        ignored ->
                                entityManager
                                        .createQuery(
                                                """
                                                update DeviceEntity d
                                                   set d.verifiedAt = :verifiedAt,
                                                       d.lastSeenAt = :verifiedAt,
                                                       d.revokedAt = :revokedAt
                                                 where d.id.ownerId = :username
                                                   and d.id.deviceId = :deviceId
                                                """)
                                        .setParameter("verifiedAt", verified ? Instant.now() : null)
                                        .setParameter(
                                                "revokedAt",
                                                revoked ? Instant.now().plusSeconds(1) : null)
                                        .setParameter("username", username)
                                        .setParameter("deviceId", deviceId)
                                        .executeUpdate());
    }

    private void createVault(@NonNull String owner, @NonNull String vaultId) throws Exception {
        mvc.perform(
                        put("/api/v1/vaults/{vaultId}", vaultId)
                                .with(user(owner))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"encryptedMetadata\":\"opaque-metadata\"}"))
                .andExpect(status().isCreated());
    }

    private void invite(
            @NonNull String owner,
            @NonNull String recipient,
            @NonNull String vaultId,
            @NonNull String role)
            throws Exception {
        mvc.perform(
                        put("/api/v1/vaults/{vaultId}/members/{recipient}", vaultId, recipient)
                                .with(user(owner))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"role\":\"%s\"}".formatted(role)))
                .andExpect(status().isCreated());
    }

    private void inviteAndAccept(
            @NonNull String owner,
            @NonNull String recipient,
            @NonNull String vaultId,
            @NonNull String role)
            throws Exception {
        invite(owner, recipient, vaultId, role);
        mvc.perform(post("/api/v1/vaults/{vaultId}/members/accept", vaultId).with(user(recipient)))
                .andExpect(status().isNoContent());
    }

    private void putOwnerPackage(
            @NonNull String owner,
            @NonNull String vaultId,
            @NonNull String deviceId,
            @NonNull String keyId)
            throws Exception {
        mvc.perform(
                        put("/api/v1/vaults/{vaultId}/key-packages/{deviceId}", vaultId, deviceId)
                                .with(user(owner))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(packageBody(keyId)))
                .andExpect(status().isCreated());
    }

    private void putRecipientPackage(
            @NonNull String owner,
            @NonNull String vaultId,
            @NonNull String recipient,
            @NonNull String deviceId,
            @NonNull String keyId,
            int statusCode)
            throws Exception {
        mvc.perform(
                        put(
                                        "/api/v1/vaults/{vaultId}/key-packages/recipients/{recipient}/devices/{deviceId}",
                                        vaultId,
                                        recipient,
                                        deviceId)
                                .with(user(owner))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(packageBody(keyId)))
                .andExpect(status().is(statusCode));
    }

    private void assertMembershipState(
            @NonNull String username, @NonNull String vaultId, @NonNull String state)
            throws Exception {
        mvc.perform(get("/api/v1/vaults").with(user(username)))
                .andExpect(status().isOk())
                .andExpect(
                        jsonPath("$[?(@.vaultId == '%s')].membershipState".formatted(vaultId))
                                .value(hasItem(state)));
    }

    private static @NonNull String packageBody(@NonNull String keyId) {
        return """
        {
          "vaultKeyId": "%s",
          "keyAlgorithm": "%s",
          "encryptedVaultKey": "opaque-device-wrapped-vault-key"
        }
        """
                .formatted(keyId, KEY_ALGORITHM);
    }
}
