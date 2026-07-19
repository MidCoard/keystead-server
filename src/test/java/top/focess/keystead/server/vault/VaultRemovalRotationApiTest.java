package top.focess.keystead.server.vault;

import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
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
import java.util.List;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class VaultRemovalRotationApiTest {

    @Autowired private MockMvc mvc;
    @Autowired private EntityManager entityManager;
    @Autowired private PlatformTransactionManager transactionManager;

    @Test
    void activeMemberRemovalRevokesAccessInvalidatesPackagesAndBlocksFutureWrites()
            throws Exception {
        String suffix = Long.toUnsignedString(System.nanoTime());
        String owner = "removal-owner-" + suffix;
        String removed = "removal-removed-" + suffix;
        String remaining = "removal-remaining-" + suffix;
        String vaultId = "removal-vault-" + suffix;
        for (String username : new String[] {owner, removed, remaining}) {
            registerUser(username);
            registerDevice(username, username + "-device");
        }
        createVault(owner, vaultId);
        putOwnerPackage(owner, vaultId, owner + "-device", "current-key");
        activate(owner, removed, vaultId, "EDITOR", "current-key");
        activate(owner, remaining, vaultId, "EDITOR", "current-key");
        putRecord(removed, vaultId, "record-1", 1L, 201);

        mvc.perform(
                        delete("/api/v1/vaults/{vaultId}/members/{userId}", vaultId, removed)
                                .with(user(owner)))
                .andExpect(status().isNoContent());

        mvc.perform(get("/api/v1/vaults/{vaultId}/records", vaultId).with(user(removed)))
                .andExpect(status().isNotFound());
        mvc.perform(get("/api/v1/vaults/{vaultId}/records", vaultId).with(user(remaining)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].secretId").value("record-1"));
        putRecord(owner, vaultId, "record-2", 2L, 409);
        putRecord(remaining, vaultId, "record-2", 2L, 409);
        mvc.perform(
                        put("/api/v1/vaults/{vaultId}/records/record-2", vaultId)
                                .with(user(owner))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(recordBody(2L)))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.lifecycleState").value("ROTATION_REQUIRED"));
        assertLifecycle(owner, vaultId, "ROTATION_REQUIRED");
        mvc.perform(get("/api/v1/vaults/{vaultId}/package-recipients", vaultId).with(user(owner)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.devices[*].userId").value(not(hasItem(removed))));

        String details = rotationAuditDetails(vaultId);
        assertTrue(details.contains("MEMBER_REMOVED"));
        assertTrue(details.contains(removed));
        assertFalse(details.toLowerCase().contains("encryptedvaultkey"));
        assertFalse(details.contains("opaque-device-wrapped-vault-key"));
    }

    @Test
    void pendingRemovalAndRoleChangeDoNotRequireRotation() throws Exception {
        String suffix = Long.toUnsignedString(System.nanoTime());
        String owner = "nonrotation-owner-" + suffix;
        String pending = "nonrotation-pending-" + suffix;
        String active = "nonrotation-active-" + suffix;
        String vaultId = "nonrotation-vault-" + suffix;
        for (String username : new String[] {owner, pending, active}) {
            registerUser(username);
            registerDevice(username, username + "-device");
        }
        createVault(owner, vaultId);
        putOwnerPackage(owner, vaultId, owner + "-device", "current-key");
        inviteAndAccept(owner, pending, vaultId, "VIEWER");
        mvc.perform(
                        delete("/api/v1/vaults/{vaultId}/members/{userId}", vaultId, pending)
                                .with(user(owner)))
                .andExpect(status().isNoContent());
        assertLifecycle(owner, vaultId, "STABLE");

        activate(owner, active, vaultId, "EDITOR", "current-key");
        mvc.perform(
                        put("/api/v1/vaults/{vaultId}/members/{userId}/role", vaultId, active)
                                .with(user(owner))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"role\":\"VIEWER\"}"))
                .andExpect(status().isNoContent());
        assertLifecycle(owner, vaultId, "STABLE");
    }

    @Test
    void deviceRevocationRequiresRotationOnlyForVaultsWithItsCurrentPackage() throws Exception {
        String suffix = Long.toUnsignedString(System.nanoTime());
        String owner = "device-revoke-owner-" + suffix;
        String packagedDevice = "packaged-device-" + suffix;
        String otherDevice = "other-device-" + suffix;
        String packagedVault = "device-packaged-vault-" + suffix;
        String otherVault = "device-other-vault-" + suffix;
        registerUser(owner);
        registerDevice(owner, packagedDevice);
        registerDevice(owner, otherDevice);
        createVault(owner, packagedVault);
        createVault(owner, otherVault);
        putOwnerPackage(owner, packagedVault, packagedDevice, "packaged-key");
        putOwnerPackage(owner, otherVault, otherDevice, "other-key");

        mvc.perform(delete("/api/v1/devices/{deviceId}", packagedDevice).with(user(owner)))
                .andExpect(status().isNoContent());

        assertLifecycle(owner, packagedVault, "ROTATION_REQUIRED");
        assertLifecycle(owner, otherVault, "STABLE");
        mvc.perform(get("/api/v1/vaults/{vaultId}/key-packages", packagedVault).with(user(owner)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isEmpty());
    }

    @Test
    void automationRevocationRequiresRotationOnlyWhenCurrentPackageExists() throws Exception {
        String suffix = Long.toUnsignedString(System.nanoTime());
        String owner = "automation-revoke-owner-" + suffix;
        String packagedVault = "automation-packaged-vault-" + suffix;
        String otherVault = "automation-other-vault-" + suffix;
        String packagedPrincipal = "packaged-principal-" + suffix;
        String unpackagedPrincipal = "unpackaged-principal-" + suffix;
        registerUser(owner);
        createVault(owner, packagedVault);
        createVault(owner, otherVault);
        declareCurrentKey(owner, packagedVault, "packaged-key");
        declareCurrentKey(owner, otherVault, "other-key");
        putAutomationPrincipal(owner, packagedVault, packagedPrincipal);
        putAutomationPackage(owner, packagedVault, packagedPrincipal, "packaged-key");
        putAutomationPrincipal(owner, otherVault, unpackagedPrincipal);

        mvc.perform(
                        delete(
                                        "/api/v1/vaults/{vaultId}/automation-principals/{principalId}",
                                        packagedVault,
                                        packagedPrincipal)
                                .with(user(owner)))
                .andExpect(status().isNoContent());
        mvc.perform(
                        delete(
                                        "/api/v1/vaults/{vaultId}/automation-principals/{principalId}",
                                        otherVault,
                                        unpackagedPrincipal)
                                .with(user(owner)))
                .andExpect(status().isNoContent());

        assertLifecycle(owner, packagedVault, "ROTATION_REQUIRED");
        assertLifecycle(owner, otherVault, "STABLE");
    }

    private void registerUser(@NonNull String username) throws Exception {
        mvc.perform(
                        post("/api/v1/users")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        "{\"username\":\"%s\",\"password\":\"correct horse battery staple\"}"
                                                .formatted(username)))
                .andExpect(status().isCreated());
    }

    private void registerDevice(@NonNull String username, @NonNull String deviceId)
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
        new TransactionTemplate(transactionManager)
                .executeWithoutResult(
                        ignored ->
                                entityManager
                                        .createQuery(
                                                """
                                                update DeviceEntity d
                                                   set d.verifiedAt = :now, d.lastSeenAt = :now
                                                 where d.id.ownerId = :username
                                                   and d.id.deviceId = :deviceId
                                                """)
                                        .setParameter("now", Instant.now())
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

    private void declareCurrentKey(
            @NonNull String owner, @NonNull String vaultId, @NonNull String keyId)
            throws Exception {
        mvc.perform(
                        put("/api/v1/vaults/{vaultId}/key-rotation", vaultId)
                                .with(user(owner))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"vaultKeyId\":\"%s\"}".formatted(keyId)))
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

    private void inviteAndAccept(
            @NonNull String owner,
            @NonNull String recipient,
            @NonNull String vaultId,
            @NonNull String role)
            throws Exception {
        mvc.perform(
                        put("/api/v1/vaults/{vaultId}/members/{userId}", vaultId, recipient)
                                .with(user(owner))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"role\":\"%s\"}".formatted(role)))
                .andExpect(status().isCreated());
        mvc.perform(post("/api/v1/vaults/{vaultId}/members/accept", vaultId).with(user(recipient)))
                .andExpect(status().isNoContent());
    }

    private void activate(
            @NonNull String owner,
            @NonNull String recipient,
            @NonNull String vaultId,
            @NonNull String role,
            @NonNull String keyId)
            throws Exception {
        inviteAndAccept(owner, recipient, vaultId, role);
        mvc.perform(
                        put(
                                        "/api/v1/vaults/{vaultId}/key-packages/recipients/{recipientId}/devices/{deviceId}",
                                        vaultId,
                                        recipient,
                                        recipient + "-device")
                                .with(user(owner))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(packageBody(keyId)))
                .andExpect(status().isCreated());
    }

    private void putRecord(
            @NonNull String actor,
            @NonNull String vaultId,
            @NonNull String secretId,
            long revision,
            int statusCode)
            throws Exception {
        mvc.perform(
                        put("/api/v1/vaults/{vaultId}/records/{secretId}", vaultId, secretId)
                                .with(user(actor))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(recordBody(revision)))
                .andExpect(status().is(statusCode));
    }

    private void assertLifecycle(
            @NonNull String username, @NonNull String vaultId, @NonNull String state)
            throws Exception {
        mvc.perform(get("/api/v1/vaults").with(user(username)))
                .andExpect(status().isOk())
                .andExpect(
                        jsonPath("$[?(@.vaultId == '%s')].keyLifecycleState".formatted(vaultId))
                                .value(hasItem(state)));
    }

    private void putAutomationPrincipal(
            @NonNull String owner, @NonNull String vaultId, @NonNull String principalId)
            throws Exception {
        mvc.perform(
                        put(
                                        "/api/v1/vaults/{vaultId}/automation-principals/{principalId}",
                                        vaultId,
                                        principalId)
                                .with(user(owner))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        "{\"publicKeyAlgorithm\":\"RSA_OAEP_SHA256\",\"publicKey\":\"opaque-public-key\"}"))
                .andExpect(status().isCreated());
    }

    private void putAutomationPackage(
            @NonNull String owner,
            @NonNull String vaultId,
            @NonNull String principalId,
            @NonNull String keyId)
            throws Exception {
        mvc.perform(
                        put(
                                        "/api/v1/vaults/{vaultId}/automation-principals/{principalId}/key-package",
                                        vaultId,
                                        principalId)
                                .with(user(owner))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(packageBody(keyId)))
                .andExpect(status().isCreated());
    }

    private @NonNull String rotationAuditDetails(@NonNull String vaultId) {
        return new TransactionTemplate(transactionManager)
                .execute(
                        ignored -> {
                            List<String> values =
                                    entityManager
                                            .createQuery(
                                                    """
                                                    select a.details from AuditEventEntity a
                                                     where a.eventType = 'VAULT_ROTATION_REQUIRED'
                                                       and a.vaultId = :vaultId
                                                     order by a.createdAt desc
                                                    """,
                                                    String.class)
                                            .setParameter("vaultId", vaultId)
                                            .getResultList();
                            return values.getFirst();
                        });
    }

    private static @NonNull String packageBody(@NonNull String keyId) {
        return """
        {
          "vaultKeyId": "%s",
          "keyAlgorithm": "RSA_OAEP_SHA256",
          "encryptedVaultKey": "opaque-device-wrapped-vault-key"
        }
        """
                .formatted(keyId);
    }

    private static @NonNull String recordBody(long revision) {
        return """
        {
          "revision": %d,
          "secretType": "LOGIN_PASSWORD",
          "encryptedProfile": "opaque-encrypted-profile",
          "envelope": "opaque-envelope",
          "deleted": false
        }
        """
                .formatted(revision);
    }
}
