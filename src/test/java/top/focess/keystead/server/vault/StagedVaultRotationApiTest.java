package top.focess.keystead.server.vault;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class StagedVaultRotationApiTest {

    private static final ObjectMapper JSON = new ObjectMapper();

    @Autowired private MockMvc mvc;
    @Autowired private EntityManager entityManager;
    @Autowired private PlatformTransactionManager transactionManager;

    @Test
    void rotationPackageTextRedactsCiphertext() {
        VaultRotationPackageRequest request =
                new VaultRotationPackageRequest(
                        "key-2",
                        VaultRotationTargetType.DEVICE,
                        "owner",
                        "device",
                        null,
                        null,
                        null,
                        "RSA_OAEP_SHA256",
                        "request-ciphertext-never-log");
        VaultRotationPackageResponse response =
                new VaultRotationPackageResponse(
                        "target", "key-2", "RSA_OAEP_SHA256", "response-ciphertext-never-log");

        assertFalse(request.toString().contains("request-ciphertext-never-log"));
        assertFalse(response.toString().contains("response-ciphertext-never-log"));
    }

    @Test
    void stagedRotationSnapshotsTargetsResumesAndCommitsAtomically() throws Exception {
        String suffix = Long.toUnsignedString(System.nanoTime());
        String owner = "rotation-owner-" + suffix;
        String admin = "rotation-admin-" + suffix;
        String editor = "rotation-editor-" + suffix;
        String selectedPending = "rotation-selected-" + suffix;
        String unselectedPending = "rotation-unselected-" + suffix;
        String vaultId = "rotation-vault-" + suffix;
        for (String username :
                new String[] {owner, admin, editor, selectedPending, unselectedPending}) {
            registerUser(username);
            registerDevice(username, username + "-device");
        }
        createVault(owner, vaultId);
        putOwnerPackage(owner, vaultId, owner + "-device", "key-1");
        activate(owner, admin, vaultId, "ADMIN", "key-1");
        activate(owner, editor, vaultId, "EDITOR", "key-1");
        inviteAndAccept(owner, selectedPending, vaultId, "VIEWER");
        inviteAndAccept(owner, unselectedPending, vaultId, "VIEWER");

        mvc.perform(
                        post("/api/v1/vaults/{vaultId}/rotations", vaultId)
                                .with(user(editor))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(beginBody("key-1", "key-2", 1L, Set.of())))
                .andExpect(status().isNotFound());

        JsonNode begun =
                responseJson(
                        mvc.perform(
                                        post("/api/v1/vaults/{vaultId}/rotations", vaultId)
                                                .with(user(owner))
                                                .contentType(MediaType.APPLICATION_JSON)
                                                .content(
                                                        beginBody(
                                                                "key-1",
                                                                "key-2",
                                                                1L,
                                                                Set.of(selectedPending))))
                                .andExpect(status().isCreated())
                                .andExpect(jsonPath("$.state").value("OPEN"))
                                .andExpect(jsonPath("$.sourceVaultKeyId").value("key-1"))
                                .andExpect(jsonPath("$.targetVaultKeyId").value("key-2"))
                                .andExpect(jsonPath("$.lifecycleVersion").value(2))
                                .andReturn());
        String generationId = begun.path("generationId").asText();
        mvc.perform(
                        post("/api/v1/vaults/{vaultId}/rotations", vaultId)
                                .with(user(admin))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(beginBody("key-1", "key-3", 2L, Set.of())))
                .andExpect(status().isConflict());
        List<JsonNode> targets = values(begun.path("targets"));
        assertEquals(4, targets.size());
        Set<String> recipients = new HashSet<>();
        targets.forEach(target -> recipients.add(target.path("recipientId").asText()));
        assertEquals(Set.of(owner, admin, editor, selectedPending), recipients);
        assertFalse(recipients.contains(unselectedPending));

        registerDevice(owner, owner + "-new-device");
        JsonNode statusBeforeUploads = rotationStatus(owner, vaultId, generationId);
        assertFalse(
                values(statusBeforeUploads.path("targets")).stream()
                        .anyMatch(
                                target ->
                                        target.path("deviceId")
                                                .asText()
                                                .equals(owner + "-new-device")));

        JsonNode first = targets.getFirst();
        mvc.perform(
                        put(
                                        "/api/v1/vaults/{vaultId}/rotations/{generationId}/targets/{targetId}/package",
                                        vaultId,
                                        generationId,
                                        first.path("targetId").asText())
                                .with(user(owner))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(packageBody(first, "key-2", "wrong-recipient")))
                .andExpect(status().isBadRequest());
        putTargetPackage(owner, vaultId, generationId, first, "key-2");

        mvc.perform(
                        post(
                                        "/api/v1/vaults/{vaultId}/rotations/{generationId}/commit",
                                        vaultId,
                                        generationId)
                                .with(user(owner)))
                .andExpect(status().isConflict());
        mvc.perform(
                        delete(
                                        "/api/v1/vaults/{vaultId}/rotations/{generationId}",
                                        vaultId,
                                        generationId)
                                .with(user(owner)))
                .andExpect(status().isConflict());

        String ownerTargetId =
                targets.stream()
                        .filter(target -> target.path("recipientId").asText().equals(owner))
                        .findFirst()
                        .orElseThrow()
                        .path("targetId")
                        .asText();
        mvc.perform(
                        get(
                                        "/api/v1/vaults/{vaultId}/rotations/{generationId}/self-package",
                                        vaultId,
                                        generationId)
                                .queryParam("deviceId", owner + "-device")
                                .with(user(owner)))
                .andExpect(
                        first.path("targetId").asText().equals(ownerTargetId)
                                ? status().isOk()
                                : status().isNotFound());
        if (!first.path("targetId").asText().equals(ownerTargetId)) {
            JsonNode ownerTarget =
                    targets.stream()
                            .filter(
                                    target ->
                                            target.path("targetId").asText().equals(ownerTargetId))
                            .findFirst()
                            .orElseThrow();
            putTargetPackage(owner, vaultId, generationId, ownerTarget, "key-2");
            mvc.perform(
                            get(
                                            "/api/v1/vaults/{vaultId}/rotations/{generationId}/self-package",
                                            vaultId,
                                            generationId)
                                    .queryParam("deviceId", owner + "-device")
                                    .with(user(owner)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.targetId").value(ownerTargetId))
                    .andExpect(
                            jsonPath("$.encryptedVaultKey")
                                    .value("opaque-rotation-package-" + ownerTargetId));
        }
        mvc.perform(
                        get(
                                        "/api/v1/vaults/{vaultId}/rotations/{generationId}/self-package",
                                        vaultId,
                                        generationId)
                                .queryParam("deviceId", owner + "-device")
                                .with(user(admin)))
                .andExpect(status().isNotFound());

        for (JsonNode target : targets) {
            if (!target.path("covered").asBoolean()) {
                putTargetPackage(owner, vaultId, generationId, target, "key-2");
            }
        }
        rotationStatus(owner, vaultId, generationId);
        mvc.perform(
                        get(
                                        "/api/v1/vaults/{vaultId}/rotations/{generationId}",
                                        vaultId,
                                        generationId)
                                .with(user(owner)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.state").value("READY"));

        mvc.perform(
                        post(
                                        "/api/v1/vaults/{vaultId}/rotations/{generationId}/commit",
                                        vaultId,
                                        generationId)
                                .with(user(owner)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.state").value("COMMITTED"))
                .andExpect(jsonPath("$.lifecycleVersion").value(3));
        mvc.perform(
                        post(
                                        "/api/v1/vaults/{vaultId}/rotations/{generationId}/commit",
                                        vaultId,
                                        generationId)
                                .with(user(owner)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.state").value("COMMITTED"))
                .andExpect(jsonPath("$.lifecycleVersion").value(3));

        assertMembership(owner, vaultId, "ACTIVE", "key-2", "STABLE", 3L);
        assertMembership(selectedPending, vaultId, "ACTIVE", "key-2", "STABLE", 3L);
        assertMembership(unselectedPending, vaultId, "ACCEPTED_PENDING_KEY", "key-2", "STABLE", 3L);
        mvc.perform(get("/api/v1/vaults/{vaultId}/key-packages", vaultId).with(user(owner)))
                .andExpect(status().isOk())
                .andExpect(
                        jsonPath("$[*].vaultKeyId")
                                .value(
                                        org.hamcrest.Matchers.everyItem(
                                                org.hamcrest.Matchers.is("key-2"))));
        mvc.perform(
                        put("/api/v1/vaults/{vaultId}/records/after-rotation", vaultId)
                                .with(user(editor))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(recordBody(1L)))
                .andExpect(status().isCreated());
    }

    @Test
    void automationAndRecoveryTargetsRotateWhileRevokedTargetsArePruned() throws Exception {
        String suffix = Long.toUnsignedString(System.nanoTime());
        String owner = "rotation-bridge-owner-" + suffix;
        String vaultId = "rotation-bridge-vault-" + suffix;
        String deviceId = owner + "-device";
        String principalId = "rotation-agent-" + suffix;
        registerUser(owner);
        registerDevice(owner, deviceId);
        createVault(owner, vaultId);
        putOwnerPackage(owner, vaultId, deviceId, "key-1");
        putAutomationPrincipal(owner, vaultId, principalId, "key-1");
        String enrollmentId = createActiveRecoveryEnrollment(owner);
        putRecoveryPackage(owner, vaultId, enrollmentId, "key-1");

        JsonNode begun =
                responseJson(
                        mvc.perform(
                                        post("/api/v1/vaults/{vaultId}/rotations", vaultId)
                                                .with(user(owner))
                                                .contentType(MediaType.APPLICATION_JSON)
                                                .content(beginBody("key-1", "key-2", 1L, Set.of())))
                                .andExpect(status().isCreated())
                                .andReturn());
        String generationId = begun.path("generationId").asText();
        assertEquals(
                Set.of("DEVICE", "AUTOMATION", "RECOVERY"),
                values(begun.path("targets")).stream()
                        .map(target -> target.path("targetType").asText())
                        .collect(java.util.stream.Collectors.toSet()));

        mvc.perform(
                        delete(
                                        "/api/v1/vaults/{vaultId}/automation-principals/{principalId}",
                                        vaultId,
                                        principalId)
                                .with(user(owner)))
                .andExpect(status().isNoContent());
        JsonNode pruned = rotationStatus(owner, vaultId, generationId);
        List<JsonNode> remaining = values(pruned.path("targets"));
        assertEquals(2, remaining.size());
        assertFalse(
                remaining.stream()
                        .anyMatch(
                                target -> target.path("targetType").asText().equals("AUTOMATION")));

        for (JsonNode target : remaining) {
            putTargetPackage(owner, vaultId, generationId, target, "key-2");
        }
        mvc.perform(
                        post(
                                        "/api/v1/vaults/{vaultId}/rotations/{generationId}/commit",
                                        vaultId,
                                        generationId)
                                .with(user(owner)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.state").value("COMMITTED"))
                .andExpect(jsonPath("$.lifecycleVersion").value(3));

        JsonNode recoveryTarget =
                remaining.stream()
                        .filter(target -> target.path("targetType").asText().equals("RECOVERY"))
                        .findFirst()
                        .orElseThrow();
        mvc.perform(
                        get(
                                        "/api/v1/recovery/enrollments/{enrollmentId}/vaults/{vaultId}",
                                        enrollmentId,
                                        vaultId)
                                .with(user(owner)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.vaultKeyId").value("key-2"))
                .andExpect(
                        jsonPath("$.encryptedVaultKey")
                                .value(
                                        "opaque-rotation-package-"
                                                + recoveryTarget.path("targetId").asText()));
        List<String> rotationAudit =
                new TransactionTemplate(transactionManager)
                        .execute(
                                ignored ->
                                        entityManager
                                                .createQuery(
                                                        "select e.details from AuditEventEntity e where e.ownerId = :owner and e.eventType = 'VAULT_ROTATION_COMMITTED'",
                                                        String.class)
                                                .setParameter("owner", owner)
                                                .getResultList());
        assertNotNull(rotationAudit);
        assertEquals(1, rotationAudit.size());
        assertFalse(rotationAudit.getFirst().contains("opaque-rotation-package"));
    }

    @Test
    void generationCanCancelOnlyBeforeUploadAndStaleBeginIsRejected() throws Exception {
        String suffix = Long.toUnsignedString(System.nanoTime());
        String owner = "cancel-owner-" + suffix;
        String admin = "cancel-admin-" + suffix;
        String vaultId = "cancel-vault-" + suffix;
        registerUser(owner);
        registerDevice(owner, owner + "-device");
        registerUser(admin);
        registerDevice(admin, admin + "-device");
        createVault(owner, vaultId);
        putOwnerPackage(owner, vaultId, owner + "-device", "key-1");
        activate(owner, admin, vaultId, "ADMIN", "key-1");

        mvc.perform(
                        post("/api/v1/vaults/{vaultId}/rotations", vaultId)
                                .with(user(owner))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(beginBody("stale-key", "key-2", 1L, Set.of())))
                .andExpect(status().isConflict());
        JsonNode begun =
                responseJson(
                        mvc.perform(
                                        post("/api/v1/vaults/{vaultId}/rotations", vaultId)
                                                .with(user(admin))
                                                .contentType(MediaType.APPLICATION_JSON)
                                                .content(beginBody("key-1", "key-2", 1L, Set.of())))
                                .andExpect(status().isCreated())
                                .andReturn());
        String generationId = begun.path("generationId").asText();
        mvc.perform(
                        delete(
                                        "/api/v1/vaults/{vaultId}/rotations/{generationId}",
                                        vaultId,
                                        generationId)
                                .with(user(owner)))
                .andExpect(status().isNoContent());
        mvc.perform(
                        get(
                                        "/api/v1/vaults/{vaultId}/rotations/{generationId}",
                                        vaultId,
                                        generationId)
                                .with(user(owner)))
                .andExpect(status().isNotFound());
        assertMembership(owner, vaultId, "ACTIVE", "key-1", "STABLE", 3L);
    }

    @Test
    void concurrentCommitHasOneAuditedWinnerAfterRemovedMemberTargetIsPruned() throws Exception {
        String suffix = Long.toUnsignedString(System.nanoTime());
        String owner = "rotation-race-owner-" + suffix;
        String removed = "rotation-race-removed-" + suffix;
        String vaultId = "rotation-race-vault-" + suffix;
        registerUser(owner);
        registerDevice(owner, owner + "-device");
        registerUser(removed);
        registerDevice(removed, removed + "-device");
        createVault(owner, vaultId);
        putOwnerPackage(owner, vaultId, owner + "-device", "key-1");
        activate(owner, removed, vaultId, "VIEWER", "key-1");
        JsonNode begun =
                responseJson(
                        mvc.perform(
                                        post("/api/v1/vaults/{vaultId}/rotations", vaultId)
                                                .with(user(owner))
                                                .contentType(MediaType.APPLICATION_JSON)
                                                .content(beginBody("key-1", "key-2", 1L, Set.of())))
                                .andExpect(status().isCreated())
                                .andReturn());
        String generationId = begun.path("generationId").asText();
        mvc.perform(
                        delete("/api/v1/vaults/{vaultId}/members/{userId}", vaultId, removed)
                                .with(user(owner)))
                .andExpect(status().isNoContent());
        JsonNode pruned = rotationStatus(owner, vaultId, generationId);
        List<JsonNode> remaining = values(pruned.path("targets"));
        assertEquals(1, remaining.size());
        assertEquals(owner, remaining.getFirst().path("recipientId").asText());
        putTargetPackage(owner, vaultId, generationId, remaining.getFirst(), "key-2");

        ExecutorService executor = Executors.newFixedThreadPool(2);
        CountDownLatch ready = new CountDownLatch(2);
        CountDownLatch start = new CountDownLatch(1);
        try {
            java.util.concurrent.Callable<Integer> commit =
                    () -> {
                        ready.countDown();
                        assertTrue(start.await(5, TimeUnit.SECONDS));
                        return mvc.perform(
                                        post(
                                                        "/api/v1/vaults/{vaultId}/rotations/{generationId}/commit",
                                                        vaultId,
                                                        generationId)
                                                .with(user(owner)))
                                .andReturn()
                                .getResponse()
                                .getStatus();
                    };
            Future<Integer> first = executor.submit(commit);
            Future<Integer> second = executor.submit(commit);
            assertTrue(ready.await(5, TimeUnit.SECONDS));
            start.countDown();
            List<Integer> statuses =
                    List.of(first.get(15, TimeUnit.SECONDS), second.get(15, TimeUnit.SECONDS));
            assertTrue(statuses.stream().allMatch(value -> value == 200 || value == 409));
            assertTrue(statuses.contains(200));
        } finally {
            start.countDown();
            executor.shutdownNow();
            assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS));
        }
        assertMembership(owner, vaultId, "ACTIVE", "key-2", "STABLE", 3L);
        Long auditCount =
                new TransactionTemplate(transactionManager)
                        .execute(
                                ignored ->
                                        entityManager
                                                .createQuery(
                                                        "select count(e) from AuditEventEntity e where e.ownerId = :owner and e.eventType = 'VAULT_ROTATION_COMMITTED'",
                                                        Long.class)
                                                .setParameter("owner", owner)
                                                .getSingleResult());
        assertEquals(1L, auditCount);
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
                                .content(currentPackageBody(keyId)))
                .andExpect(status().isCreated());
    }

    private void putAutomationPrincipal(
            @NonNull String owner,
            @NonNull String vaultId,
            @NonNull String principalId,
            @NonNull String keyId)
            throws Exception {
        mvc.perform(
                        put(
                                        "/api/v1/vaults/{vaultId}/automation-principals/{principalId}",
                                        vaultId,
                                        principalId)
                                .with(user(owner))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        "{\"publicKeyAlgorithm\":\"RSA_OAEP_SHA256\",\"publicKey\":\"opaque-automation-public-key\"}"))
                .andExpect(status().isCreated());
        mvc.perform(
                        put(
                                        "/api/v1/vaults/{vaultId}/automation-principals/{principalId}/key-package",
                                        vaultId,
                                        principalId)
                                .with(user(owner))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        "{\"vaultKeyId\":\"%s\",\"keyAlgorithm\":\"RSA_OAEP_SHA256\",\"encryptedVaultKey\":\"opaque-automation-package\"}"
                                                .formatted(keyId)))
                .andExpect(status().isCreated());
    }

    private @NonNull String createActiveRecoveryEnrollment(@NonNull String owner) throws Exception {
        JsonNode created =
                responseJson(
                        mvc.perform(
                                        post("/api/v1/recovery/enrollments")
                                                .with(user(owner))
                                                .contentType(MediaType.APPLICATION_JSON)
                                                .content(
                                                        """
                                                        {
                                                          "generation": 1,
                                                          "accountCredential": "rotation-recovery-credential",
                                                          "wrappingAlgorithm": "TINK_ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM",
                                                          "wrappingPublicKey": "opaque-recovery-public-key",
                                                          "encryptedPrivateKey": "opaque-recovery-private-key"
                                                        }
                                                        """))
                                .andExpect(status().isCreated())
                                .andReturn());
        String enrollmentId = created.path("enrollmentId").asText();
        mvc.perform(
                        post("/api/v1/recovery/enrollments/{enrollmentId}/commit", enrollmentId)
                                .with(user(owner))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"generation\":1}"))
                .andExpect(status().isOk());
        return enrollmentId;
    }

    private void putRecoveryPackage(
            @NonNull String owner,
            @NonNull String vaultId,
            @NonNull String enrollmentId,
            @NonNull String keyId)
            throws Exception {
        mvc.perform(
                        put(
                                        "/api/v1/recovery/users/{username}/enrollments/{enrollmentId}/vaults/{vaultId}",
                                        owner,
                                        enrollmentId,
                                        vaultId)
                                .with(user(owner))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "generation": 1,
                                          "vaultKeyId": "%s",
                                          "keyAlgorithm": "TINK_ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM",
                                          "encryptedVaultKey": "opaque-recovery-package"
                                        }
                                        """
                                                .formatted(keyId)))
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
                                .content(currentPackageBody(keyId)))
                .andExpect(status().isCreated());
    }

    private @NonNull JsonNode rotationStatus(
            @NonNull String actor, @NonNull String vaultId, @NonNull String generationId)
            throws Exception {
        return responseJson(
                mvc.perform(
                                get(
                                                "/api/v1/vaults/{vaultId}/rotations/{generationId}",
                                                vaultId,
                                                generationId)
                                        .with(user(actor)))
                        .andExpect(status().isOk())
                        .andReturn());
    }

    private void putTargetPackage(
            @NonNull String actor,
            @NonNull String vaultId,
            @NonNull String generationId,
            @NonNull JsonNode target,
            @NonNull String targetKeyId)
            throws Exception {
        mvc.perform(
                        put(
                                        "/api/v1/vaults/{vaultId}/rotations/{generationId}/targets/{targetId}/package",
                                        vaultId,
                                        generationId,
                                        target.path("targetId").asText())
                                .with(user(actor))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(packageBody(target, targetKeyId, null)))
                .andExpect(status().isOk());
        ((com.fasterxml.jackson.databind.node.ObjectNode) target).put("covered", true);
    }

    private void assertMembership(
            @NonNull String username,
            @NonNull String vaultId,
            @NonNull String membershipState,
            @NonNull String currentKeyId,
            @NonNull String lifecycleState,
            long lifecycleVersion)
            throws Exception {
        mvc.perform(get("/api/v1/vaults").with(user(username)))
                .andExpect(status().isOk())
                .andExpect(
                        jsonPath("$[?(@.vaultId == '%s')].membershipState".formatted(vaultId))
                                .value(org.hamcrest.Matchers.hasItem(membershipState)))
                .andExpect(
                        jsonPath("$[?(@.vaultId == '%s')].currentVaultKeyId".formatted(vaultId))
                                .value(org.hamcrest.Matchers.hasItem(currentKeyId)))
                .andExpect(
                        jsonPath("$[?(@.vaultId == '%s')].keyLifecycleState".formatted(vaultId))
                                .value(org.hamcrest.Matchers.hasItem(lifecycleState)))
                .andExpect(
                        jsonPath("$[?(@.vaultId == '%s')].lifecycleVersion".formatted(vaultId))
                                .value(org.hamcrest.Matchers.hasItem((int) lifecycleVersion)));
    }

    private static @NonNull String beginBody(
            @NonNull String expectedKeyId,
            @NonNull String targetKeyId,
            long lifecycleVersion,
            @NonNull Set<String> selectedPendingUsers)
            throws Exception {
        var value = JSON.createObjectNode();
        value.put("expectedCurrentVaultKeyId", expectedKeyId);
        value.put("targetVaultKeyId", targetKeyId);
        value.put("expectedLifecycleVersion", lifecycleVersion);
        var selected = value.putArray("selectedPendingUsers");
        selectedPendingUsers.stream().sorted().forEach(selected::add);
        return JSON.writeValueAsString(value);
    }

    private static @NonNull String packageBody(
            @NonNull JsonNode target, @NonNull String targetKeyId, String recipientOverride)
            throws Exception {
        var value = JSON.createObjectNode();
        value.put("vaultKeyId", targetKeyId);
        value.put("targetType", target.path("targetType").asText());
        copyNullable(value, "recipientId", target, recipientOverride);
        copyNullable(value, "deviceId", target, null);
        copyNullable(value, "principalId", target, null);
        copyNullable(value, "enrollmentId", target, null);
        if (target.path("recoveryGeneration").isNull()
                || target.path("recoveryGeneration").isMissingNode()) {
            value.putNull("recoveryGeneration");
        } else {
            value.put("recoveryGeneration", target.path("recoveryGeneration").asLong());
        }
        value.put("keyAlgorithm", target.path("keyAlgorithm").asText());
        value.put(
                "encryptedVaultKey", "opaque-rotation-package-" + target.path("targetId").asText());
        return JSON.writeValueAsString(value);
    }

    private static void copyNullable(
            com.fasterxml.jackson.databind.node.ObjectNode value,
            @NonNull String field,
            @NonNull JsonNode source,
            String override) {
        if (override != null) {
            value.put(field, override);
        } else if (source.path(field).isNull() || source.path(field).isMissingNode()) {
            value.putNull(field);
        } else {
            value.put(field, source.path(field).asText());
        }
    }

    private static @NonNull List<JsonNode> values(@NonNull JsonNode array) {
        List<JsonNode> values = new ArrayList<>();
        array.forEach(values::add);
        return values;
    }

    private static @NonNull JsonNode responseJson(@NonNull MvcResult result) throws Exception {
        return JSON.readTree(result.getResponse().getContentAsString());
    }

    private static @NonNull String currentPackageBody(@NonNull String keyId) {
        return """
        {
          "vaultKeyId": "%s",
          "keyAlgorithm": "RSA_OAEP_SHA256",
          "encryptedVaultKey": "opaque-current-package"
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
