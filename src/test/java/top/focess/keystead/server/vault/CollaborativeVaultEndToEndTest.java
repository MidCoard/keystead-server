package top.focess.keystead.server.vault;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.jayway.jsonpath.JsonPath;
import jakarta.persistence.EntityManager;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import top.focess.keystead.crypto.DefaultCryptoService;
import top.focess.keystead.crypto.DeviceKeyPair;
import top.focess.keystead.memory.SecretBuffer;
import top.focess.keystead.model.SecretClassification;
import top.focess.keystead.model.SecretId;
import top.focess.keystead.model.VaultId;
import top.focess.keystead.service.CreateVaultRequest;
import top.focess.keystead.service.DefaultVaultService;
import top.focess.keystead.service.DeviceVaultKeyPackage;
import top.focess.keystead.service.VaultHandle;
import top.focess.keystead.store.FileVaultStore;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class CollaborativeVaultEndToEndTest {

    private static final String PASSWORD = "correct horse battery staple";
    private static final String DEVICE_ALGORITHM = DefaultCryptoService.DEVICE_KEY_ALGORITHM;

    @Autowired private MockMvc mvc;
    @Autowired private EntityManager entityManager;
    @Autowired private PlatformTransactionManager transactionManager;
    @TempDir Path temporaryDirectory;

    @Test
    void twoUsersOpenOneCoreVaultThenEnforceRolesCoverageRemovalAndRotation() throws Exception {
        String suffix = Long.toUnsignedString(System.nanoTime());
        String owner = "e2e-owner-" + suffix;
        String member = "e2e-member-" + suffix;
        String guest = "e2e-guest-" + suffix;
        String ownerDevice = "owner-device-" + suffix;
        String memberDevice = "member-device-" + suffix;
        String memberSecondDevice = "member-second-" + suffix;
        String vaultIdText = UUID.randomUUID().toString();
        VaultId vaultId = new VaultId(UUID.fromString(vaultIdText));
        DefaultCryptoService crypto = new DefaultCryptoService();
        FileVaultStore ownerStore = new FileVaultStore(temporaryDirectory.resolve("owner"));
        FileVaultStore memberStore = new FileVaultStore(temporaryDirectory.resolve("member"));

        registerUser(owner);
        registerUser(member);
        registerUser(guest);
        try (DeviceKeyPair ownerKeys = crypto.generateDeviceKeyPair();
                DeviceKeyPair memberKeys = crypto.generateDeviceKeyPair();
                DeviceKeyPair memberSecondKeys = crypto.generateDeviceKeyPair();
                VaultHandle ownerVault =
                        new DefaultVaultService(ownerStore)
                                .createVault(
                                        new CreateVaultRequest(vaultId), PASSWORD.toCharArray())) {
            registerVerifiedDevice(owner, ownerDevice, ownerKeys.publicKey());
            registerVerifiedDevice(member, memberDevice, memberKeys.publicKey());
            registerVerifiedDevice(member, memberSecondDevice, memberSecondKeys.publicKey());
            createServerVault(owner, vaultIdText);

            SecretId secretId = saveLogin(ownerVault);
            byte[] ownerContext = packageContext(vaultIdText, ownerDevice);
            DeviceVaultKeyPackage ownerPackage =
                    ownerVault.wrapVaultKeyPackageForDevice(ownerKeys.publicKey(), ownerContext);
            putOwnPackage(owner, vaultIdText, ownerDevice, ownerPackage);

            invite(owner, member, vaultIdText, "VIEWER");
            mvc.perform(
                            post("/api/v1/vaults/{vaultId}/members/accept", vaultIdText)
                                    .with(httpBasic(member, PASSWORD)))
                    .andExpect(status().isNoContent());
            mvc.perform(
                            get("/api/v1/vaults/{vaultId}/records", vaultIdText)
                                    .with(httpBasic(member, PASSWORD)))
                    .andExpect(status().isNotFound());

            byte[] memberContext = packageContext(vaultIdText, memberDevice);
            DeviceVaultKeyPackage memberPackage =
                    ownerVault.wrapVaultKeyPackageForDevice(memberKeys.publicKey(), memberContext);
            putRecipientPackage(owner, member, vaultIdText, memberDevice, memberPackage);
            mvc.perform(
                            get("/api/v1/vaults/{vaultId}/records", vaultIdText)
                                    .with(httpBasic(member, PASSWORD)))
                    .andExpect(status().isOk());

            String memberPackageJson =
                    mvc.perform(
                                    get("/api/v1/vaults/{vaultId}/key-packages", vaultIdText)
                                            .with(httpBasic(member, PASSWORD)))
                            .andExpect(status().isOk())
                            .andReturn()
                            .getResponse()
                            .getContentAsString();
            List<String> encryptedValues =
                    JsonPath.read(
                            memberPackageJson,
                            "$[?(@.deviceId == '%s')].encryptedVaultKey".formatted(memberDevice));
            assertEquals(1, encryptedValues.size());
            byte[] encryptedMemberKey = Base64.getDecoder().decode(encryptedValues.getFirst());
            ownerStore.listSecretRecords(vaultId).forEach(memberStore::saveSecretRecord);
            try (VaultHandle opened =
                    new DefaultVaultService(memberStore)
                            .provisionVault(
                                    vaultId,
                                    new DeviceVaultKeyPackage(
                                            ownerVault.vaultKeyId(),
                                            DEVICE_ALGORITHM,
                                            encryptedMemberKey),
                                    memberKeys.privateKey(),
                                    memberContext)) {
                opened.withLogin(
                        secretId,
                        view ->
                                view.withPassword(
                                        chars ->
                                                assertArrayEquals(
                                                        "shared-secret".toCharArray(), chars)));
            }

            putRecord(member, vaultIdText, "viewer-write", 1L, 404);
            changeRole(owner, member, vaultIdText, "EDITOR");
            putRecord(member, vaultIdText, "editor-write", 1L, 201);
            changeRole(owner, member, vaultIdText, "ADMIN");
            invite(member, guest, vaultIdText, "VIEWER");

            mvc.perform(
                            get("/api/v1/vaults/{vaultId}/package-recipients", vaultIdText)
                                    .with(httpBasic(owner, PASSWORD)))
                    .andExpect(status().isOk())
                    .andExpect(
                            jsonPath(
                                            "$.devices[?(@.deviceId == '%s')].covered"
                                                    .formatted(memberSecondDevice))
                                    .value(false));
            byte[] secondContext = packageContext(vaultIdText, memberSecondDevice);
            DeviceVaultKeyPackage secondPackage =
                    ownerVault.wrapVaultKeyPackageForDevice(
                            memberSecondKeys.publicKey(), secondContext);
            putRecipientPackage(owner, member, vaultIdText, memberSecondDevice, secondPackage);

            mvc.perform(
                            delete("/api/v1/vaults/{vaultId}/members/{userId}", vaultIdText, member)
                                    .with(httpBasic(owner, PASSWORD)))
                    .andExpect(status().isNoContent());
            mvc.perform(
                            get("/api/v1/vaults/{vaultId}/records", vaultIdText)
                                    .with(httpBasic(member, PASSWORD)))
                    .andExpect(status().isNotFound());
            putRecord(owner, vaultIdText, "blocked-before-rotation", 2L, 409);

            completeOpaqueRotation(owner, vaultIdText, ownerVault.vaultKeyId().value());
            putRecord(owner, vaultIdText, "allowed-after-rotation", 2L, 201);
            mvc.perform(
                            get("/api/v1/vaults/{vaultId}/key-packages", vaultIdText)
                                    .with(httpBasic(owner, PASSWORD)))
                    .andExpect(status().isOk())
                    .andExpect(
                            jsonPath("$[*].recipientId")
                                    .value(
                                            org.hamcrest.Matchers.not(
                                                    org.hamcrest.Matchers.hasItem(member))));

            assertFalse(memberPackage.toString().contains(encryptedValues.getFirst()));
            assertTrue(ownerPackage.toString().contains("REDACTED"));
            java.util.Arrays.fill(ownerContext, (byte) 0);
            java.util.Arrays.fill(memberContext, (byte) 0);
            java.util.Arrays.fill(secondContext, (byte) 0);
            java.util.Arrays.fill(encryptedMemberKey, (byte) 0);
        }
    }

    private @NonNull SecretId saveLogin(@NonNull VaultHandle vault) {
        try (SecretBuffer username = SecretBuffer.fromChars("member@example.com".toCharArray());
                SecretBuffer password = SecretBuffer.fromChars("shared-secret".toCharArray())) {
            return vault.saveLogin(
                    draft ->
                            draft.title("Shared login")
                                    .classification(
                                            new SecretClassification(
                                                    "shared", "keystead", "team", Set.of()))
                                    .username(username)
                                    .password(password));
        }
    }

    private void completeOpaqueRotation(
            @NonNull String owner, @NonNull String vaultId, @NonNull String currentKeyId)
            throws Exception {
        String vaults =
                mvc.perform(get("/api/v1/vaults").with(httpBasic(owner, PASSWORD)))
                        .andReturn()
                        .getResponse()
                        .getContentAsString();
        List<Integer> versions =
                JsonPath.read(
                        vaults, "$[?(@.vaultId == '%s')].lifecycleVersion".formatted(vaultId));
        String targetKeyId = "rotated-" + UUID.randomUUID();
        String rotation =
                mvc.perform(
                                post("/api/v1/vaults/{vaultId}/rotations", vaultId)
                                        .with(httpBasic(owner, PASSWORD))
                                        .contentType(MediaType.APPLICATION_JSON)
                                        .content(
                                                """
                                                {"expectedCurrentVaultKeyId":"%s","targetVaultKeyId":"%s","expectedLifecycleVersion":%d,"selectedPendingUsers":[]}
                                                """
                                                        .formatted(
                                                                currentKeyId,
                                                                targetKeyId,
                                                                versions.getFirst())))
                        .andExpect(status().isCreated())
                        .andReturn()
                        .getResponse()
                        .getContentAsString();
        String generationId = JsonPath.read(rotation, "$.generationId");
        List<String> targetIds = JsonPath.read(rotation, "$.targets[*].targetId");
        for (String targetId : targetIds) {
            List<String> deviceIds =
                    JsonPath.read(
                            rotation,
                            "$.targets[?(@.targetId == '%s')].deviceId".formatted(targetId));
            List<String> algorithms =
                    JsonPath.read(
                            rotation,
                            "$.targets[?(@.targetId == '%s')].keyAlgorithm".formatted(targetId));
            mvc.perform(
                            put(
                                            "/api/v1/vaults/{vaultId}/rotations/{generationId}/targets/{targetId}/package",
                                            vaultId,
                                            generationId,
                                            targetId)
                                    .with(httpBasic(owner, PASSWORD))
                                    .contentType(MediaType.APPLICATION_JSON)
                                    .content(
                                            """
                                            {"vaultKeyId":"%s","targetType":"DEVICE","recipientId":"%s","deviceId":"%s","principalId":null,"enrollmentId":null,"recoveryGeneration":null,"keyAlgorithm":"%s","encryptedVaultKey":"opaque-rotated-package-%s"}
                                            """
                                                    .formatted(
                                                            targetKeyId,
                                                            owner,
                                                            deviceIds.getFirst(),
                                                            algorithms.getFirst(),
                                                            targetId)))
                    .andExpect(status().isOk());
        }
        mvc.perform(
                        post(
                                        "/api/v1/vaults/{vaultId}/rotations/{generationId}/commit",
                                        vaultId,
                                        generationId)
                                .with(httpBasic(owner, PASSWORD)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.state").value("COMMITTED"));
    }

    private void registerUser(@NonNull String username) throws Exception {
        mvc.perform(
                        post("/api/v1/users")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        "{\"username\":\"%s\",\"password\":\"%s\"}"
                                                .formatted(username, PASSWORD)))
                .andExpect(status().isCreated());
    }

    private void registerVerifiedDevice(
            @NonNull String username, @NonNull String deviceId, byte @NonNull [] wrappingPublicKey)
            throws Exception {
        KeyPairGenerator proof = KeyPairGenerator.getInstance("RSA");
        proof.initialize(2048);
        String proofPublic =
                Base64.getEncoder()
                        .encodeToString(proof.generateKeyPair().getPublic().getEncoded());
        mvc.perform(
                        post("/api/v1/devices")
                                .with(httpBasic(username, PASSWORD))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {"deviceId":"%s","keyAlgorithm":"RSA_OAEP_SHA256","publicKey":"%s","wrappingKeyAlgorithm":"%s","wrappingPublicKey":"%s"}
                                        """
                                                .formatted(
                                                        deviceId,
                                                        proofPublic,
                                                        DEVICE_ALGORITHM,
                                                        Base64.getEncoder()
                                                                .encodeToString(
                                                                        wrappingPublicKey))))
                .andExpect(status().isCreated());
        new TransactionTemplate(transactionManager)
                .executeWithoutResult(
                        ignored ->
                                entityManager
                                        .createQuery(
                                                """
                                                update DeviceEntity d set d.verifiedAt = :now, d.lastSeenAt = :now
                                                 where d.id.ownerId = :username and d.id.deviceId = :deviceId
                                                """)
                                        .setParameter("now", Instant.now())
                                        .setParameter("username", username)
                                        .setParameter("deviceId", deviceId)
                                        .executeUpdate());
    }

    private void createServerVault(@NonNull String owner, @NonNull String vaultId)
            throws Exception {
        mvc.perform(
                        put("/api/v1/vaults/{vaultId}", vaultId)
                                .with(httpBasic(owner, PASSWORD))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"encryptedMetadata\":\"opaque-metadata\"}"))
                .andExpect(status().isCreated());
    }

    private void invite(
            @NonNull String actor,
            @NonNull String recipient,
            @NonNull String vaultId,
            @NonNull String role)
            throws Exception {
        mvc.perform(
                        put("/api/v1/vaults/{vaultId}/members/{userId}", vaultId, recipient)
                                .with(httpBasic(actor, PASSWORD))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"role\":\"%s\"}".formatted(role)))
                .andExpect(status().isCreated());
    }

    private void changeRole(
            @NonNull String owner,
            @NonNull String member,
            @NonNull String vaultId,
            @NonNull String role)
            throws Exception {
        mvc.perform(
                        put("/api/v1/vaults/{vaultId}/members/{userId}/role", vaultId, member)
                                .with(httpBasic(owner, PASSWORD))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"role\":\"%s\"}".formatted(role)))
                .andExpect(status().isNoContent());
    }

    private void putOwnPackage(
            @NonNull String owner,
            @NonNull String vaultId,
            @NonNull String deviceId,
            @NonNull DeviceVaultKeyPackage keyPackage)
            throws Exception {
        putPackage(
                owner,
                "/api/v1/vaults/%s/key-packages/%s".formatted(vaultId, deviceId),
                keyPackage);
    }

    private void putRecipientPackage(
            @NonNull String owner,
            @NonNull String recipient,
            @NonNull String vaultId,
            @NonNull String deviceId,
            @NonNull DeviceVaultKeyPackage keyPackage)
            throws Exception {
        putPackage(
                owner,
                "/api/v1/vaults/%s/key-packages/recipients/%s/devices/%s"
                        .formatted(vaultId, recipient, deviceId),
                keyPackage);
    }

    private void putPackage(
            @NonNull String actor, @NonNull String path, @NonNull DeviceVaultKeyPackage keyPackage)
            throws Exception {
        byte[] encrypted = keyPackage.encryptedVaultKey();
        try {
            mvc.perform(
                            put(path)
                                    .with(httpBasic(actor, PASSWORD))
                                    .contentType(MediaType.APPLICATION_JSON)
                                    .content(
                                            """
                                            {"vaultKeyId":"%s","keyAlgorithm":"%s","encryptedVaultKey":"%s"}
                                            """
                                                    .formatted(
                                                            keyPackage.vaultKeyId().value(),
                                                            keyPackage.keyAlgorithm(),
                                                            Base64.getEncoder()
                                                                    .encodeToString(encrypted))))
                    .andExpect(status().isCreated());
        } finally {
            java.util.Arrays.fill(encrypted, (byte) 0);
        }
    }

    private void putRecord(
            @NonNull String actor,
            @NonNull String vaultId,
            @NonNull String secretId,
            long revision,
            int expectedStatus)
            throws Exception {
        mvc.perform(
                        put("/api/v1/vaults/{vaultId}/records/{secretId}", vaultId, secretId)
                                .with(httpBasic(actor, PASSWORD))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {"revision":%d,"secretType":"LOGIN_PASSWORD","encryptedProfile":"opaque-profile","envelope":"opaque-envelope","deleted":false}
                                        """
                                                .formatted(revision)))
                .andExpect(status().is(expectedStatus));
    }

    private byte @NonNull [] packageContext(@NonNull String vaultId, @NonNull String deviceId) {
        return "keystead-vault-key-package-v1|vault:%s|device:%s"
                .formatted(vaultId, deviceId)
                .getBytes(StandardCharsets.UTF_8);
    }
}
