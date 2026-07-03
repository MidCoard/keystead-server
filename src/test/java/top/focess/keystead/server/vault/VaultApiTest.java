package top.focess.keystead.server.vault;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Instant;
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
class VaultApiTest {

    @Autowired private MockMvc mvc;

    @Autowired private VaultRepository vaults;

    @Test
    void authenticatedUserCanCreateAndListVaults() throws Exception {
        mvc.perform(
                        put("/api/v1/vaults/vault-a")
                                .with(user("vault-test-alice"))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "encryptedMetadata": "opaque-vault-metadata"
                                        }
                                        """))
                .andExpect(status().isCreated());

        mvc.perform(get("/api/v1/vaults").with(user("vault-test-alice")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].vaultId").value("vault-a"))
                .andExpect(jsonPath("$[0].encryptedMetadata").value("opaque-vault-metadata"));
    }

    @Test
    void oversizedVaultEncryptedMetadataIsRejected() throws Exception {
        String oversized = "x".repeat(65_537);

        mvc.perform(
                        put("/api/v1/vaults/vault-oversized")
                                .with(user("vault-sized-alice"))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "encryptedMetadata": "%s"
                                        }
                                        """
                                                .formatted(oversized)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void userCannotListAnotherUsersVaults() throws Exception {
        mvc.perform(
                        put("/api/v1/vaults/vault-private")
                                .with(user("vault-private-alice"))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "encryptedMetadata": "alice-only"
                                        }
                                        """))
                .andExpect(status().isCreated());

        mvc.perform(get("/api/v1/vaults").with(user("vault-private-bob")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isEmpty());
    }

    @Test
    void differentUserCannotCreateVaultWithExistingGlobalVaultId() throws Exception {
        mvc.perform(
                        put("/api/v1/vaults/vault-global-private")
                                .with(user("vault-global-alice"))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "encryptedMetadata": "alice-vault-metadata"
                                        }
                                        """))
                .andExpect(status().isCreated());

        mvc.perform(
                        put("/api/v1/vaults/vault-global-private")
                                .with(user("vault-global-bob"))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "encryptedMetadata": "bob-vault-metadata"
                                        }
                                        """))
                .andExpect(status().isNotFound());

        mvc.perform(get("/api/v1/vaults").with(user("vault-global-bob")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isEmpty());

        mvc.perform(get("/api/v1/vaults").with(user("vault-global-alice")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].vaultId").value("vault-global-private"))
                .andExpect(jsonPath("$[0].encryptedMetadata").value("alice-vault-metadata"));
    }

    @Test
    void databaseRejectsDuplicateVaultIdAcrossOwners() {
        insertVault("vault-db-global", "vault-db-alice");

        assertThrows(
                DataIntegrityViolationException.class,
                () -> insertVault("vault-db-global", "vault-db-bob"));
    }

    private void insertVault(String vaultId, String ownerId) {
        Instant now = Instant.parse("2026-07-03T00:00:00Z");
        vaults.upsert(new StoredVault(ownerId, vaultId, "opaque-vault-metadata", now, now));
    }
}
