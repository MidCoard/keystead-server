package top.focess.keystead.server.vault;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

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
class VaultApiTest {

    @Autowired private MockMvc mvc;

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
}
