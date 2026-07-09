package top.focess.keystead.server.record;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class SecretTypeCatalogApiTest {

    @Autowired private MockMvc mvc;

    @Test
    void publicCatalogDescribesZeroKnowledgeSecretTaxonomyAndSchemas() throws Exception {
        mvc.perform(get("/api/v1/secret-types/catalog"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.types[0].type").value("LOGIN_PASSWORD"))
                .andExpect(jsonPath("$.types[0].defaultCategory").value("communication"))
                .andExpect(jsonPath("$.types[0].defaultProvider").doesNotExist())
                .andExpect(jsonPath("$.types[0].fields[0].name").value("username"))
                .andExpect(jsonPath("$.types[0].fields[0].fieldType").value("SECRET"))
                .andExpect(jsonPath("$.types[0].fields[0].required").value(true))
                .andExpect(jsonPath("$.types[0].fields[0].revealable").value(true))
                .andExpect(jsonPath("$.types[2].type").value("SSH_KEY"))
                .andExpect(jsonPath("$.types[2].defaultCategory").value("development"))
                .andExpect(jsonPath("$.types[2].defaultProvider").value("ssh"))
                .andExpect(jsonPath("$.types[2].defaultSoftware").value("openssh"))
                .andExpect(jsonPath("$.types[2].fields[0].name").value("publicKey"))
                .andExpect(jsonPath("$.types[2].fields[0].fieldType").value("TEXT"))
                .andExpect(jsonPath("$.types[2].fields[1].name").value("privateKey"))
                .andExpect(jsonPath("$.types[2].fields[1].fieldType").value("SECRET"))
                .andExpect(jsonPath("$.types[3].type").value("API_TOKEN"))
                .andExpect(jsonPath("$.types[3].defaultCategory").value("development"))
                .andExpect(jsonPath("$.types[3].defaultProvider").value("api"))
                .andExpect(jsonPath("$.types[4].type").value("GPG_KEY"))
                .andExpect(jsonPath("$.types[4].defaultProvider").value("gpg"))
                .andExpect(jsonPath("$.types[5].type").value("MFA_SECRET"))
                .andExpect(jsonPath("$.types[5].defaultCategory").value("communication"))
                .andExpect(jsonPath("$.types[7].type").value("GENERIC_SECRET"))
                .andExpect(jsonPath("$.types[7].allowsCustomFields").value(true))
                .andExpect(jsonPath("$.types[7].customFieldType").value("SECRET"))
                .andExpect(jsonPath("$.types[7].customFieldsRevealable").value(true));
    }
}
