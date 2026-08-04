package top.focess.keystead.server.crypto;

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
class CryptoAlgorithmApiTest {

    @Autowired private MockMvc mvc;

    @Test
    void publicCatalogDescribesVaultAndEphemeralAccessAlgorithms() throws Exception {
        mvc.perform(get("/api/v1/crypto/algorithms"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.defaults.payloadAead").value("AES-256-GCM"))
                .andExpect(jsonPath("$.defaults.vaultKeyKdf").value("ARGON2ID"))
                .andExpect(
                        jsonPath("$.defaults.vaultAccessExchangeKey")
                                .value("TINK_ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM"))
                .andExpect(
                        jsonPath("$.defaults.vaultAccessWrappedKey")
                                .value("TINK_DEVICE_KEY_PACKAGE"))
                .andExpect(jsonPath("$.payloadAeadAlgorithms[0]").value("AES-256-GCM"))
                .andExpect(
                        jsonPath("$.vaultAccessExchangeKeyAlgorithms[0]")
                                .value("TINK_ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM"))
                .andExpect(
                        jsonPath("$.vaultAccessWrappedKeyAlgorithms[0]")
                                .value("TINK_DEVICE_KEY_PACKAGE"))
                .andExpect(jsonPath("$.deviceProofAlgorithms").doesNotExist());
    }
}
