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
    void publicCatalogDescribesSupportedMainstreamAlgorithms() throws Exception {
        mvc.perform(get("/api/v1/crypto/algorithms"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.defaults.payloadAead").value("AES-256-GCM"))
                .andExpect(jsonPath("$.defaults.vaultKeyKdf").value("PBKDF2WithHmacSHA256"))
                .andExpect(
                        jsonPath("$.defaults.vaultKeyPackage")
                                .value("TINK_ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM"))
                .andExpect(jsonPath("$.payloadAeadAlgorithms[0]").value("AES-256-GCM"))
                .andExpect(jsonPath("$.payloadAeadAlgorithms[1]").value("CHACHA20-POLY1305"))
                .andExpect(jsonPath("$.vaultKeyKdfAlgorithms[0]").value("PBKDF2WithHmacSHA256"))
                .andExpect(jsonPath("$.vaultKeyKdfAlgorithms[1]").value("PBKDF2WithHmacSHA512"))
                .andExpect(jsonPath("$.deviceProofAlgorithms[0]").value("RSA_OAEP_SHA256"))
                .andExpect(jsonPath("$.deviceProofAlgorithms[1]").value("RSA_PSS_SHA256"))
                .andExpect(jsonPath("$.deviceProofAlgorithms[2]").value("ECDSA_P256_SHA256"))
                .andExpect(jsonPath("$.deviceProofAlgorithms[3]").value("ECDSA_P384_SHA384"))
                .andExpect(jsonPath("$.deviceProofAlgorithms[4]").value("ECDSA_P521_SHA512"))
                .andExpect(jsonPath("$.deviceProofAlgorithms[5]").value("ED25519"))
                .andExpect(jsonPath("$.vaultKeyPackageAlgorithms[0]").value("RSA_OAEP_SHA256"))
                .andExpect(
                        jsonPath("$.vaultKeyPackageAlgorithms[1]")
                                .value("TINK_ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM"));
    }
}
