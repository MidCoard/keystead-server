package top.focess.keystead.server.audit;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import top.focess.keystead.service.EncryptedSyncRecord;
import top.focess.keystead.service.SyncRecordEventId;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class PersonalVaultAuditApiTest {

    @Autowired private MockMvc mvc;

    @Test
    void appendOnlyPersonalRecordProducesRedactedOwnerAuditEvent() throws Exception {
        register("audit-personal-alice");
        String eventId =
                SyncRecordEventId.of(
                        new EncryptedSyncRecord(
                                "personal-vault-a",
                                "secret-a",
                                1,
                                "LOGIN_PASSWORD",
                                "opaque-profile",
                                "opaque-envelope",
                                false));

        mvc.perform(
                        post("/api/v1/vault/records")
                                .with(
                                        httpBasic(
                                                "audit-personal-alice",
                                                "correct horse battery staple"))
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(
                                        """
                                        {
                                          "eventId": "%s",
                                          "fingerprint": "personal-vault-a",
                                          "secretId": "secret-a",
                                          "revision": 1,
                                          "secretType": "LOGIN_PASSWORD",
                                          "encryptedProfile": "opaque-profile",
                                          "envelope": "opaque-envelope",
                                          "deleted": false
                                        }
                                        """
                                                .formatted(eventId)))
                .andExpect(status().isCreated());

        mvc.perform(
                        get("/api/v1/audit/events")
                                .with(
                                        httpBasic(
                                                "audit-personal-alice",
                                                "correct horse battery staple")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.events[0].eventType").value("RECORD_STORED"))
                .andExpect(jsonPath("$.events[0].fingerprint").value("personal-vault-a"))
                .andExpect(
                        jsonPath("$.events[0].details")
                                .value("{\"secretType\":\"LOGIN_PASSWORD\",\"deleted\":false}"));
    }

    private void register(String username) throws Exception {
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
}
