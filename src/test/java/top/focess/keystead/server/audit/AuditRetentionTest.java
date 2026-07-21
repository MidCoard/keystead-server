package top.focess.keystead.server.audit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Retention pruning is opt-in via {@code keystead.audit.retention}. The base test profile disables
 * it (P0D); this class narrows the window to one second so a far-past event is pruned the moment a
 * fresh event is recorded for the same owner.
 */
@SpringBootTest(properties = "keystead.audit.retention=PT1S")
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AuditRetentionTest {

    @Autowired private MockMvc mvc;

    @Autowired private AuditEventRepository auditEvents;

    @Test
    void oldAuditEventsArePrunedWhenNewEventRecorded() throws Exception {
        registerUser("retention-alice");
        StoredAuditEvent oldEvent =
                new StoredAuditEvent(
                        "retention-old-event",
                        "retention-alice",
                        "retention-alice",
                        AuditEventType.LOGIN_FAILED.name(),
                        "auth",
                        "retention-alice",
                        null,
                        null,
                        "FAILURE",
                        "{\"reason\":\"BAD_CREDENTIALS\"}",
                        Instant.parse("2020-01-01T00:00:00Z"));
        auditEvents.append(oldEvent, null);
        assertThat(auditEvents.listForOwner("retention-alice"))
                .extracting(StoredAuditEvent::eventId)
                .contains("retention-old-event");

        mvc.perform(get("/api/v1/devices").with(httpBasic("retention-alice", "wrong-password")))
                .andExpect(status().isUnauthorized());

        List<StoredAuditEvent> events = auditEvents.listForOwner("retention-alice");
        assertThat(events)
                .extracting(StoredAuditEvent::eventId)
                .doesNotContain("retention-old-event");
        assertThat(events)
                .extracting(StoredAuditEvent::eventType)
                .contains(AuditEventType.LOGIN_FAILED.name());
    }

    private void registerUser(String username) throws Exception {
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
