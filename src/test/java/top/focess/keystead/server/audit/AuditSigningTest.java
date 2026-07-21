package top.focess.keystead.server.audit;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

/**
 * With a signing key configured, every persisted event carries an HMAC signature that a verifier
 * holding the key can recompute from the stored fields. Covers the round-trip (sign at append,
 * verify after read-back) and tamper detection (any signed field changed -> verification fails).
 */
@SpringBootTest(properties = "keystead.audit.signing.key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
@ActiveProfiles("test")
class AuditSigningTest {

    @Autowired private AuditService auditService;
    @Autowired private AuditSigner signer;

    @Test
    void signedEventRoundTripsAndDetectsTampering() {
        assertThat(signer.isEnabled()).isTrue();
        String owner = "signing-alice";
        auditService.loginFailed(owner);

        AuditEventPageResponse page = auditService.pageForOwner(owner, 100, null, null, null);
        assertThat(page.events()).isNotEmpty();
        AuditEventResponse event = page.events().get(0);
        assertThat(event.signature()).isNotBlank();

        StoredAuditEvent stored = toStored(event);
        assertThat(signer.verify(stored, event.signature())).isTrue();

        // Tamper with a free-form field: targetId is unconstrained for LOGIN_FAILED, so the mutated
        // record still validates, but its recomputed signature no longer matches the stored one.
        StoredAuditEvent tampered =
                new StoredAuditEvent(
                        stored.eventId(),
                        stored.ownerId(),
                        stored.actorId(),
                        stored.eventType(),
                        stored.targetType(),
                        "tampered-target",
                        stored.vaultId(),
                        stored.revision(),
                        stored.outcome(),
                        stored.details(),
                        stored.createdAt());
        assertThat(signer.verify(tampered, event.signature())).isFalse();
    }

    private static StoredAuditEvent toStored(AuditEventResponse event) {
        return new StoredAuditEvent(
                event.eventId(),
                event.ownerId(),
                event.actorId(),
                event.eventType(),
                event.targetType(),
                event.targetId(),
                event.vaultId(),
                event.revision(),
                event.outcome(),
                event.details(),
                event.createdAt());
    }
}
