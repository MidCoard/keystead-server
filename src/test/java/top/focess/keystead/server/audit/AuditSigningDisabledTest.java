package top.focess.keystead.server.audit;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

/**
 * Without a signing key (the default test profile) signing is disabled: {@link AuditSigner#sign}
 * returns {@code null} and persisted events carry no signature, leaving pre-signing behavior
 * unchanged.
 */
@SpringBootTest
@ActiveProfiles("test")
class AuditSigningDisabledTest {

    @Autowired private AuditService auditService;
    @Autowired private AuditSigner signer;

    @Test
    void signingDisabledByDefaultLeavesSignatureNull() {
        assertThat(signer.isEnabled()).isFalse();
        String owner = "unsigned-alice";
        auditService.loginFailed(owner);

        AuditEventPageResponse page = auditService.pageForOwner(owner, 100, null, null, null);
        assertThat(page.events()).isNotEmpty();
        assertThat(page.events().get(0).signature()).isNull();
    }
}
