package top.focess.keystead.server.automation;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import jakarta.validation.Validator;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import top.focess.keystead.server.audit.AuditService;
import top.focess.keystead.server.vault.VaultAccessGuard;
import top.focess.keystead.server.vault.VaultAutomationRevocationService;
import top.focess.keystead.server.vault.VaultKeyRotationService;

class AutomationServiceTest {

    private static final Instant NOW = Instant.parse("2026-07-11T00:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);

    @Test
    void authenticateReturnsEmptyWhenActiveTokenTouchLosesRace() {
        AutomationPrincipalRepository principals = mock(AutomationPrincipalRepository.class);
        AutomationTokenRepository tokens = mock(AutomationTokenRepository.class);
        AutomationService service = newService(principals, tokens);
        AutomationToken token =
                new AutomationToken(
                        "stored-token-hash",
                        "owner",
                        "principal",
                        "vault",
                        AutomationScope.READ_VAULT_KEY_PACKAGE.name(),
                        NOW.plusSeconds(60),
                        NOW.minusSeconds(60),
                        null,
                        null);
        AutomationPrincipal principal =
                new AutomationPrincipal(
                        "owner",
                        "principal",
                        "RSA_OAEP_SHA256",
                        "public-key",
                        NOW.minusSeconds(60),
                        NOW.minusSeconds(60),
                        null);
        when(tokens.find(anyString())).thenReturn(Optional.of(token));
        when(principals.find("owner", "principal")).thenReturn(Optional.of(principal));
        when(tokens.touchActive("stored-token-hash", NOW)).thenReturn(0);

        Optional<AutomationTokenSubject> subject = service.authenticate("raw-token");

        assertTrue(subject.isEmpty());
        verify(tokens).touchActive("stored-token-hash", NOW);
        verify(tokens, never()).persist(any(AutomationToken.class));
    }

    private static AutomationService newService(
            AutomationPrincipalRepository principals, AutomationTokenRepository tokens) {
        return new AutomationService(
                principals,
                tokens,
                mock(AutomationVaultKeyPackageRepository.class),
                mock(VaultAccessGuard.class),
                mock(VaultKeyRotationService.class),
                mock(VaultAutomationRevocationService.class),
                mock(AuditService.class),
                CLOCK,
                mock(Validator.class));
    }
}
