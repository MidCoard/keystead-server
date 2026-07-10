package top.focess.keystead.server.automation;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validator;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.EnumSet;
import java.util.Optional;
import java.util.Set;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import top.focess.keystead.server.audit.AuditService;
import top.focess.keystead.server.vault.VaultAccessGuard;
import top.focess.keystead.server.vault.VaultKeyRotationService;

@Service
class AutomationService {

    private static final int TOKEN_BYTES = 32;

    private final AutomationPrincipalRepository principals;
    private final AutomationTokenRepository tokens;
    private final AutomationVaultKeyPackageRepository keyPackages;
    private final VaultAccessGuard accessGuard;
    private final VaultKeyRotationService rotations;
    private final AuditService audit;
    private final Clock clock;
    private final Validator validator;
    private final SecureRandom secureRandom = new SecureRandom();

    AutomationService(
            @NonNull AutomationPrincipalRepository principals,
            @NonNull AutomationTokenRepository tokens,
            @NonNull AutomationVaultKeyPackageRepository keyPackages,
            @NonNull VaultAccessGuard accessGuard,
            @NonNull VaultKeyRotationService rotations,
            @NonNull AuditService audit,
            @NonNull Clock clock,
            @NonNull Validator validator) {
        this.principals = principals;
        this.tokens = tokens;
        this.keyPackages = keyPackages;
        this.accessGuard = accessGuard;
        this.rotations = rotations;
        this.audit = audit;
        this.clock = clock;
        this.validator = validator;
    }

    @Transactional
    void putPrincipal(
            @NonNull String ownerId,
            @NonNull String vaultId,
            @NonNull String principalId,
            @NonNull AutomationPrincipalRequest request) {
        accessGuard.requireOwnedVault(ownerId, vaultId);
        validate(request);
        request.validateShape();
        Instant now = clock.instant();
        AutomationPrincipal existing = principals.find(ownerId, principalId).orElse(null);
        if (existing != null && existing.revokedAt() != null) {
            throw new AutomationNotFoundException("Automation principal does not exist");
        }
        principals.persist(
                new AutomationPrincipal(
                        ownerId,
                        principalId,
                        request.publicKeyAlgorithm(),
                        request.publicKey(),
                        existing == null ? now : existing.createdAt(),
                        now,
                        null));
        audit.automationPrincipalStored(ownerId, principalId, request.publicKeyAlgorithm());
    }

    @Transactional
    @NonNull AutomationTokenResponse issueToken(
            @NonNull String ownerId,
            @NonNull String vaultId,
            @NonNull String principalId,
            @NonNull IssueAutomationTokenRequest request) {
        accessGuard.requireOwnedVault(ownerId, vaultId);
        validate(request);
        AutomationPrincipal principal =
                principals
                        .find(ownerId, principalId)
                        .filter(value -> value.revokedAt() == null)
                        .orElseThrow(
                                () ->
                                        new AutomationNotFoundException(
                                                "Automation principal does not exist"));
        Instant now = clock.instant();
        if (!request.expiresAt().isAfter(now)) {
            throw new InvalidAutomationRequestException("Token expiry must be in the future");
        }
        Set<AutomationScope> scopes = EnumSet.copyOf(request.scopes());
        String rawToken = newToken();
        tokens.persist(
                new AutomationToken(
                        hash(rawToken),
                        ownerId,
                        principal.principalId(),
                        vaultId,
                        encodeScopes(scopes),
                        request.expiresAt(),
                        now,
                        null,
                        null));
        audit.automationTokenIssued(ownerId, principalId, vaultId, encodeScopes(scopes));
        return new AutomationTokenResponse(
                rawToken, principalId, vaultId, Set.copyOf(scopes), request.expiresAt());
    }

    @Transactional
    void revokeToken(
            @NonNull String ownerId,
            @NonNull String vaultId,
            @NonNull RevokeAutomationTokenRequest request) {
        accessGuard.requireOwnedVault(ownerId, vaultId);
        validate(request);
        tokens.find(hash(request.token()))
                .filter(token -> token.ownerId().equals(ownerId))
                .filter(token -> token.vaultId().equals(vaultId))
                .ifPresent(token -> revokeStoredToken(token));
    }

    @Transactional
    void revokePrincipal(
            @NonNull String ownerId, @NonNull String vaultId, @NonNull String principalId) {
        accessGuard.requireOwnedVault(ownerId, vaultId);
        AutomationPrincipal principal =
                principals
                        .find(ownerId, principalId)
                        .orElseThrow(
                                () ->
                                        new AutomationNotFoundException(
                                                "Automation principal does not exist"));
        if (principal.revokedAt() != null) {
            return;
        }
        Instant now = clock.instant();
        principals.persist(
                new AutomationPrincipal(
                        principal.ownerId(),
                        principal.principalId(),
                        principal.publicKeyAlgorithm(),
                        principal.publicKey(),
                        principal.createdAt(),
                        now,
                        now));
        tokens.revokeActiveForPrincipal(ownerId, principalId, now);
        keyPackages.deleteForPrincipal(ownerId, principalId);
        audit.automationPrincipalRevoked(ownerId, principalId, vaultId);
    }

    @Transactional
    void putKeyPackage(
            @NonNull String ownerId,
            @NonNull String vaultId,
            @NonNull String principalId,
            @NonNull AutomationVaultKeyPackageRequest request) {
        accessGuard.requireOwnedVault(ownerId, vaultId);
        validate(request);
        request.validateShape();
        rotations.requireCurrentOrLegacy(ownerId, vaultId, request.vaultKeyId());
        principals
                .find(ownerId, principalId)
                .filter(value -> value.revokedAt() == null)
                .orElseThrow(
                        () ->
                                new AutomationNotFoundException(
                                        "Automation principal does not exist"));
        Instant now = clock.instant();
        AutomationVaultKeyPackage existing =
                keyPackages.find(ownerId, vaultId, principalId).orElse(null);
        keyPackages.persist(
                new AutomationVaultKeyPackage(
                        ownerId,
                        vaultId,
                        principalId,
                        request.vaultKeyId(),
                        request.keyAlgorithm(),
                        request.encryptedVaultKey(),
                        existing == null ? now : existing.createdAt(),
                        now));
        audit.automationKeyPackageStored(
                ownerId, principalId, vaultId, request.vaultKeyId(), request.keyAlgorithm());
    }

    @Transactional
    @NonNull Optional<AutomationTokenSubject> authenticate(@NonNull String rawToken) {
        Instant now = clock.instant();
        return tokens.find(hash(rawToken))
                .filter(token -> token.revokedAt() == null && token.expiresAt().isAfter(now))
                .flatMap(
                        token ->
                                principals
                                        .find(token.ownerId(), token.principalId())
                                        .filter(principal -> principal.revokedAt() == null)
                                        .map(
                                                ignored -> {
                                                    tokens.persist(
                                                            new AutomationToken(
                                                                    token.tokenHash(),
                                                                    token.ownerId(),
                                                                    token.principalId(),
                                                                    token.vaultId(),
                                                                    token.scopes(),
                                                                    token.expiresAt(),
                                                                    token.createdAt(),
                                                                    token.revokedAt(),
                                                                    now));
                                                    return new AutomationTokenSubject(
                                                            token.ownerId(),
                                                            token.principalId(),
                                                            token.vaultId(),
                                                            decodeScopes(token.scopes()));
                                                }));
    }

    @Transactional(readOnly = true)
    @NonNull AutomationVaultKeyPackageResponse keyPackage(@NonNull AutomationTokenSubject subject) {
        requireScope(subject, AutomationScope.READ_VAULT_KEY_PACKAGE);
        return keyPackages
                .find(subject.ownerId(), subject.vaultId(), subject.principalId())
                .map(AutomationVaultKeyPackageResponse::from)
                .orElseThrow(
                        () -> new AutomationNotFoundException("Vault key package does not exist"));
    }

    void requireScope(@NonNull AutomationTokenSubject subject, @NonNull AutomationScope scope) {
        if (!subject.hasScope(scope)) {
            throw new AutomationNotFoundException("Automation scope does not allow this resource");
        }
    }

    private void validate(@NonNull Object request) {
        Set<? extends ConstraintViolation<?>> violations = validator.validate(request);
        if (!violations.isEmpty()) {
            throw new InvalidAutomationRequestException(
                    violations.iterator().next().getPropertyPath() + " is invalid");
        }
    }

    private void revokeStoredToken(@NonNull AutomationToken token) {
        tokens.persist(
                new AutomationToken(
                        token.tokenHash(),
                        token.ownerId(),
                        token.principalId(),
                        token.vaultId(),
                        token.scopes(),
                        token.expiresAt(),
                        token.createdAt(),
                        clock.instant(),
                        token.lastUsedAt()));
        audit.automationTokenRevoked(token.ownerId(), token.principalId(), token.vaultId());
    }

    private @NonNull String newToken() {
        byte[] bytes = new byte[TOKEN_BYTES];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static @NonNull String hash(@NonNull String token) {
        try {
            return Base64.getUrlEncoder()
                    .withoutPadding()
                    .encodeToString(
                            MessageDigest.getInstance("SHA-256")
                                    .digest(token.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception exception) {
            throw new IllegalStateException("Could not hash automation token", exception);
        }
    }

    private static @NonNull String encodeScopes(@NonNull Set<AutomationScope> scopes) {
        return scopes.stream()
                .map(Enum::name)
                .sorted()
                .reduce((left, right) -> left + "," + right)
                .orElseThrow();
    }

    private static @NonNull Set<AutomationScope> decodeScopes(@NonNull String encodedScopes) {
        EnumSet<AutomationScope> scopes = EnumSet.noneOf(AutomationScope.class);
        for (String scope : encodedScopes.split(",")) {
            scopes.add(AutomationScope.valueOf(scope));
        }
        return Set.copyOf(scopes);
    }
}
