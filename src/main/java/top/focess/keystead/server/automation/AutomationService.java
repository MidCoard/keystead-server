package top.focess.keystead.server.automation;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validator;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.EnumSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import top.focess.keystead.server.audit.AuditService;
import top.focess.keystead.server.vault.VaultAccessGuard;
import top.focess.keystead.server.vault.VaultAutomationRevocationService;
import top.focess.keystead.server.vault.VaultKeyRotationService;

@Service
class AutomationService {

    private static final int TOKEN_BYTES = 32;

    private final AutomationPrincipalRepository principals;
    private final AutomationTokenRepository tokens;
    private final AutomationVaultKeyPackageRepository keyPackages;
    private final VaultAccessGuard accessGuard;
    private final VaultKeyRotationService rotations;
    private final VaultAutomationRevocationService vaultRevocations;
    private final AuditService audit;
    private final Clock clock;
    private final Validator validator;
    private final AutomationProperties properties;
    private final SecureRandom secureRandom = new SecureRandom();

    AutomationService(
            @NonNull AutomationPrincipalRepository principals,
            @NonNull AutomationTokenRepository tokens,
            @NonNull AutomationVaultKeyPackageRepository keyPackages,
            @NonNull VaultAccessGuard accessGuard,
            @NonNull VaultKeyRotationService rotations,
            @NonNull VaultAutomationRevocationService vaultRevocations,
            @NonNull AuditService audit,
            @NonNull Clock clock,
            @NonNull Validator validator,
            @NonNull AutomationProperties properties) {
        this.principals = principals;
        this.tokens = tokens;
        this.keyPackages = keyPackages;
        this.accessGuard = accessGuard;
        this.rotations = rotations;
        this.vaultRevocations = vaultRevocations;
        this.audit = audit;
        this.clock = clock;
        this.validator = validator;
        this.properties = properties;
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
        audit.automationPrincipalStored(
                ownerId, principalId, vaultId, request.publicKeyAlgorithm());
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
        Duration maxTtl = properties.tokenMaxTtl();
        if (request.expiresAt().isAfter(now.plus(maxTtl))) {
            throw new InvalidAutomationRequestException("Token expiry exceeds the maximum TTL");
        }
        Set<AutomationScope> scopes = EnumSet.copyOf(request.scopes());
        Set<String> grantedSecretIds = normalizeGrantedSecretIds(request.grantedSecretIds());
        String rawToken = newToken();
        String tokenId = newToken();
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
                        null,
                        tokenId,
                        encodeSecretIds(grantedSecretIds)));
        audit.automationTokenIssued(ownerId, principalId, vaultId, encodeScopes(scopes));
        return new AutomationTokenResponse(
                rawToken, tokenId, principalId, vaultId, Set.copyOf(scopes), request.expiresAt());
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

    @Transactional(readOnly = true)
    @NonNull List<AutomationTokenSummary> listTokens(
            @NonNull String ownerId, @NonNull String vaultId, @NonNull String principalId) {
        accessGuard.requireOwnedVault(ownerId, vaultId);
        principals
                .find(ownerId, principalId)
                .orElseThrow(
                        () ->
                                new AutomationNotFoundException(
                                        "Automation principal does not exist"));
        return tokens.list(ownerId, vaultId, principalId).stream()
                .map(AutomationService::toSummary)
                .toList();
    }

    @Transactional
    void revokeTokenById(
            @NonNull String ownerId,
            @NonNull String vaultId,
            @NonNull String principalId,
            @NonNull String tokenId) {
        accessGuard.requireOwnedVault(ownerId, vaultId);
        AutomationToken token =
                tokens.findByTokenId(ownerId, vaultId, principalId, tokenId)
                        .orElseThrow(
                                () ->
                                        new AutomationNotFoundException(
                                                "Automation token does not exist"));
        if (token.revokedAt() != null) {
            return;
        }
        revokeStoredToken(token);
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
        var affectedVaultIds = keyPackages.listCurrentVaultIds(ownerId, principalId);
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
        vaultRevocations.requireRotation(ownerId, principalId, affectedVaultIds, now);
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
                                        .filter(
                                                ignored ->
                                                        tokens.touchActive(token.tokenHash(), now)
                                                                == 1)
                                        .map(
                                                ignored ->
                                                        new AutomationTokenSubject(
                                                                token.ownerId(),
                                                                token.principalId(),
                                                                token.vaultId(),
                                                                decodeScopes(token.scopes()),
                                                                token.tokenId(),
                                                                decodeSecretIds(
                                                                        token
                                                                                .grantedSecretIds()))));
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
                        token.lastUsedAt(),
                        token.tokenId(),
                        token.grantedSecretIds()));
        audit.automationTokenRevoked(token.ownerId(), token.principalId(), token.vaultId());
    }

    private static @NonNull AutomationTokenSummary toSummary(@NonNull AutomationToken token) {
        return new AutomationTokenSummary(
                token.tokenId(),
                token.principalId(),
                decodeScopes(token.scopes()),
                decodeSecretIds(token.grantedSecretIds()),
                token.expiresAt(),
                token.createdAt(),
                token.revokedAt(),
                token.lastUsedAt());
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

    private static @NonNull Set<String> normalizeGrantedSecretIds(@Nullable Set<String> ids) {
        if (ids == null || ids.isEmpty()) {
            return Set.of();
        }
        for (String id : ids) {
            if (id == null || id.strip().isEmpty()) {
                throw new InvalidAutomationRequestException(
                        "grantedSecretIds must not contain blank entries");
            }
        }
        return ids.stream().map(String::strip).collect(Collectors.toUnmodifiableSet());
    }

    private static @NonNull String encodeSecretIds(@NonNull Set<String> ids) {
        if (ids.isEmpty()) {
            return "";
        }
        return ids.stream().sorted().distinct().collect(Collectors.joining(","));
    }

    private static @NonNull Set<String> decodeSecretIds(@NonNull String encoded) {
        if (encoded.isEmpty()) {
            return Set.of();
        }
        return Arrays.stream(encoded.split(","))
                .map(String::strip)
                .filter(value -> !value.isEmpty())
                .collect(Collectors.toUnmodifiableSet());
    }
}
