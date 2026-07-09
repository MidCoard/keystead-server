package top.focess.keystead.server.identity;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import top.focess.keystead.server.audit.AuditService;
import top.focess.keystead.server.crypto.ServerCryptoAlgorithmRegistry;
import top.focess.keystead.server.crypto.UnsupportedCryptoAlgorithmException;

@Service
class IdentityService {

    private static final Duration CHALLENGE_TTL = Duration.ofMinutes(5);
    private static final int NONCE_BYTES = 32;

    private final UserRepository users;
    private final DeviceRepository devices;
    private final DeviceChallengeRepository challenges;
    private final AuditService audit;
    private final PasswordEncoder passwordEncoder;
    private final Clock clock;
    private final SecureRandom secureRandom;

    IdentityService(
            @NonNull UserRepository users,
            @NonNull DeviceRepository devices,
            @NonNull DeviceChallengeRepository challenges,
            @NonNull AuditService audit,
            @NonNull PasswordEncoder passwordEncoder,
            @NonNull Clock clock) {
        this.users = users;
        this.devices = devices;
        this.challenges = challenges;
        this.audit = audit;
        this.passwordEncoder = passwordEncoder;
        this.clock = clock;
        this.secureRandom = new SecureRandom();
    }

    @Transactional
    void register(@NonNull UserRegistrationRequest request) {
        if (users.exists(request.username())) {
            throw new UserAlreadyExistsException("User already exists");
        }
        Instant now = clock.instant();
        users.insert(
                new StoredUser(
                        request.username(),
                        passwordEncoder.encode(request.password()),
                        now,
                        now,
                        0L));
    }

    @Transactional
    void registerDevice(@NonNull String ownerId, @NonNull DeviceRegistrationRequest request) {
        if (!ServerCryptoAlgorithmRegistry.isApprovedDeviceProofAlgorithm(request.keyAlgorithm())) {
            throw new UnsupportedCryptoAlgorithmException("Unsupported device key algorithm");
        }
        devices.find(ownerId, request.deviceId())
                .ifPresent(
                        device -> {
                            throw new DeviceAlreadyExistsException("Device already exists");
                        });
        devices.insert(
                new StoredDevice(
                        ownerId,
                        request.deviceId(),
                        request.keyAlgorithm(),
                        request.publicKey(),
                        clock.instant(),
                        null,
                        null,
                        null));
    }

    @Transactional(readOnly = true)
    @NonNull List<DeviceResponse> listDevices(@NonNull String ownerId) {
        return devices.list(ownerId).stream().map(DeviceResponse::from).toList();
    }

    @Transactional
    @NonNull DeviceChallengeResponse createDeviceChallenge(
            @NonNull String ownerId, @NonNull String deviceId) {
        StoredDevice device =
                devices.find(ownerId, deviceId)
                        .orElseThrow(() -> new DeviceNotFoundException("Device does not exist"));
        if (device.revokedAt() != null) {
            throw new DeviceNotFoundException("Device does not exist");
        }
        Instant now = clock.instant();
        StoredDeviceChallenge challenge =
                new StoredDeviceChallenge(
                        ownerId,
                        deviceId,
                        UUID.randomUUID().toString(),
                        nonce(),
                        now.plus(CHALLENGE_TTL),
                        null,
                        now);
        challenges.insert(challenge);
        return new DeviceChallengeResponse(
                deviceId, challenge.challengeId(), challenge.nonce(), challenge.expiresAt());
    }

    @Transactional
    void proveDevice(
            @NonNull String ownerId,
            @NonNull String deviceId,
            @NonNull DeviceProofRequest request) {
        Instant now = clock.instant();
        StoredDevice device =
                devices.find(ownerId, deviceId)
                        .orElseThrow(() -> new DeviceNotFoundException("Device does not exist"));
        StoredDeviceChallenge challenge =
                challenges
                        .find(ownerId, deviceId, request.challengeId())
                        .orElseThrow(() -> new DeviceProofFailedException("Device proof failed"));
        if (device.revokedAt() != null
                || challenge.usedAt() != null
                || !challenge.expiresAt().isAfter(now)
                || !verifySignature(device, challenge, request.signature())) {
            throw new DeviceProofFailedException("Device proof failed");
        }
        challenges.markUsed(ownerId, deviceId, challenge.challengeId(), now);
        devices.markVerified(ownerId, deviceId, now);
    }

    @Transactional
    void revokeDevice(@NonNull String ownerId, @NonNull String deviceId) {
        StoredDevice device =
                devices.find(ownerId, deviceId)
                        .orElseThrow(() -> new DeviceNotFoundException("Device does not exist"));
        if (device.revokedAt() != null) {
            return;
        }
        Instant now = clock.instant();
        devices.update(
                new StoredDevice(
                        device.ownerId(),
                        device.deviceId(),
                        device.keyAlgorithm(),
                        device.publicKey(),
                        device.createdAt(),
                        device.verifiedAt(),
                        device.lastSeenAt(),
                        now));
        audit.deviceRevoked(ownerId, ownerId, deviceId);
    }

    private boolean verifySignature(
            @NonNull StoredDevice device,
            @NonNull StoredDeviceChallenge challenge,
            @NonNull String encodedSignature) {
        try {
            Signature signature = Signature.getInstance(signatureAlgorithm(device.keyAlgorithm()));
            configureSignature(signature, device.keyAlgorithm());
            signature.initVerify(publicKey(device));
            signature.update(proofPayload(challenge).getBytes(StandardCharsets.UTF_8));
            return signature.verify(Base64.getDecoder().decode(encodedSignature));
        } catch (IllegalArgumentException | GeneralSecurityException e) {
            return false;
        }
    }

    private @NonNull PublicKey publicKey(@NonNull StoredDevice device)
            throws GeneralSecurityException {
        byte[] keyBytes = Base64.getDecoder().decode(device.publicKey());
        return KeyFactory.getInstance(keyFactoryAlgorithm(device.keyAlgorithm()))
                .generatePublic(new X509EncodedKeySpec(keyBytes));
    }

    private @NonNull String signatureAlgorithm(@NonNull String keyAlgorithm) {
        return switch (keyAlgorithm) {
            case ServerCryptoAlgorithmRegistry.DEVICE_RSA_OAEP_SHA256 -> "SHA256withRSA";
            case ServerCryptoAlgorithmRegistry.DEVICE_RSA_PSS_SHA256 -> "RSASSA-PSS";
            case ServerCryptoAlgorithmRegistry.DEVICE_ECDSA_P256_SHA256 -> "SHA256withECDSA";
            case ServerCryptoAlgorithmRegistry.DEVICE_ECDSA_P384_SHA384 -> "SHA384withECDSA";
            case ServerCryptoAlgorithmRegistry.DEVICE_ECDSA_P521_SHA512 -> "SHA512withECDSA";
            case ServerCryptoAlgorithmRegistry.DEVICE_ED25519 -> "Ed25519";
            default -> throw new IllegalArgumentException("Unsupported device key algorithm");
        };
    }

    private void configureSignature(@NonNull Signature signature, @NonNull String keyAlgorithm)
            throws GeneralSecurityException {
        @Nullable AlgorithmParameterSpec parameters =
                switch (keyAlgorithm) {
                    case ServerCryptoAlgorithmRegistry.DEVICE_RSA_PSS_SHA256 ->
                            rsaPssSha256Parameters();
                    default -> null;
                };
        if (parameters != null) {
            signature.setParameter(parameters);
        }
    }

    private @NonNull PSSParameterSpec rsaPssSha256Parameters() {
        return new PSSParameterSpec(
                "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, PSSParameterSpec.TRAILER_FIELD_BC);
    }

    private @NonNull String keyFactoryAlgorithm(@NonNull String keyAlgorithm) {
        return switch (keyAlgorithm) {
            case ServerCryptoAlgorithmRegistry.DEVICE_RSA_OAEP_SHA256,
                    ServerCryptoAlgorithmRegistry.DEVICE_RSA_PSS_SHA256 ->
                    "RSA";
            case ServerCryptoAlgorithmRegistry.DEVICE_ECDSA_P256_SHA256,
                    ServerCryptoAlgorithmRegistry.DEVICE_ECDSA_P384_SHA384,
                    ServerCryptoAlgorithmRegistry.DEVICE_ECDSA_P521_SHA512 ->
                    "EC";
            case ServerCryptoAlgorithmRegistry.DEVICE_ED25519 -> "Ed25519";
            default -> throw new IllegalArgumentException("Unsupported device key algorithm");
        };
    }

    private @NonNull String proofPayload(@NonNull StoredDeviceChallenge challenge) {
        return "keystead-device-proof:v1:" + challenge.challengeId() + ":" + challenge.nonce();
    }

    private @NonNull String nonce() {
        byte[] value = new byte[NONCE_BYTES];
        secureRandom.nextBytes(value);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }
}
