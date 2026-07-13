package top.focess.keystead.server.identity;

import java.time.Instant;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import top.focess.keystead.server.crypto.ServerCryptoAlgorithmRegistry;

@Service
public class IdentityRecoveryService {

    private final UserRepository users;
    private final DeviceRepository devices;
    private final DeviceSignatureVerifier signatures;

    IdentityRecoveryService(
            @NonNull UserRepository users,
            @NonNull DeviceRepository devices,
            @NonNull DeviceSignatureVerifier signatures) {
        this.users = users;
        this.devices = devices;
        this.signatures = signatures;
    }

    @Transactional
    public void resetPasswordAndEnrollVerifiedDevice(
            @NonNull String username,
            @NonNull String passwordHash,
            @NonNull RecoveryDeviceRegistration registration,
            @NonNull Instant now) {
        if (devices.find(username, registration.deviceId()).isPresent()) {
            throw new IdentityRecoveryConflictException("Replacement device already exists");
        }
        requireValidDevice(registration);
        if (users.resetCredentials(username, passwordHash, now) != 1) {
            throw new IdentityRecoveryConflictException("Recovery account does not exist");
        }
        devices.insert(
                new StoredDevice(
                        username,
                        registration.deviceId(),
                        registration.proofKeyAlgorithm(),
                        registration.proofPublicKey(),
                        registration.wrappingKeyAlgorithm(),
                        registration.wrappingPublicKey(),
                        now,
                        now,
                        now,
                        null));
    }

    private void requireValidDevice(@NonNull RecoveryDeviceRegistration registration) {
        if (!ServerCryptoAlgorithmRegistry.isApprovedDeviceProofAlgorithm(
                        registration.proofKeyAlgorithm())
                || !signatures.isValidPublicKey(
                        registration.proofKeyAlgorithm(), registration.proofPublicKey())) {
            throw new IdentityRecoveryConflictException("Replacement device proof key is invalid");
        }
        if (!ServerCryptoAlgorithmRegistry.isApprovedDeviceWrappingPublicKeyAlgorithm(
                registration.wrappingKeyAlgorithm())) {
            throw new IdentityRecoveryConflictException(
                    "Replacement device wrapping key is invalid");
        }
        if (registration.proofPublicKey().equals(registration.wrappingPublicKey())) {
            throw new IdentityRecoveryConflictException("Replacement device keys must be distinct");
        }
    }
}
