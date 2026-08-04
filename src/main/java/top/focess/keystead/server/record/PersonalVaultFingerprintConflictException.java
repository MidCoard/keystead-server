package top.focess.keystead.server.record;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.CONFLICT)
final class PersonalVaultFingerprintConflictException extends RuntimeException {

    final String serverFingerprint;
    final String submittedFingerprint;

    PersonalVaultFingerprintConflictException(
            String serverFingerprint, String submittedFingerprint) {
        super("This account already has a different personal vault");
        this.serverFingerprint = serverFingerprint;
        this.submittedFingerprint = submittedFingerprint;
    }
}
