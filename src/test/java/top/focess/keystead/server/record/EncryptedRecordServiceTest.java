package top.focess.keystead.server.record;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import jakarta.validation.Validation;
import jakarta.validation.Validator;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataIntegrityViolationException;
import top.focess.keystead.server.audit.AuditService;
import top.focess.keystead.server.vault.VaultAccessGuard;

class EncryptedRecordServiceTest {

    private static final Clock CLOCK =
            Clock.fixed(Instant.parse("2026-07-09T00:00:00Z"), ZoneOffset.UTC);

    @Test
    void findRequiresVaultOwnershipBeforeRecordLookup() {
        EncryptedRecordRepository records = mock(EncryptedRecordRepository.class);
        VaultAccessGuard accessGuard = mock(VaultAccessGuard.class);
        AuditService audit = mock(AuditService.class);
        EncryptedRecordService service = newService(records, accessGuard, audit);
        RuntimeException denied = new RuntimeException("vault denied");
        when(accessGuard.requireActiveMemberAndResolveOwner("alice", "vault-denied"))
                .thenThrow(denied);

        RuntimeException exception =
                assertThrows(
                        RuntimeException.class,
                        () -> service.find("alice", "vault-denied", "secret-hidden"));

        assertEquals(denied, exception);
        verify(records, never()).find("alice", "vault-denied", "secret-hidden");
    }

    @Test
    void storeTranslatesRacedRevisionConstraintIntoConflict() {
        EncryptedRecordRepository records = mock(EncryptedRecordRepository.class);
        VaultAccessGuard accessGuard = mock(VaultAccessGuard.class);
        AuditService audit = mock(AuditService.class);
        EncryptedRecordService service = newService(records, accessGuard, audit);
        when(accessGuard.requireActiveMemberAndResolveOwner("alice", "vault-race"))
                .thenReturn("alice");
        StoredEncryptedRecord latest =
                storedRecord("alice", "vault-race", "secret-existing", 4L, false);
        when(records.find("alice", "vault-race", "secret-new")).thenReturn(Optional.empty());
        when(records.latestRevision("alice", "vault-race"))
                .thenReturn(Optional.empty(), Optional.of(latest));
        doThrow(new DataIntegrityViolationException("duplicate revision"))
                .when(records)
                .insert(any(StoredEncryptedRecord.class));

        RevisionConflictException exception =
                assertThrows(
                        RevisionConflictException.class,
                        () ->
                                service.store(
                                        "alice",
                                        "vault-race",
                                        "secret-new",
                                        new EncryptedRecordRequest(
                                                4L,
                                                "SECURE_NOTE",
                                                "metadata",
                                                null,
                                                "envelope",
                                                false)));

        assertEquals("vault-race", exception.vaultId());
        assertEquals("secret-new", exception.secretId());
        assertEquals(4L, exception.latestRevision());
        assertEquals(4L, exception.rejectedRevision());
        verify(audit).recordRevisionConflict("alice", "alice", "vault-race", "secret-new", 4L, 4L);
    }

    @Test
    void deleteTranslatesRacedRevisionConstraintIntoConflict() {
        EncryptedRecordRepository records = mock(EncryptedRecordRepository.class);
        VaultAccessGuard accessGuard = mock(VaultAccessGuard.class);
        AuditService audit = mock(AuditService.class);
        EncryptedRecordService service = newService(records, accessGuard, audit);
        when(accessGuard.requireActiveMemberAndResolveOwner("alice", "vault-delete-race"))
                .thenReturn("alice");
        StoredEncryptedRecord existing =
                storedRecord("alice", "vault-delete-race", "secret-delete", 2L, false);
        StoredEncryptedRecord latest =
                storedRecord("alice", "vault-delete-race", "secret-other", 3L, false);
        when(records.find("alice", "vault-delete-race", "secret-delete"))
                .thenReturn(Optional.of(existing));
        when(records.latestRevision("alice", "vault-delete-race"))
                .thenReturn(Optional.of(existing), Optional.of(latest));
        doThrow(new DataIntegrityViolationException("duplicate revision"))
                .when(records)
                .update(any(StoredEncryptedRecord.class));

        RevisionConflictException exception =
                assertThrows(
                        RevisionConflictException.class,
                        () -> service.delete("alice", "vault-delete-race", "secret-delete", 3L));

        assertEquals("vault-delete-race", exception.vaultId());
        assertEquals("secret-delete", exception.secretId());
        assertEquals(3L, exception.latestRevision());
        assertEquals(3L, exception.rejectedRevision());
        verify(audit)
                .recordRevisionConflict(
                        "alice", "alice", "vault-delete-race", "secret-delete", 3L, 3L);
    }

    private static StoredEncryptedRecord storedRecord(
            String ownerId, String vaultId, String secretId, long revision, boolean deleted) {
        return new StoredEncryptedRecord(
                ownerId,
                vaultId,
                secretId,
                revision,
                "SECURE_NOTE",
                deleted ? "" : "encrypted-profile",
                deleted ? "" : "encrypted-profile",
                deleted ? "" : "envelope",
                deleted,
                CLOCK.instant());
    }

    private static EncryptedRecordService newService(
            EncryptedRecordRepository records, VaultAccessGuard accessGuard, AuditService audit) {
        Validator validator = Validation.buildDefaultValidatorFactory().getValidator();
        return new EncryptedRecordService(records, accessGuard, audit, CLOCK, validator);
    }
}
