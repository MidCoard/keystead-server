package top.focess.keystead.server.automation;

import java.util.List;
import org.jspecify.annotations.NonNull;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import top.focess.keystead.server.record.EncryptedRecordPageResponse;
import top.focess.keystead.server.record.EncryptedRecordResponse;
import top.focess.keystead.server.record.EncryptedRecordService;

@RestController
@RequestMapping("/api/v1/automation")
class AutomationAccessController {

    private final AutomationService automation;
    private final EncryptedRecordService records;

    AutomationAccessController(
            @NonNull AutomationService automation, @NonNull EncryptedRecordService records) {
        this.automation = automation;
        this.records = records;
    }

    @GetMapping("/records")
    @NonNull List<EncryptedRecordResponse> list(
            @AuthenticationPrincipal @NonNull AutomationTokenSubject subject,
            @RequestParam(defaultValue = "0") long sinceRevision) {
        automation.requireScope(subject, AutomationScope.READ_ENCRYPTED_RECORDS);
        return records.listForAutomation(
                subject.ownerId(), subject.vaultId(), sinceRevision, subject.grantedSecretIds());
    }

    @GetMapping("/records/page")
    @NonNull EncryptedRecordPageResponse page(
            @AuthenticationPrincipal @NonNull AutomationTokenSubject subject,
            @RequestParam(defaultValue = "0") long sinceRevision,
            @RequestParam(defaultValue = "100") int limit) {
        automation.requireScope(subject, AutomationScope.READ_ENCRYPTED_RECORDS);
        return records.pageForAutomation(
                subject.ownerId(),
                subject.vaultId(),
                sinceRevision,
                limit,
                subject.grantedSecretIds());
    }

    @GetMapping("/key-package")
    @NonNull AutomationVaultKeyPackageResponse keyPackage(
            @AuthenticationPrincipal @NonNull AutomationTokenSubject subject) {
        return automation.keyPackage(subject);
    }
}
