package top.focess.keystead.server.vault;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class VaultMemberRoleTest {

    @Test
    void writePermissionExcludesViewers() {
        assertTrue(VaultMemberRole.OWNER.canWriteRecords());
        assertTrue(VaultMemberRole.ADMIN.canWriteRecords());
        assertTrue(VaultMemberRole.EDITOR.canWriteRecords());
        assertFalse(VaultMemberRole.VIEWER.canWriteRecords());
    }

    @Test
    void memberManagementIsRestrictedToOwnersAndAdmins() {
        assertTrue(VaultMemberRole.OWNER.canManageMembers());
        assertTrue(VaultMemberRole.ADMIN.canManageMembers());
        assertFalse(VaultMemberRole.EDITOR.canManageMembers());
        assertFalse(VaultMemberRole.VIEWER.canManageMembers());
    }
}
