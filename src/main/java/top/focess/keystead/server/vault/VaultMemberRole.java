package top.focess.keystead.server.vault;

public enum VaultMemberRole {
    OWNER,
    ADMIN,
    EDITOR,
    VIEWER;

    public boolean canWriteRecords() {
        return this == OWNER || this == ADMIN || this == EDITOR;
    }

    public boolean canManageMembers() {
        return this == OWNER || this == ADMIN;
    }
}
