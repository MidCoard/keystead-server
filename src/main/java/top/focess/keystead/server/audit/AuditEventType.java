package top.focess.keystead.server.audit;

public enum AuditEventType {
    RECORD_STORED,
    RECORD_DELETED,
    RECORD_REVISION_CONFLICT,
    KEY_PACKAGE_STORED,
    DEVICE_REVOKED,
    LOGIN_FAILED
}
