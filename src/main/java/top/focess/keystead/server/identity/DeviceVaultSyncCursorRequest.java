package top.focess.keystead.server.identity;

import jakarta.validation.constraints.PositiveOrZero;

record DeviceVaultSyncCursorRequest(@PositiveOrZero long pulledRevision) {}
