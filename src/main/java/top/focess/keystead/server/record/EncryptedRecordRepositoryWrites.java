package top.focess.keystead.server.record;

import org.jspecify.annotations.NonNull;

interface EncryptedRecordRepositoryWrites {

    void insert(@NonNull StoredEncryptedRecord record);

    void update(@NonNull StoredEncryptedRecord record);
}
