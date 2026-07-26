create unique index uq_encrypted_records_owner_vault_revision
    on encrypted_records (owner_id, fingerprint, revision);
