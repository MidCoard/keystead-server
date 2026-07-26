create index idx_encrypted_records_sync_page
    on encrypted_records (owner_id, fingerprint, revision, secret_id);
