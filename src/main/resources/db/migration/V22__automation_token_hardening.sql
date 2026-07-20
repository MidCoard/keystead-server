-- Slice 8: automation token hardening.
-- Add a stable opaque token id (distinct from the SHA-256 token hash) so tokens
-- can be listed and revoked without revealing the raw bearer value, and a
-- per-secret grant column that restricts READ_ENCRYPTED_RECORDS to specific
-- secrets (empty = vault-wide, backward compatible).

alter table automation_tokens add column token_id varchar(64);

-- Backfill any pre-existing rows with a deterministic id derived from the
-- (unique) token hash, then enforce NOT NULL + uniqueness.
update automation_tokens set token_id = 'legacy_' || token_hash where token_id is null;

alter table automation_tokens alter column token_id set not null;

alter table automation_tokens add constraint uk_automation_tokens_token_id unique (token_id);

alter table automation_tokens add column granted_secret_ids varchar(4096) not null default '';
