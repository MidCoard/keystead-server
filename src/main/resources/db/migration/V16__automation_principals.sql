create table automation_principals (
    owner_id varchar(255) not null,
    principal_id varchar(255) not null,
    public_key_algorithm varchar(64) not null,
    public_key text not null,
    created_at timestamp not null,
    updated_at timestamp not null,
    revoked_at timestamp,
    primary key (owner_id, principal_id)
);

create table automation_tokens (
    token_hash varchar(64) not null primary key,
    owner_id varchar(255) not null,
    principal_id varchar(255) not null,
    vault_id varchar(255) not null,
    scopes varchar(255) not null,
    expires_at timestamp not null,
    created_at timestamp not null,
    revoked_at timestamp,
    last_used_at timestamp
);

create index idx_automation_tokens_owner_principal on automation_tokens (owner_id, principal_id);
