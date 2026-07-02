create table encrypted_records (
    owner_id varchar(255) not null,
    vault_id varchar(255) not null,
    secret_id varchar(255) not null,
    revision bigint not null,
    secret_type varchar(64) not null,
    metadata text not null,
    envelope text not null,
    deleted boolean not null,
    updated_at timestamp not null,
    primary key (owner_id, vault_id, secret_id)
);

create index idx_encrypted_records_owner_vault
    on encrypted_records (owner_id, vault_id);
