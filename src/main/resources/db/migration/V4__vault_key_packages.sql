create table vault_key_packages (
    owner_id varchar(255) not null,
    vault_id varchar(255) not null,
    device_id varchar(255) not null,
    key_algorithm varchar(64) not null,
    encrypted_vault_key text not null,
    created_at timestamp not null,
    updated_at timestamp not null,
    primary key (owner_id, vault_id, device_id)
);

create index idx_vault_key_packages_owner_vault
    on vault_key_packages (owner_id, vault_id);
