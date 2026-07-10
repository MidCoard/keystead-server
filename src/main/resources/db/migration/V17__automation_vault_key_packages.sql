create table automation_vault_key_packages (
    owner_id varchar(255) not null,
    vault_id varchar(255) not null,
    principal_id varchar(255) not null,
    vault_key_id varchar(255) not null,
    key_algorithm varchar(64) not null,
    encrypted_vault_key text not null,
    created_at timestamp not null,
    updated_at timestamp not null,
    primary key (owner_id, vault_id, principal_id)
);
