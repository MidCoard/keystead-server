create table vault_key_packages (
    owner_id varchar(255) not null,
    vault_id varchar(255) not null,
    device_id varchar(255) not null,
    key_algorithm varchar(64) not null,
    encrypted_vault_key text not null,
    created_at timestamp not null,
    updated_at timestamp not null,
    -- Named explicitly so V14 can drop it portably: PostgreSQL has no
    -- "DROP PRIMARY KEY" form and the two databases generate different names
    -- for an unnamed inline primary key.
    constraint pk_vault_key_packages primary key (owner_id, vault_id, device_id)
);

create index idx_vault_key_packages_owner_vault
    on vault_key_packages (owner_id, vault_id);
