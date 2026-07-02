create table app_users (
    username varchar(255) not null primary key,
    password_hash varchar(255) not null,
    created_at timestamp not null,
    updated_at timestamp not null
);

create table devices (
    owner_id varchar(255) not null,
    device_id varchar(255) not null,
    key_algorithm varchar(64) not null,
    public_key text not null,
    created_at timestamp not null,
    primary key (owner_id, device_id)
);

create table vaults (
    owner_id varchar(255) not null,
    vault_id varchar(255) not null,
    encrypted_metadata text not null,
    created_at timestamp not null,
    updated_at timestamp not null,
    primary key (owner_id, vault_id)
);

create index idx_devices_owner
    on devices (owner_id);

create index idx_vaults_owner
    on vaults (owner_id);
