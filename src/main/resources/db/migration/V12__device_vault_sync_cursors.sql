create table device_vault_sync_cursors (
    owner_id varchar(255) not null,
    vault_id varchar(255) not null,
    device_id varchar(255) not null,
    pulled_revision bigint not null,
    updated_at timestamp not null,
    primary key (owner_id, vault_id, device_id)
);

create index idx_device_vault_sync_cursors_owner_vault_revision
    on device_vault_sync_cursors (owner_id, vault_id, pulled_revision);
