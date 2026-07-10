create table vault_key_rotations (
    owner_id varchar(255) not null,
    vault_id varchar(255) not null,
    vault_key_id varchar(255) not null,
    rotated_at timestamp not null,
    primary key (owner_id, vault_id)
);
