create table vault_members (
    vault_id varchar(255) not null,
    user_id varchar(255) not null,
    role varchar(32) not null,
    state varchar(32) not null,
    created_at timestamp not null,
    updated_at timestamp not null,
    primary key (vault_id, user_id)
);

insert into vault_members (vault_id, user_id, role, state, created_at, updated_at)
select vault_id, owner_id, 'OWNER', 'ACTIVE', created_at, updated_at
  from vaults;
