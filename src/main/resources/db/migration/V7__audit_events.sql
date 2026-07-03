create table audit_events (
    event_id varchar(36) not null,
    owner_id varchar(255) not null,
    actor_id varchar(255) not null,
    event_type varchar(64) not null,
    target_type varchar(64) not null,
    target_id varchar(255) not null,
    vault_id varchar(255),
    revision bigint,
    outcome varchar(64) not null,
    details text not null,
    created_at timestamp not null,
    primary key (event_id)
);

create index idx_audit_events_owner_created
    on audit_events (owner_id, created_at);

create index idx_audit_events_owner_vault
    on audit_events (owner_id, vault_id);
