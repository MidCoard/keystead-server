drop table vault_access_requests;

create table vault_access_requests (
    request_id varchar(36) not null,
    username varchar(255) not null,
    server_origin varchar(2048) not null,
    fingerprint varchar(64) not null,
    key_algorithm varchar(64) not null,
    exchange_public_key text not null,
    state varchar(32) not null,
    expires_at timestamp not null,
    vault_fingerprint varchar(255),
    vault_key_id varchar(255),
    package_key_algorithm varchar(64),
    encrypted_vault_key text,
    approved_at timestamp,
    created_at timestamp not null,
    primary key (request_id),
    constraint ck_vault_access_request_state_v2 check (
        state in ('PENDING', 'APPROVED', 'EXPIRED')
    ),
    constraint ck_vault_access_request_expiry_v2 check (expires_at > created_at)
);

create index idx_vault_access_requests_username_v2
    on vault_access_requests (username, state, expires_at);
