create table auth_refresh_tokens (
    token_hash varchar(64) not null,
    username varchar(255) not null,
    device_id varchar(255),
    refresh_expires_at timestamp not null,
    revoked_at timestamp,
    created_at timestamp not null,
    last_used_at timestamp not null,
    primary key (token_hash)
);

create index idx_auth_refresh_tokens_username
    on auth_refresh_tokens (username);
