create table shares (
    code varchar(64) not null primary key,
    owner_id varchar(255) not null,
    payload text not null,
    burn_after_reading boolean not null,
    expires_at timestamp not null,
    created_at timestamp not null
);

create index idx_shares_owner on shares (owner_id);
create index idx_shares_expires_at on shares (expires_at);
