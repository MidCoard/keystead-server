alter table app_users
    add column token_version bigint not null default 0;
