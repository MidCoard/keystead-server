alter table vault_key_packages
    add column vault_key_id varchar(255) not null default 'legacy';
