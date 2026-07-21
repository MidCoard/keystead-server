alter table vault_key_packages
    add column recipient_id varchar(255);

update vault_key_packages
   set recipient_id = owner_id
 where recipient_id is null;

alter table vault_key_packages
    alter column recipient_id set not null;

-- PostgreSQL has no "DROP PRIMARY KEY" form (a MySQL/H2 extension), and H2 and
-- PostgreSQL generate different names for an unnamed inline primary key. V4
-- therefore declares the constraint explicitly as pk_vault_key_packages so it
-- can be dropped and recreated portably here.
alter table vault_key_packages
    drop constraint pk_vault_key_packages;

alter table vault_key_packages
    add constraint pk_vault_key_packages primary key (owner_id, vault_id, recipient_id, device_id);
