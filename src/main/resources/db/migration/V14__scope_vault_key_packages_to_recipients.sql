alter table vault_key_packages
    add column recipient_id varchar(255);

update vault_key_packages
   set recipient_id = owner_id
 where recipient_id is null;

alter table vault_key_packages
    alter column recipient_id set not null;

alter table vault_key_packages
    drop primary key;

alter table vault_key_packages
    add primary key (owner_id, vault_id, recipient_id, device_id);
