alter table encrypted_records add column encrypted_profile text;

update encrypted_records
   set encrypted_profile = metadata
 where encrypted_profile is null;
