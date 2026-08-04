drop table if exists recovery_device_request_packages;
drop table if exists recovery_sessions;
drop table if exists recovery_vault_packages;
drop table if exists recovery_challenges;
drop table if exists recovery_device_requests;
drop table if exists recovery_enrollments;

drop table if exists vault_rotation_packages;
drop table if exists vault_rotation_targets;
drop table if exists vault_key_states;
drop table if exists vault_rotation_generations;
drop table if exists vault_key_rotations;
drop table if exists vault_key_packages;
drop table if exists vault_members;

drop table if exists automation_vault_key_packages;
drop table if exists automation_tokens;
drop table if exists automation_principals;

drop table if exists device_vault_sync_cursors;
drop table if exists encrypted_records;
drop table if exists vaults;
drop table if exists device_challenges;
drop table if exists devices;

alter table auth_refresh_tokens drop column if exists device_id;
