create table vault_access_requests (
    request_id varchar(255) not null,
    username varchar(255) not null,
    nonce varchar(255) not null,
    fingerprint varchar(64) not null,
    device_id varchar(255) not null,
    proof_key_algorithm varchar(64) not null,
    proof_public_key text not null,
    wrapping_key_algorithm varchar(64) not null,
    wrapping_public_key text not null,
    state varchar(32) not null,
    expires_at timestamp not null,
    approved_by_device_id varchar(255),
    approved_at timestamp,
    created_at timestamp not null,
    primary key (request_id),
    constraint ck_vault_access_request_state check (
        state in ('PENDING', 'APPROVED', 'EXPIRED')
    ),
    constraint ck_vault_access_request_expiry check (expires_at > created_at)
);

create index idx_vault_access_requests_username
    on vault_access_requests (username, state, expires_at);

delete from vault_rotation_packages
 where exists (
    select 1
      from vault_rotation_targets t
     where t.generation_id = vault_rotation_packages.generation_id
       and t.target_id = vault_rotation_packages.target_id
       and t.target_type = 'RECOVERY'
 );

delete from vault_rotation_targets where target_type = 'RECOVERY';

alter table vault_rotation_targets drop constraint ck_vault_rotation_target_identity;
alter table vault_rotation_targets drop constraint ck_vault_rotation_target_type;

alter table vault_rotation_targets add constraint ck_vault_rotation_target_type check (
    target_type in ('DEVICE', 'AUTOMATION')
);

alter table vault_rotation_targets add constraint ck_vault_rotation_target_identity check (
    (target_type = 'DEVICE'
        and recipient_id is not null and device_id is not null
        and principal_id is null and enrollment_id is null
        and recovery_generation is null)
    or (target_type = 'AUTOMATION'
        and recipient_id is null and device_id is null
        and principal_id is not null and enrollment_id is null
        and recovery_generation is null)
);

drop table recovery_device_request_packages;
drop table recovery_sessions;
drop table recovery_challenges;
drop table recovery_vault_packages;
drop table recovery_device_requests;
drop table recovery_enrollments;
