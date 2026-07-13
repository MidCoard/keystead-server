alter table vault_members add constraint ck_vault_member_state check (
    state in ('INVITED', 'ACCEPTED_PENDING_KEY', 'ACTIVE', 'REMOVED')
);

create table vault_key_states (
    owner_id varchar(255) not null,
    vault_id varchar(255) not null,
    current_vault_key_id varchar(255),
    lifecycle_state varchar(32) not null,
    lifecycle_version bigint not null,
    pending_generation_id varchar(255),
    updated_at timestamp not null,
    primary key (owner_id, vault_id),
    constraint fk_vault_key_state_vault foreign key (owner_id, vault_id)
        references vaults (owner_id, vault_id),
    constraint ck_vault_key_state_lifecycle_state check (
        lifecycle_state in ('STABLE', 'ROTATION_REQUIRED', 'ROTATING')
    ),
    constraint ck_vault_key_state_lifecycle_version check (lifecycle_version > 0),
    constraint ck_vault_key_state_pending_generation check (
        (lifecycle_state = 'ROTATING' and pending_generation_id is not null)
        or (lifecycle_state in ('STABLE', 'ROTATION_REQUIRED')
            and pending_generation_id is null)
    ),
    constraint ux_vault_key_state_pending_generation unique (pending_generation_id)
);

create table vault_rotation_generations (
    generation_id varchar(255) not null,
    owner_id varchar(255) not null,
    vault_id varchar(255) not null,
    source_key_id varchar(255),
    target_key_id varchar(255) not null,
    state varchar(32) not null,
    initiator_id varchar(255) not null,
    lifecycle_version bigint not null,
    prior_lifecycle_state varchar(32) not null,
    pending_marker char(1),
    created_at timestamp not null,
    updated_at timestamp not null,
    primary key (generation_id),
    constraint uq_vault_rotation_generation_binding unique (
        generation_id, owner_id, vault_id
    ),
    constraint fk_vault_rotation_generation_vault foreign key (owner_id, vault_id)
        references vaults (owner_id, vault_id),
    constraint ck_vault_rotation_generation_state check (
        state in ('OPEN', 'PACKAGING', 'READY', 'COMMITTED')
    ),
    constraint ck_vault_rotation_generation_version check (lifecycle_version > 0),
    constraint ck_vault_rotation_generation_prior_state check (
        prior_lifecycle_state in ('STABLE', 'ROTATION_REQUIRED')
    ),
    constraint ck_vault_rotation_generation_pending check (
        (state in ('OPEN', 'PACKAGING', 'READY') and pending_marker = 'P')
        or (state = 'COMMITTED' and pending_marker is null)
    ),
    constraint ux_vault_rotation_pending_generation unique (
        owner_id, vault_id, pending_marker
    )
);

alter table vault_key_states add constraint fk_vault_key_state_pending_generation
    foreign key (pending_generation_id, owner_id, vault_id)
    references vault_rotation_generations (generation_id, owner_id, vault_id);

create table vault_rotation_targets (
    generation_id varchar(255) not null,
    target_id varchar(255) not null,
    target_type varchar(32) not null,
    recipient_id varchar(255),
    device_id varchar(255),
    principal_id varchar(255),
    enrollment_id varchar(128),
    recovery_generation bigint,
    key_algorithm varchar(64) not null,
    public_key text not null,
    required boolean not null,
    primary key (generation_id, target_id),
    constraint fk_vault_rotation_target_generation foreign key (generation_id)
        references vault_rotation_generations (generation_id),
    constraint ck_vault_rotation_target_type check (
        target_type in ('DEVICE', 'AUTOMATION', 'RECOVERY')
    ),
    constraint ck_vault_rotation_target_identity check (
        (target_type = 'DEVICE'
            and recipient_id is not null and device_id is not null
            and principal_id is null and enrollment_id is null
            and recovery_generation is null)
        or (target_type = 'AUTOMATION'
            and recipient_id is null and device_id is null
            and principal_id is not null and enrollment_id is null
            and recovery_generation is null)
        or (target_type = 'RECOVERY'
            and recipient_id is not null and device_id is null
            and principal_id is null and enrollment_id is not null
            and recovery_generation is not null and recovery_generation > 0)
    )
);

create table vault_rotation_packages (
    generation_id varchar(255) not null,
    target_id varchar(255) not null,
    key_algorithm varchar(64) not null,
    encrypted_vault_key text not null,
    created_at timestamp not null,
    primary key (generation_id, target_id),
    constraint fk_vault_rotation_package_target foreign key (generation_id, target_id)
        references vault_rotation_targets (generation_id, target_id)
);

insert into vault_key_states (
    owner_id,
    vault_id,
    current_vault_key_id,
    lifecycle_state,
    lifecycle_version,
    pending_generation_id,
    updated_at
)
select owner_id, vault_id, vault_key_id, 'STABLE', 1, null, rotated_at
  from vault_key_rotations;

drop table vault_key_rotations;

create index idx_vault_rotation_generations_vault
    on vault_rotation_generations (owner_id, vault_id);
create index idx_vault_rotation_targets_generation
    on vault_rotation_targets (generation_id);
