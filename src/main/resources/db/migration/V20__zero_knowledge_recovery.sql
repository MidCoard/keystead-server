create table recovery_enrollments (
    username varchar(255) not null,
    enrollment_id varchar(128) not null,
    generation bigint not null,
    credential_hash varchar(255) not null,
    wrapping_algorithm varchar(64) not null,
    wrapping_public_key text not null,
    encrypted_private_key text not null,
    state varchar(32) not null,
    lifecycle_marker char(1),
    created_at timestamp not null,
    committed_at timestamp,
    consumed_at timestamp,
    primary key (username, enrollment_id, generation),
    constraint ck_recovery_enrollment_generation check (generation > 0),
    constraint ck_recovery_enrollment_state check (
        state in ('PENDING', 'ACTIVE', 'CONSUMED', 'SUPERSEDED')
    ),
    constraint ck_recovery_enrollment_lifecycle check (
        (state = 'PENDING' and lifecycle_marker = 'P')
        or (state = 'ACTIVE' and lifecycle_marker = 'A')
        or (state in ('CONSUMED', 'SUPERSEDED') and lifecycle_marker is null)
    ),
    constraint ux_recovery_enrollment_lifecycle unique (username, lifecycle_marker)
);

create table recovery_vault_packages (
    username varchar(255) not null,
    enrollment_id varchar(128) not null,
    generation bigint not null,
    vault_id varchar(255) not null,
    vault_key_id varchar(255) not null,
    key_algorithm varchar(64) not null,
    encrypted_vault_key text not null,
    created_at timestamp not null,
    updated_at timestamp not null,
    primary key (username, enrollment_id, generation, vault_id),
    constraint fk_recovery_vault_package_enrollment foreign key (
        username, enrollment_id, generation
    ) references recovery_enrollments (username, enrollment_id, generation)
);

create table recovery_challenges (
    challenge_id varchar(255) not null,
    username varchar(255) not null,
    enrollment_id varchar(128),
    generation bigint,
    expires_at timestamp not null,
    attempts integer not null,
    consumed_at timestamp,
    created_at timestamp not null,
    primary key (challenge_id),
    constraint ck_recovery_challenge_attempts check (attempts >= 0 and attempts <= 5),
    constraint ck_recovery_challenge_enrollment check (
        (enrollment_id is null and generation is null)
        or (enrollment_id is not null and generation is not null and generation > 0)
    ),
    constraint ck_recovery_challenge_expiry check (expires_at > created_at)
);

create table recovery_device_requests (
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
    consumed_at timestamp,
    created_at timestamp not null,
    primary key (request_id),
    constraint ck_recovery_request_state check (
        state in ('PENDING', 'APPROVED', 'CONSUMED', 'EXPIRED')
    ),
    constraint ck_recovery_request_expiry check (expires_at > created_at)
);

create table recovery_sessions (
    token_hash varchar(255) not null,
    username varchar(255) not null,
    authority varchar(32) not null,
    enrollment_id varchar(128),
    generation bigint,
    request_id varchar(255),
    expires_at timestamp not null,
    consumed_at timestamp,
    created_at timestamp not null,
    primary key (token_hash),
    constraint ck_recovery_session_authority check (
        (authority = 'KIT' and enrollment_id is not null and generation is not null
            and generation > 0 and request_id is null)
        or (authority = 'DEVICE_APPROVAL' and enrollment_id is null and generation is null
            and request_id is not null)
    ),
    constraint ck_recovery_session_expiry check (expires_at > created_at)
);

create index idx_recovery_challenges_username on recovery_challenges (username);
create index idx_recovery_requests_username on recovery_device_requests (username);
create index idx_recovery_sessions_username on recovery_sessions (username);
