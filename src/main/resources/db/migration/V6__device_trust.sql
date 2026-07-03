alter table devices
    add column verified_at timestamp;

alter table devices
    add column last_seen_at timestamp;

alter table devices
    add column revoked_at timestamp;

create table device_challenges (
    owner_id varchar(255) not null,
    device_id varchar(255) not null,
    challenge_id varchar(255) not null,
    nonce varchar(255) not null,
    expires_at timestamp not null,
    used_at timestamp,
    created_at timestamp not null,
    primary key (owner_id, device_id, challenge_id)
);

create index idx_device_challenges_owner_device
    on device_challenges (owner_id, device_id);
