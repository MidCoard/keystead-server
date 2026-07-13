alter table devices
    add column wrapping_key_algorithm varchar(64);

alter table devices
    add column wrapping_public_key text;

alter table devices
    add constraint ck_devices_wrapping_key_pair
    check (
        (wrapping_key_algorithm is null and wrapping_public_key is null)
        or
        (wrapping_key_algorithm is not null and wrapping_public_key is not null)
    );
