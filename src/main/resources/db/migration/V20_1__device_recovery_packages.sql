create table recovery_device_request_packages (
    request_id varchar(255) not null,
    vault_id varchar(255) not null,
    vault_key_id varchar(255) not null,
    key_algorithm varchar(64) not null,
    encrypted_vault_key text not null,
    created_at timestamp not null,
    primary key (request_id, vault_id),
    constraint fk_recovery_request_package_request foreign key (request_id)
        references recovery_device_requests (request_id)
);
