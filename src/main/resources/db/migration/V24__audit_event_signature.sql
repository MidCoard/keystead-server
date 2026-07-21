-- Slice 9 Phase 4: tamper-evident audit signing at rest.
-- Nullable: rows written before signing was configured, or while signing is
-- disabled, carry no signature. A verifier with the key treats a null signature
-- as unsigned rather than invalid; a present signature is recomputed and
-- compared to detect any field modification.
alter table audit_events add column signature varchar(128);
