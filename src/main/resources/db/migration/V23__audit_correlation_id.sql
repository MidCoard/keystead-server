-- Slice 9 Phase 2: per-request correlation id for audit traceability.
-- Nullable: events recorded outside a request (scheduled tasks, direct repository
-- calls, or rows written before this column existed) carry no correlation id.
alter table audit_events add column correlation_id varchar(64);
