"""Exact additive v3 schema. Every key is unique across all trusted scopes."""

OPERATIONS = """CREATE TABLE operations (
    operation_id TEXT PRIMARY KEY NOT NULL,
    key_digest TEXT UNIQUE NOT NULL,
    request_id TEXT UNIQUE NOT NULL,
    connection TEXT NOT NULL, tool TEXT NOT NULL, arguments TEXT NOT NULL,
    identity TEXT NOT NULL, policy TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('RESERVED','IN_PROGRESS','COMPLETED',
        'FAILED_BEFORE_EFFECT','OUTCOME_UNKNOWN')),
    pre_id TEXT UNIQUE NOT NULL REFERENCES audit_events(event_id),
    post_id TEXT UNIQUE REFERENCES audit_events(event_id),
    created REAL NOT NULL, updated REAL NOT NULL, expires REAL NOT NULL,
    completed REAL, receipt TEXT, error TEXT,
    CHECK((state='COMPLETED')=(completed IS NOT NULL)),
    CHECK(state!='COMPLETED' OR (receipt IS NOT NULL AND post_id IS NOT NULL AND error IS NULL))
)"""
ATTEMPTS = """CREATE TABLE operation_attempts (
    event_id TEXT PRIMARY KEY REFERENCES audit_events(event_id),
    operation_id TEXT NOT NULL REFERENCES operations(operation_id),
    decision TEXT NOT NULL CHECK(decision IN ('new','replay','in_progress','conflict',
        'unknown','denied'))
)"""

STATE_GUARD = """CREATE TRIGGER operation_state_guard BEFORE UPDATE ON operations
WHEN OLD.state='COMPLETED' OR NOT (
    NEW.state=OLD.state OR
    (OLD.state='RESERVED' AND NEW.state IN ('IN_PROGRESS','FAILED_BEFORE_EFFECT')) OR
    (OLD.state='IN_PROGRESS' AND NEW.state IN ('COMPLETED','OUTCOME_UNKNOWN'))
) BEGIN SELECT RAISE(ABORT, 'operation transition denied'); END"""
