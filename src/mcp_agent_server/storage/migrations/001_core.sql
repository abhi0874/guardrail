CREATE TABLE audit_events (
    event_id TEXT PRIMARY KEY NOT NULL,
    request_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    connection_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    phase TEXT NOT NULL CHECK(phase IN ('pre','post','denied')),
    allowed INTEGER NOT NULL CHECK(allowed IN (0,1)),
    validation TEXT NOT NULL,
    status TEXT NOT NULL,
    error_code TEXT,
    duration_ms DOUBLE PRECISION NOT NULL CHECK(duration_ms >= 0),
    argument_summary TEXT NOT NULL,
    parent_event_id TEXT,
    UNIQUE(request_id, phase), UNIQUE(request_id, event_id),
    CHECK((phase = 'post') = (parent_event_id IS NOT NULL)),
    FOREIGN KEY(request_id, parent_event_id) REFERENCES audit_events(request_id, event_id)
);

CREATE TABLE approvals (
    reference TEXT PRIMARY KEY NOT NULL,
    token_digest TEXT NOT NULL UNIQUE,
    connection_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    arguments_digest TEXT NOT NULL,
    identity_digest TEXT NOT NULL,
    policy_digest TEXT NOT NULL,
    issued_at DOUBLE PRECISION NOT NULL,
    expires_at DOUBLE PRECISION NOT NULL CHECK(expires_at > issued_at),
    issuer TEXT NOT NULL, approval_order BIGINT GENERATED ALWAYS AS IDENTITY UNIQUE,
    revoked_at DOUBLE PRECISION,
    consumed_at DOUBLE PRECISION,
    consumed_event TEXT UNIQUE REFERENCES audit_events(event_id),
    CHECK ((consumed_at IS NULL) = (consumed_event IS NULL))
);

CREATE TABLE audit_policy (
    event_id TEXT PRIMARY KEY REFERENCES audit_events(event_id),
    policy_digest TEXT NOT NULL,
    principal TEXT NOT NULL,
    approval_required INTEGER,
    approval_ref TEXT REFERENCES approvals(reference)
);

CREATE TABLE operations (
    operation_id TEXT PRIMARY KEY NOT NULL,
    key_digest TEXT UNIQUE NOT NULL,
    request_id TEXT UNIQUE NOT NULL,
    connection TEXT NOT NULL, tool TEXT NOT NULL, arguments TEXT NOT NULL,
    identity TEXT NOT NULL, policy TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('RESERVED','IN_PROGRESS','COMPLETED',
        'FAILED_BEFORE_EFFECT','OUTCOME_UNKNOWN')),
    pre_id TEXT UNIQUE NOT NULL REFERENCES audit_events(event_id),
    post_id TEXT UNIQUE REFERENCES audit_events(event_id),
    created DOUBLE PRECISION NOT NULL, updated DOUBLE PRECISION NOT NULL, expires DOUBLE PRECISION NOT NULL,
    completed DOUBLE PRECISION, receipt TEXT, error TEXT,
    CHECK((state='COMPLETED')=(completed IS NOT NULL)),
    CHECK(state!='COMPLETED' OR (receipt IS NOT NULL AND post_id IS NOT NULL AND error IS NULL))
);

CREATE TABLE operation_attempts (
    event_id TEXT PRIMARY KEY REFERENCES audit_events(event_id),
    operation_id TEXT NOT NULL REFERENCES operations(operation_id),
    decision TEXT NOT NULL CHECK(decision IN ('new','replay','in_progress','conflict',
        'unknown','denied'))
);

CREATE TABLE notes (
    note_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, title TEXT NOT NULL CHECK(length(title) BETWEEN 1 AND 120),
    body TEXT NOT NULL CHECK(length(body) BETWEEN 1 AND 1500)
);

CREATE FUNCTION operation_transition() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF OLD.state='COMPLETED' OR NOT (
 NEW.state=OLD.state OR
 (OLD.state='RESERVED' AND NEW.state IN ('IN_PROGRESS','FAILED_BEFORE_EFFECT')) OR
 (OLD.state='IN_PROGRESS' AND NEW.state IN ('COMPLETED','OUTCOME_UNKNOWN')))
 THEN RAISE EXCEPTION 'operation transition denied'; END IF;
 RETURN NEW;
END
$$;
CREATE TRIGGER operation_state_guard BEFORE UPDATE ON operations
FOR EACH ROW EXECUTE FUNCTION operation_transition();
