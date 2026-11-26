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
    duration_ms REAL NOT NULL CHECK(duration_ms >= 0),
    argument_summary TEXT NOT NULL,
    parent_event_id TEXT,
    UNIQUE(request_id, phase), UNIQUE(request_id, event_id),
    CHECK((phase = 'post') = (parent_event_id IS NOT NULL)),
    FOREIGN KEY(request_id, parent_event_id) REFERENCES audit_events(request_id, event_id)
);
PRAGMA user_version=1;
