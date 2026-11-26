CREATE TABLE mcp_cloud.sessions (
 session_id TEXT PRIMARY KEY,
 credential_digest TEXT NOT NULL UNIQUE,
 created DOUBLE PRECISION NOT NULL,
 updated DOUBLE PRECISION NOT NULL
);
