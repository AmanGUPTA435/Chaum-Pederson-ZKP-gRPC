CREATE TABLE users (
    user_name TEXT PRIMARY KEY,
    y1 BYTEA NOT NULL,
    y2 BYTEA NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE auth_logs (
    id SERIAL PRIMARY KEY,
    user_name TEXT NOT NULL,
    auth_id TEXT,
    session_id TEXT,
    success BOOLEAN NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    failure_reason TEXT,

    FOREIGN KEY (user_name) REFERENCES users(user_name) ON DELETE CASCADE
);

CREATE TABLE sessions (
    session_id TEXT PRIMARY KEY,
    user_name TEXT NOT NULL,
    auth_id TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,

    FOREIGN KEY (user_name) REFERENCES users(user_name) ON DELETE CASCADE
);

CREATE INDEX idx_auth_logs_user_name ON auth_logs(user_name);
CREATE INDEX idx_sessions_user_name ON sessions(user_name);
