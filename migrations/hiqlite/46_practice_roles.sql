ALTER TABLE shared_device_practices ADD role_mode INTEGER NOT NULL DEFAULT 0;
-- Additive role mode. Existing personal PINs remain unchanged.
CREATE TABLE shared_practice_roles (
    practice_id TEXT NOT NULL REFERENCES shared_device_practices(id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (role IN ('administration', 'management', 'staff')),
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    pin_hmac BLOB,
    pin_key_id TEXT,
    pin_version INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(practice_id, role)
);
CREATE TABLE shared_role_sessions (
    session_id TEXT PRIMARY KEY REFERENCES sessions(id) ON DELETE CASCADE,
    pin_version INTEGER NOT NULL,
    practice_id TEXT NOT NULL,
    role TEXT NOT NULL,
    FOREIGN KEY(practice_id, role) REFERENCES shared_practice_roles(practice_id, role) ON DELETE CASCADE
);
CREATE TABLE shared_role_attempts (
    device_id TEXT NOT NULL REFERENCES shared_devices(id) ON DELETE CASCADE,
    role TEXT NOT NULL,
    failures INTEGER NOT NULL DEFAULT 0,
    locked_until INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(device_id, role)
);
CREATE TABLE practice_password_attempts (
    user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    failures INTEGER NOT NULL DEFAULT 0,
    locked_until INTEGER NOT NULL DEFAULT 0
);

ALTER TABLE shared_device_events ADD role TEXT;
