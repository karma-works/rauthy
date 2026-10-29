ALTER TABLE shared_device_practices ADD role_mode BOOLEAN NOT NULL DEFAULT false;
-- Additive role mode. Existing personal PINs remain unchanged.
CREATE TABLE shared_practice_roles (
    practice_id VARCHAR NOT NULL REFERENCES shared_device_practices(id) ON DELETE CASCADE,
    role VARCHAR NOT NULL CHECK (role IN ('administration', 'management', 'staff')),
    user_id VARCHAR NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    pin_hmac BYTEA,
    pin_key_id VARCHAR,
    pin_version BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY(practice_id, role)
);
CREATE TABLE shared_role_sessions (
    session_id VARCHAR PRIMARY KEY REFERENCES sessions(id) ON DELETE CASCADE,
    pin_version BIGINT NOT NULL,
    practice_id VARCHAR NOT NULL,
    role VARCHAR NOT NULL,
    FOREIGN KEY(practice_id, role) REFERENCES shared_practice_roles(practice_id, role) ON DELETE CASCADE
);
CREATE TABLE shared_role_attempts (
    device_id VARCHAR NOT NULL REFERENCES shared_devices(id) ON DELETE CASCADE,
    role VARCHAR NOT NULL,
    failures BIGINT NOT NULL DEFAULT 0,
    locked_until BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY(device_id, role)
);
CREATE TABLE practice_password_attempts (
    user_id VARCHAR PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    failures BIGINT NOT NULL DEFAULT 0,
    locked_until BIGINT NOT NULL DEFAULT 0
);

ALTER TABLE shared_device_events ADD role VARCHAR;
