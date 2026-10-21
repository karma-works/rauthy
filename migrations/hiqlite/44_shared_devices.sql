-- Registered shared devices (practice PCs) and the PIN sign-in on them, see
-- `rauthy_data::entity::shared_devices`.
CREATE TABLE shared_device_practices
(
    id              TEXT    NOT NULL
        CONSTRAINT shared_device_practices_pk
            PRIMARY KEY,
    name            TEXT    NOT NULL,
    idle_timeout    INTEGER NOT NULL,
    notify_user_ids TEXT    NOT NULL,
    risk_ack_by     TEXT,
    risk_ack_at     INTEGER,
    created         INTEGER NOT NULL,
    updated         INTEGER NOT NULL
) STRICT;

-- Only an HMAC of each PIN is stored, keyed with the encryption key `pin_key_id`.
CREATE TABLE shared_device_members
(
    practice_id TEXT    NOT NULL
        CONSTRAINT shared_device_members_practices_id_fk
            REFERENCES shared_device_practices
            ON UPDATE CASCADE ON DELETE CASCADE,
    user_id     TEXT    NOT NULL
        CONSTRAINT shared_device_members_users_id_fk
            REFERENCES users
            ON UPDATE CASCADE ON DELETE CASCADE,
    pin_hmac    BLOB,
    pin_key_id  TEXT,
    pin_created INTEGER,
    created     INTEGER NOT NULL,
    CONSTRAINT shared_device_members_pk
        PRIMARY KEY (practice_id, user_id)
) STRICT;

CREATE UNIQUE INDEX shared_device_members_pin
    ON shared_device_members (practice_id, pin_hmac);

CREATE INDEX shared_device_members_user_id
    ON shared_device_members (user_id);

CREATE TABLE shared_devices
(
    id            TEXT    NOT NULL
        CONSTRAINT shared_devices_pk
            PRIMARY KEY,
    practice_id   TEXT    NOT NULL
        CONSTRAINT shared_devices_practices_id_fk
            REFERENCES shared_device_practices
            ON UPDATE CASCADE ON DELETE CASCADE,
    label         TEXT    NOT NULL,
    token_hash    BLOB    NOT NULL,
    public_key    BLOB    NOT NULL,
    ip_registered TEXT    NOT NULL,
    ip_lock       INTEGER NOT NULL,
    failed_pins   INTEGER NOT NULL,
    locked_at     INTEGER,
    created_by    TEXT    NOT NULL,
    created       INTEGER NOT NULL,
    last_seen     INTEGER NOT NULL,
    last_seen_ip  TEXT,
    ip_warned     INTEGER
) STRICT;

CREATE UNIQUE INDEX shared_devices_token_hash
    ON shared_devices (token_hash);

CREATE INDEX shared_devices_practice_id
    ON shared_devices (practice_id);

-- Security log per practice, kept 90 days. No User-Agent, no location.
CREATE TABLE shared_device_events
(
    id          TEXT    NOT NULL
        CONSTRAINT shared_device_events_pk
            PRIMARY KEY,
    practice_id TEXT    NOT NULL,
    device_id   TEXT,
    user_id     TEXT,
    kind        TEXT    NOT NULL,
    ip          TEXT,
    created     INTEGER NOT NULL
) STRICT;

CREATE INDEX shared_device_events_practice_created
    ON shared_device_events (practice_id, created);

CREATE INDEX shared_device_events_created
    ON shared_device_events (created);

-- The registered device a session has been started from
ALTER TABLE sessions
    ADD shared_device_id TEXT;

CREATE INDEX sessions_shared_device_id
    ON sessions (shared_device_id);
