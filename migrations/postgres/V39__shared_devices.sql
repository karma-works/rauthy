-- Registered shared devices (practice PCs) and the PIN sign-in on them, see
-- `rauthy_data::entity::shared_devices`.
CREATE TABLE shared_device_practices
(
    id              VARCHAR NOT NULL
        CONSTRAINT shared_device_practices_pk
            PRIMARY KEY,
    name            VARCHAR NOT NULL,
    idle_timeout    BIGINT  NOT NULL,
    notify_user_ids VARCHAR NOT NULL,
    risk_ack_by     VARCHAR,
    risk_ack_at     BIGINT,
    created         BIGINT  NOT NULL,
    updated         BIGINT  NOT NULL
);

-- Only an HMAC of each PIN is stored, keyed with the encryption key `pin_key_id`.
CREATE TABLE shared_device_members
(
    practice_id VARCHAR NOT NULL
        CONSTRAINT shared_device_members_practices_id_fk
            REFERENCES shared_device_practices
            ON UPDATE CASCADE ON DELETE CASCADE,
    user_id     VARCHAR NOT NULL
        CONSTRAINT shared_device_members_users_id_fk
            REFERENCES users
            ON UPDATE CASCADE ON DELETE CASCADE,
    pin_hmac    BYTEA,
    pin_key_id  VARCHAR,
    pin_created BIGINT,
    created     BIGINT  NOT NULL,
    CONSTRAINT shared_device_members_pk
        PRIMARY KEY (practice_id, user_id)
);

CREATE UNIQUE INDEX shared_device_members_pin
    ON shared_device_members (practice_id, pin_hmac);

CREATE INDEX shared_device_members_user_id
    ON shared_device_members (user_id);

CREATE TABLE shared_devices
(
    id            VARCHAR NOT NULL
        CONSTRAINT shared_devices_pk
            PRIMARY KEY,
    practice_id   VARCHAR NOT NULL
        CONSTRAINT shared_devices_practices_id_fk
            REFERENCES shared_device_practices
            ON UPDATE CASCADE ON DELETE CASCADE,
    label         VARCHAR NOT NULL,
    token_hash    BYTEA   NOT NULL,
    public_key    BYTEA   NOT NULL,
    ip_registered VARCHAR NOT NULL,
    ip_lock       BOOLEAN NOT NULL,
    failed_pins   BIGINT  NOT NULL,
    locked_at     BIGINT,
    created_by    VARCHAR NOT NULL,
    created       BIGINT  NOT NULL,
    last_seen     BIGINT  NOT NULL,
    last_seen_ip  VARCHAR,
    ip_warned     BIGINT 
);

CREATE UNIQUE INDEX shared_devices_token_hash
    ON shared_devices (token_hash);

CREATE INDEX shared_devices_practice_id
    ON shared_devices (practice_id);

-- Security log per practice, kept 90 days. No User-Agent, no location.
CREATE TABLE shared_device_events
(
    id          VARCHAR NOT NULL
        CONSTRAINT shared_device_events_pk
            PRIMARY KEY,
    practice_id VARCHAR NOT NULL,
    device_id   VARCHAR,
    user_id     VARCHAR,
    kind        VARCHAR NOT NULL,
    ip          VARCHAR,
    created     BIGINT  NOT NULL
);

CREATE INDEX shared_device_events_practice_created
    ON shared_device_events (practice_id, created);

CREATE INDEX shared_device_events_created
    ON shared_device_events (created);

-- The registered device a session has been started from
ALTER TABLE sessions
    ADD shared_device_id VARCHAR;

CREATE INDEX sessions_shared_device_id
    ON sessions (shared_device_id);
