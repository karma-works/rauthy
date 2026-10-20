-- One-time recovery codes for passkey accounts. Only an HMAC of each code is stored, keyed with
-- the encryption key `key_id`.
CREATE TABLE recovery_codes
(
    user_id VARCHAR NOT NULL
        CONSTRAINT recovery_codes_users_id_fk
            REFERENCES users
            ON UPDATE CASCADE ON DELETE CASCADE,
    hmac    BYTEA   NOT NULL,
    key_id  VARCHAR NOT NULL,
    created BIGINT  NOT NULL,
    used    BIGINT,
    CONSTRAINT recovery_codes_pk
        PRIMARY KEY (user_id, hmac)
);
