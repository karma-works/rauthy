ALTER TABLE fido_mds_metadata ADD blob_hash BYTEA NOT NULL DEFAULT '\x';
ALTER TABLE fido_mds_metadata ADD verified_until BIGINT NOT NULL DEFAULT 0;
