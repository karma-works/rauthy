ALTER TABLE fido_mds_metadata ADD blob_hash BLOB NOT NULL DEFAULT X'';
ALTER TABLE fido_mds_metadata ADD verified_until INTEGER NOT NULL DEFAULT 0;
