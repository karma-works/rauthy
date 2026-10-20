-- How a passkey was added (`internal`, `hybrid`, `security_key`) and the answer to the
-- "shared computer" question (`yes`, `no`, `unknown`). Both are only set for new passkeys.
ALTER TABLE passkeys
    ADD kind TEXT;
ALTER TABLE passkeys
    ADD shared_device_choice TEXT;
