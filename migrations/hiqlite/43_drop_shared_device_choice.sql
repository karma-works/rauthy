-- The "shared computer" question is replaced by registered shared devices.
ALTER TABLE passkeys
    DROP COLUMN shared_device_choice;
