-- Public mode/device metadata only. The trusted-browser AES key is never sent.
ALTER TABLE vault_passkeys ADD COLUMN mode TEXT NOT NULL DEFAULT 'prf';
ALTER TABLE vault_passkeys ADD COLUMN device_id TEXT;
ALTER TABLE vault_passkeys ADD CONSTRAINT vault_passkeys_mode_device CHECK (
    (mode = 'prf' AND device_id IS NULL) OR
    (mode = 'trusted_browser' AND device_id IS NOT NULL AND
     device_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$')
);
