-- Richer WebAuthn credential public-key metadata (SEC-AN-006)

ALTER TABLE webauthn_credentials ADD COLUMN public_key_cose BLOB NOT NULL DEFAULT X'';
ALTER TABLE webauthn_credentials ADD COLUMN public_key_alg INTEGER NOT NULL DEFAULT 0;
ALTER TABLE webauthn_credentials ADD COLUMN aaguid BLOB NOT NULL DEFAULT X'';
ALTER TABLE webauthn_credentials ADD COLUMN transports_json TEXT NOT NULL DEFAULT '[]';
ALTER TABLE webauthn_credentials ADD COLUMN attestation_format TEXT NOT NULL DEFAULT '';
ALTER TABLE webauthn_credentials ADD COLUMN nickname TEXT NOT NULL DEFAULT '';
