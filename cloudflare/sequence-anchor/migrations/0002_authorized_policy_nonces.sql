CREATE TABLE IF NOT EXISTS used_authorization_nonces (
  signer_id TEXT NOT NULL,
  nonce TEXT NOT NULL CHECK(length(nonce) = 32),
  network_id TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  PRIMARY KEY (signer_id, nonce)
);
CREATE INDEX IF NOT EXISTS used_authorization_nonces_expiry
  ON used_authorization_nonces(expires_at);
