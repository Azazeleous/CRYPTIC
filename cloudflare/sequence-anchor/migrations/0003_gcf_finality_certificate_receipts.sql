CREATE TABLE IF NOT EXISTS used_finality_certificates (
  certificate_digest TEXT PRIMARY KEY CHECK(length(certificate_digest) = 64),
  network_id TEXT NOT NULL,
  sequence INTEGER NOT NULL CHECK(sequence > 0),
  accepted_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS used_finality_certificates_network_sequence
  ON used_finality_certificates(network_id, sequence);
