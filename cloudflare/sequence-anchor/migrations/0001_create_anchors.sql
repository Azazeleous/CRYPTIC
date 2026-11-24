CREATE TABLE IF NOT EXISTS anchors (
  network_id TEXT PRIMARY KEY NOT NULL,
  sequence INTEGER NOT NULL CHECK(sequence >= 1),
  policy_hash TEXT NOT NULL CHECK(length(policy_hash) = 64),
  updated_at INTEGER NOT NULL
);
