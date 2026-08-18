-- 云剪贴板初始表结构
CREATE TABLE clipboards (
  name TEXT PRIMARY KEY,
  content TEXT NOT NULL,
  password_hash TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  expires_in_days INTEGER NOT NULL DEFAULT 0,
  expires_at INTEGER,
  enable_markdown INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX idx_expires_at ON clipboards(expires_at);

CREATE TABLE create_tokens (
  token TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
