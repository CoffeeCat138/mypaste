-- 为 create_tokens.expires_at 添加索引以加速过期清理
CREATE INDEX IF NOT EXISTS idx_create_tokens_expires_at ON create_tokens (expires_at);