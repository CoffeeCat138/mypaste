-- D1 限速表：跨 Isolate 持久化限速计数器，配合 cleanupExpiredData 定时清理
CREATE TABLE IF NOT EXISTS rate_limits (
  key TEXT NOT NULL,          -- 限速键（如 "verify-create:127.0.0.1"）
  window_start INTEGER NOT NULL, -- 窗口起始时间戳（毫秒）
  count INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (key, window_start)
);