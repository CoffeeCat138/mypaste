// ==================== 云剪贴板（Cloudflare Workers + D1）====================
//
// 同源部署的单文件 Worker：前端页面 + REST API + 定时清理。
// 详见 README.md

// ---------- 常量 ----------
const MAX_CONTENT_LENGTH = 100 * 1024;   // 单条内容上限（100KB）
const MAX_NAME_LENGTH = 64;              // 剪贴板名称最大长度
const VALID_EXPIRY_DAYS = [0, 1, 3, 7, 14, 30];
const DEFAULT_EXPIRY_DAYS = 3;
const CREATE_TOKEN_COOKIE = 'create_token';
const CREATE_TOKEN_TTL_MS = 10 * 60 * 1000; // 创建令牌有效期 10 分钟
const PBKDF2_DEFAULT_ITERATIONS = 10000;
const PROJECT_NAME = 'mypaste';
const PROJECT_URL = 'https://github.com/CoffeeCat138/mypaste';
const RATE_LIMITS = {
  globalPassword: { limit: 10, windowMs: 10 * 60 * 1000 },   // 全局密码试错：10 次失败 / 10 分钟
  passwordAttempt: { limit: 10, windowMs: 10 * 60 * 1000 },  // 剪贴板密码试错：10 次失败 / 10 分钟
  createClipboard: { limit: 20, windowMs: 10 * 60 * 1000 },  // 创建剪贴板频率：20 次 / 10 分钟
};
const CLIPBOARD_COLUMNS =
  'name, content, password_hash, created_at, updated_at, expires_in_days, expires_at, enable_markdown';

// ---------- 阿里云内容安全审核配置（开关、密钥与参数在 Workers 环境变量 / Secrets 中配置）----------
const ALIYUN_MODERATION_API_VERSION = '2022-03-02';
const DEFAULT_ALIYUN_MODERATION_ENDPOINT = 'green-cip.cn-shanghai.aliyuncs.com';
const DEFAULT_ALIYUN_MODERATION_SERVICE = 'ugc_moderation_byllm';
const DEFAULT_ALIYUN_MODERATION_ACTION = 'TextModerationPlus';
const ALIYUN_MODERATION_DEFAULT_CHUNK_SIZE = 600; // 普通文本审核服务单次上限 600 字
const ALIYUN_MODERATION_LLM_CHUNK_SIZE = 2000;    // ugc_moderation_byllm 系列单次上限 2000 字
const ALIYUN_MODERATION_TIMEOUT_MS = 10000;

// 常见风险标签的中文说明映射（未命中时回退显示原始标签）
const ALIYUN_LABEL_MAP = {
  sexual_content: '色情低俗内容',
  porn: '色情内容',
  ad: '垃圾广告',
  ad_compliance: '广告法违规',
  political_content: '涉政敏感内容',
  violent_content: '暴恐违禁内容',
  violence: '暴力内容',
  contraband: '违禁品信息',
  profanity: '辱骂/低俗用语',
  abuse: '辱骂内容',
  fraud: '诈骗信息',
  spam: '垃圾灌水',
  minor_safety: '未成年人保护相关风险',
  religion: '宗教敏感内容',
  customized: '命中自定义敏感词库',
  unmarked_url: '风险链接'
};

// ---------- 内存限速（按 IP，Worker isolate 级别）----------
const rateLimitStore = new Map();

// 仅检查是否已达限速阈值（不递增计数），用于密码校验前快速拦截
function isRateLimitBlocked(ip, key, { limit }) {
  const now = Date.now();
  const bucketKey = ip + '|' + key;
  const bucket = rateLimitStore.get(bucketKey);
  if (!bucket || bucket.resetAt <= now) {
    if (bucket) rateLimitStore.delete(bucketKey);
    return false;
  }
  return bucket.count >= limit;
}

// 递增计数并返回是否超过 limit（适用于频率限速或记录密码失败）
function recordRateLimitHit(ip, key, { limit, windowMs }) {
  const now = Date.now();
  const bucketKey = ip + '|' + key;
  let bucket = rateLimitStore.get(bucketKey);
  if (!bucket || bucket.resetAt <= now) {
    bucket = { count: 0, resetAt: now + windowMs };
    rateLimitStore.set(bucketKey, bucket);
  }
  bucket.count += 1;
  if (rateLimitStore.size > 5000) pruneRateLimitStore(now);
  return bucket.count > limit;
}

// 密码验证成功后清除失败记录，避免正常用户累计触发限速
function clearRateLimit(ip, key) {
  rateLimitStore.delete(ip + '|' + key);
}

function pruneRateLimitStore(now = Date.now()) {
  for (const [key, bucket] of rateLimitStore) {
    if (bucket.resetAt <= now) rateLimitStore.delete(key);
  }
}

function getClientIp(request) {
  return request.headers.get('CF-Connecting-IP') || 'unknown';
}

// 仅用于自动化测试
export function _resetRateLimitsForTest() {
  rateLimitStore.clear();
}

// ---------- Cookie 工具（创建令牌通过 HttpOnly Cookie 传递，不出现在 URL 中）----------
function parseCookies(header) {
  const cookies = {};
  if (!header) return cookies;
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    const key = part.slice(0, eq).trim();
    const value = part.slice(eq + 1).trim();
    if (key) cookies[key] = value;
  }
  return cookies;
}

function getCookie(request, name) {
  return parseCookies(request.headers.get('Cookie') || '')[name] || '';
}

function buildCreateTokenCookie(token, maxAgeSeconds, secure) {
  return `${CREATE_TOKEN_COOKIE}=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAgeSeconds}${secure ? '; Secure' : ''}`;
}

function clearCreateTokenCookie(secure) {
  return `${CREATE_TOKEN_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${secure ? '; Secure' : ''}`;
}

// ---------- 密码哈希（PBKDF2 + 随机盐）----------
// 存储格式：<盐hex>:<迭代次数>:<哈希hex>
function getPbkdf2Iterations(env) {
  const parsed = parseInt(env.PBKDF2_ITERATIONS, 10);
  if (Number.isInteger(parsed) && parsed >= 1000 && parsed <= 1000000) return parsed;
  return PBKDF2_DEFAULT_ITERATIONS;
}

async function pbkdf2(password, salt, iterations) {
  const keyMaterial = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    keyMaterial,
    256
  );
  return toHex(new Uint8Array(bits));
}

async function hashPassword(password, env) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iterations = getPbkdf2Iterations(env);
  const hash = await pbkdf2(password, salt, iterations);
  return `${toHex(salt)}:${iterations}:${hash}`;
}

async function verifyPassword(password, stored) {
  if (typeof stored !== 'string') return false;
  const parts = stored.split(':');
  if (parts.length !== 3) return false;
  const [saltHex, iterationsStr, hashHex] = parts;
  const salt = fromHex(saltHex);
  const iterations = parseInt(iterationsStr, 10);
  if (!salt || !Number.isInteger(iterations) || iterations < 1000 || iterations > 1000000 || !hashHex) {
    return false;
  }
  const hash = await pbkdf2(password, salt, iterations);
  return timingSafeEqual(hash, hashHex);
}

function toHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function fromHex(hex) {
  if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) return null;
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

// 恒定时间比较，避免时序侧信道
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

// ---------- 校验与解析工具 ----------
function isValidClipboardName(name) {
  if (typeof name !== 'string') return false;
  if (name.length === 0 || name.length > MAX_NAME_LENGTH) return false;
  if (name !== name.trim()) return false;
  // 禁止空白、斜杠、反斜杠、URI 保留字符和控制字符
  // （含 / ? # % & + 的名称会导致创建后无法通过浏览器 URL 正常打开或引发歧义）
  if (/[/\\?#%&+\s\u0000-\u001f\u007f]/.test(name)) return false;
  return true;
}

function getValidExpiration(days) {
  if (days === undefined || days === null) {
    return DEFAULT_EXPIRY_DAYS; // 字段缺失：使用默认 3 天
  }
  if (typeof days === 'number' && Number.isInteger(days) && VALID_EXPIRY_DAYS.includes(days)) {
    return days;
  }
  return null; // 显式传入非法值：交给调用方报错，而不是静默回退
}

function daysToMillis(days) {
  return days * 24 * 60 * 60 * 1000;
}

function parseAllowedPasswords(str) {
  if (!str || typeof str !== 'string') return [];
  try {
    const arr = JSON.parse(str);
    if (Array.isArray(arr)) {
      return arr
        .filter(item => typeof item === 'string' && item.trim() !== '')
        .map(item => item.trim());
    }
  } catch (e) {}
  return [];
}

function escapeHtml(str) {
  return str.replace(/[&<>"']/g, function (m) {
    const map = {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#039;'
    };
    return map[m];
  });
}

// 嵌入 <script> 时对 <、U+2028、U+2029 显式转义，避免 </script> 逃逸
function safeJsonStringify(value) {
  return JSON.stringify(value)
    .replace(/</g, '\\u003c')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');
}

// ---------- 响应工具 ----------
function jsonResponse(obj, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      ...extraHeaders
    }
  });
}

function htmlResponse(html, status = 200) {
  return new Response(html, {
    status,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'strict-origin-when-cross-origin'
    }
  });
}

// ---------- 数据访问 ----------
// 查询剪贴板；不存在或已过期（惰性删除后）返回 null
async function getExistingClipboard(env, name) {
  const row = await env.DB.prepare(
    `SELECT ${CLIPBOARD_COLUMNS} FROM clipboards WHERE name = ?`
  ).bind(name).first();
  if (!row) return null;
  if (row.expires_at !== null && row.expires_at <= Date.now()) {
    await env.DB.prepare('DELETE FROM clipboards WHERE name = ?').bind(name).run();
    return null;
  }
  return row;
}

// 创建令牌必须存在、未过期且绑定同一名称
async function isValidCreateToken(env, token, name) {
  if (!token) return false;
  const row = await env.DB.prepare(
    'SELECT name, expires_at FROM create_tokens WHERE token = ?'
  ).bind(token).first();
  return !!(row && row.expires_at > Date.now() && row.name === name);
}

// ---------- Worker 入口 ----------
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    const createVerificationEnabled = env.CREATE_PASSWORD === 'true';
    // 是否启用单条剪贴板访问密码：默认启用；在 Workers 环境变量中设 ENABLE_ACCESS_PASSWORD=false 可关闭
    const accessPasswordEnabled = env.ENABLE_ACCESS_PASSWORD !== 'false';
    const allowedCreatePasswords = parseAllowedPasswords(env.ALLOWED_PASSWORDS);

    // 处理 API 请求
    if (path.startsWith('/api/')) {
      return handleApiRequest(request, env, createVerificationEnabled, allowedCreatePasswords, accessPasswordEnabled);
    }

    // 已知静态路径直接 404，避免无效的 D1 查询
    if (path === '/favicon.ico' || path === '/robots.txt') {
      return new Response('Not Found', { status: 404 });
    }

    // 首页
    if (path === '/') {
      return htmlResponse(getHomePage());
    }

    // 剪贴板页面
    let name;
    try {
      name = decodeURIComponent(path.slice(1));
    } catch (e) {
      return new Response('Bad Request', { status: 400 });
    }
    if (name.includes('/')) {
      return new Response('Not Found', { status: 404 });
    }

    const row = await getExistingClipboard(env, name);

    if (!row) {
      if (!isValidClipboardName(name)) {
        return htmlResponse(getInvalidNamePage(name), 400);
      }
      // 剪贴板不存在（或已过期）：进入创建流程
      const token = getCookie(request, CREATE_TOKEN_COOKIE);
      const tokenValid = createVerificationEnabled && (await isValidCreateToken(env, token, name));
      if (createVerificationEnabled && !tokenValid) {
        return htmlResponse(getVerifyPage(name));
      }
      return htmlResponse(getCreatePage(name, accessPasswordEnabled));
    }

    const meta = {
      name,
      hasPassword: !!row.password_hash,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      expiresInDays: row.expires_in_days,
      enableMarkdown: row.enable_markdown === 1,
      createVerificationEnabled,
      accessPasswordEnabled,
      // 无密码剪贴板：内容直接内联进页面，省去一次 API 往返；有密码则必须验证后获取
      inlineContent: row.password_hash ? null : row.content
    };
    return htmlResponse(getOpenPage(meta));
  },

  async scheduled(event, env) {
    pruneRateLimitStore();
    await cleanupExpiredData(env);
  }
};

// ---------- API 处理 ----------
async function handleApiRequest(request, env, createVerificationEnabled, allowedCreatePasswords, accessPasswordEnabled) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  if (method !== 'POST') {
    return jsonResponse({ error: '请求方法不允许' }, 405);
  }

  // CSRF 防护：浏览器跨站 POST 必然携带 Origin，与本站不一致时直接拒绝
  const origin = request.headers.get('Origin');
  if (origin) {
    let originHost = null;
    try {
      originHost = new URL(origin).hostname;
    } catch (e) {}
    if (!originHost || originHost !== url.hostname) {
      return jsonResponse({ error: '请求来源不允许' }, 403);
    }
  }

  let body;
  try {
    body = await request.json();
  } catch (e) {
    return jsonResponse({ error: '无效的 JSON 格式' }, 400);
  }
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return jsonResponse({ error: '无效的 JSON 格式' }, 400);
  }

  switch (path) {
    case '/api/verify-create':
      return verifyCreatePassword(body, request, env, createVerificationEnabled, allowedCreatePasswords);
    case '/api/create':
      return createClipboard(body, request, env, createVerificationEnabled, accessPasswordEnabled);
    case '/api/get':
      return getClipboardContent(body, request, env);
    case '/api/update':
      return updateClipboard(body, request, env, createVerificationEnabled, allowedCreatePasswords, accessPasswordEnabled);
    case '/api/delete':
      return deleteClipboard(body, request, env, createVerificationEnabled, allowedCreatePasswords);
    default:
      return jsonResponse({ error: '接口不存在' }, 404);
  }
}

// ---------- 认证辅助 ----------
// 校验全局创建密码（仅在失败时计数，成功时清零）；返回 'ok' | 'wrong_password' | 'rate_limited'
function checkGlobalPassword(request, password, allowedCreatePasswords) {
  const ip = getClientIp(request);
  if (isRateLimitBlocked(ip, 'global-pwd', RATE_LIMITS.globalPassword)) {
    return 'rate_limited';
  }
  if (!allowedCreatePasswords.some((allowed) => timingSafeEqual(password, allowed))) {
    recordRateLimitHit(ip, 'global-pwd', RATE_LIMITS.globalPassword);
    return 'wrong_password';
  }
  clearRateLimit(ip, 'global-pwd');
  return 'ok';
}

// 校验剪贴板访问密码（仅在失败时计数，成功时清零）；返回 'ok' | 'need_password' | 'wrong_password' | 'rate_limited'
async function checkClipboardPassword(request, row, password, name) {
  if (!row.password_hash) return 'ok';
  if (typeof password !== 'string' || !password) return 'need_password';
  const ip = getClientIp(request);
  const key = 'pwd:' + name;
  if (isRateLimitBlocked(ip, key, RATE_LIMITS.passwordAttempt)) {
    return 'rate_limited';
  }
  if (!(await verifyPassword(password, row.password_hash))) {
    recordRateLimitHit(ip, key, RATE_LIMITS.passwordAttempt);
    return 'wrong_password';
  }
  clearRateLimit(ip, key);
  return 'ok';
}

// ---------- 阿里云内容安全审核（Green 2022-03-02，ACS3-HMAC-SHA256）----------
// Workers 环境变量 / Secrets：
// - ALIYUN_MODERATION_ENABLED：设为 "true" 启用审核（默认关闭）
// - ALIYUN_ACCESS_KEY_ID：阿里云 AccessKey ID（建议配为 Secret）
// - ALIYUN_ACCESS_KEY_SECRET：阿里云 AccessKey Secret（建议配为 Secret）
// - ALIYUN_MODERATION_ENDPOINT：接入地址（默认 green-cip.cn-shanghai.aliyuncs.com）
// - ALIYUN_MODERATION_SERVICE：审核服务代码（默认 ugc_moderation_byllm，如 ugc_moderation_byllm_pro / comment_detection_pro 等）
// - ALIYUN_MODERATION_ACTION：接口名（默认 TextModerationPlus，兼容 TextModeration）
// - ALIYUN_MODERATION_FAIL_OPEN：设为 "true" 时审核服务异常放行，默认 "false"（失败拦截）
function getAliyunModerationConfig(env) {
  const enabled = env.ALIYUN_MODERATION_ENABLED === 'true';
  const accessKeyId = typeof env.ALIYUN_ACCESS_KEY_ID === 'string' ? env.ALIYUN_ACCESS_KEY_ID.trim() : '';
  const accessKeySecret = typeof env.ALIYUN_ACCESS_KEY_SECRET === 'string' ? env.ALIYUN_ACCESS_KEY_SECRET.trim() : '';

  let endpoint = (typeof env.ALIYUN_MODERATION_ENDPOINT === 'string' && env.ALIYUN_MODERATION_ENDPOINT.trim())
    ? env.ALIYUN_MODERATION_ENDPOINT.trim()
    : DEFAULT_ALIYUN_MODERATION_ENDPOINT;
  // 容错：去掉可能误填的协议头和尾部斜杠
  endpoint = endpoint.replace(/^https?:\/\//i, '').replace(/\/+$/, '');

  const service = (typeof env.ALIYUN_MODERATION_SERVICE === 'string' && env.ALIYUN_MODERATION_SERVICE.trim())
    ? env.ALIYUN_MODERATION_SERVICE.trim()
    : DEFAULT_ALIYUN_MODERATION_SERVICE;

  const action = (typeof env.ALIYUN_MODERATION_ACTION === 'string' && env.ALIYUN_MODERATION_ACTION.trim())
    ? env.ALIYUN_MODERATION_ACTION.trim()
    : DEFAULT_ALIYUN_MODERATION_ACTION;

  const failOpen = env.ALIYUN_MODERATION_FAIL_OPEN === 'true';

  return { enabled, accessKeyId, accessKeySecret, endpoint, service, action, failOpen };
}

async function sha256Hex(text) {
  const data = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return toHex(new Uint8Array(digest));
}

async function hmacSha256Hex(secret, message) {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message));
  return toHex(new Uint8Array(sig));
}

function formatAliyunReason(labelsStr, reasonRaw) {
  // 优先解析阿里云 reason JSON 中的 riskTips
  if (typeof reasonRaw === 'string' && reasonRaw.trim()) {
    try {
      const parsed = JSON.parse(reasonRaw);
      if (parsed && typeof parsed.riskTips === 'string' && parsed.riskTips.trim()) {
        return parsed.riskTips.trim();
      }
    } catch (e) {}
  }

  // 回退使用标签中文映射
  const labels = String(labelsStr || '')
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s && s.toLowerCase() !== 'none' && s.toLowerCase() !== 'nonlabel');
  if (labels.length === 0) return '';
  return labels.map((l) => ALIYUN_LABEL_MAP[l] || l).join('、');
}

function parseAliyunModerationResponse(json) {
  if (!json || typeof json !== 'object') return null;
  const code = json.Code ?? json.code;
  if (code !== 200) return null;

  const data = json.Data ?? json.data;
  if (!data || typeof data !== 'object') return { safe: true, reason: '' };

  // 1) TextModeration 通用返回格式：{ labels, reason } 或 { Labels, Reason }
  const labels = data.labels ?? data.Labels;
  const reason = data.reason ?? data.Reason;
  if (typeof labels === 'string') {
    const cleaned = labels.trim();
    if (!cleaned || cleaned.toLowerCase() === 'none' || cleaned.toLowerCase() === 'nonlabel') {
      return { safe: true, reason: '' };
    }
    return { safe: false, reason: formatAliyunReason(cleaned, reason) };
  }

  // 2) TextModerationPlus 返回格式：{ RiskLevel, Result: [{ Label, Description, ... }] }
  const riskLevel = data.RiskLevel ?? data.riskLevel;
  const results = data.Result ?? data.result;
  if (typeof riskLevel === 'string') {
    if (riskLevel.toLowerCase() === 'none') {
      return { safe: true, reason: '' };
    }
    let detail = '';
    if (Array.isArray(results)) {
      const items = results
        .map((r) => ({
          label: r && (r.Label ?? r.label),
          description: r && (r.Description ?? r.description)
        }))
        .filter((r) => r.label && String(r.label).toLowerCase() !== 'nonlabel')
        .map((r) => r.description || ALIYUN_LABEL_MAP[r.label] || r.label);
      detail = items.join('、');
    }
    return { safe: false, reason: detail || `风险等级：${riskLevel}` };
  }

  // 无 labels 且无 riskLevel 时默认安全
  return { safe: true, reason: '' };
}

async function callAliyunTextModeration(config, chunk) {
  const serviceParameters = JSON.stringify({ content: chunk });
  const bodyParams = new URLSearchParams();
  bodyParams.set('Service', config.service);
  bodyParams.set('ServiceParameters', serviceParameters);
  const body = bodyParams.toString();

  const contentSha256 = await sha256Hex(body);
  const xAcsDate = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
  const nonce = crypto.randomUUID().replace(/-/g, '');
  const contentType = 'application/x-www-form-urlencoded';

  // 按小写 Header 名升序拼接 CanonicalHeaders 与 SignedHeaders（ACS3-HMAC-SHA256 规范）
  const headerEntries = [
    ['content-type', contentType],
    ['host', config.endpoint],
    ['x-acs-action', config.action],
    ['x-acs-content-sha256', contentSha256],
    ['x-acs-date', xAcsDate],
    ['x-acs-signature-nonce', nonce],
    ['x-acs-version', ALIYUN_MODERATION_API_VERSION]
  ];

  const canonicalHeaders = headerEntries.map(([k, v]) => `${k}:${v}\n`).join('');
  const signedHeaders = headerEntries.map(([k]) => k).join(';');
  const canonicalRequest = [
    'POST',
    '/',
    '',
    canonicalHeaders,
    signedHeaders,
    contentSha256
  ].join('\n');

  const hashedCanonicalRequest = await sha256Hex(canonicalRequest);
  const stringToSign = `ACS3-HMAC-SHA256\n${hashedCanonicalRequest}`;
  const signature = await hmacSha256Hex(config.accessKeySecret, stringToSign);
  const authorization =
    `ACS3-HMAC-SHA256 Credential=${config.accessKeyId},SignedHeaders=${signedHeaders},Signature=${signature}`;

  const res = await fetch(`https://${config.endpoint}/`, {
    method: 'POST',
    headers: {
      'Content-Type': contentType,
      'x-acs-action': config.action,
      'x-acs-version': ALIYUN_MODERATION_API_VERSION,
      'x-acs-date': xAcsDate,
      'x-acs-signature-nonce': nonce,
      'x-acs-content-sha256': contentSha256,
      'Authorization': authorization
    },
    body,
    signal: AbortSignal.timeout(ALIYUN_MODERATION_TIMEOUT_MS)
  });

  const text = await res.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (e) {}

  if (!res.ok) {
    throw new Error(`Aliyun HTTP ${res.status}: ${text.slice(0, 300)}`);
  }
  return json;
}

async function moderateClipboardContent(env, name, content) {
  const config = getAliyunModerationConfig(env);
  if (!config.enabled) {
    return { ok: true };
  }
  if (!config.accessKeyId || !config.accessKeySecret) {
    console.error('Aliyun moderation enabled, but AccessKey credentials are missing');
    if (config.failOpen) return { ok: true };
    return { ok: false, status: 503, error: '内容安全审查未正确配置，请联系管理员' };
  }

  // ugc_moderation_byllm 系列支持单次 2000 字，其余服务默认按 600 字分段审查
  const chunkSize = config.service.startsWith('ugc_moderation_byllm')
    ? ALIYUN_MODERATION_LLM_CHUNK_SIZE
    : ALIYUN_MODERATION_DEFAULT_CHUNK_SIZE;
  const fullText = `${name}\n${content}`;
  const chunks = [];
  for (let i = 0; i < fullText.length; i += chunkSize) {
    chunks.push(fullText.slice(i, i + chunkSize));
  }

  try {
    for (let i = 0; i < chunks.length; i++) {
      const json = await callAliyunTextModeration(config, chunks[i]);
      const parsed = parseAliyunModerationResponse(json);
      if (!parsed) {
        console.error('Unexpected Aliyun moderation response:', JSON.stringify(json));
        if (config.failOpen) return { ok: true };
        return { ok: false, status: 503, error: '内容安全审查服务响应异常，请稍后再试' };
      }
      if (!parsed.safe) {
        const detail = parsed.reason ? `（${parsed.reason}）` : '';
        return { ok: false, status: 422, error: `内容未通过安全审查${detail}` };
      }
    }
    return { ok: true };
  } catch (err) {
    console.error('Aliyun moderation failed:', err);
    if (config.failOpen) return { ok: true };
    return { ok: false, status: 503, error: '内容安全审查服务暂时不可用，请稍后再试' };
  }
}

// ---------- 核心操作 ----------
// 统一全局密码验证接口：
// - 传入 name：校验密码并签发创建令牌（用于创建剪贴板流程）
// - 不传 name：仅校验全局密码（用于编辑/删除前验证）
async function verifyCreatePassword(body, request, env, createVerificationEnabled, allowedCreatePasswords) {
  const { name, password } = body;
  if (!createVerificationEnabled) {
    return jsonResponse({ error: '未启用创建验证' }, 400);
  }
  const needToken = name !== undefined && name !== null && name !== '';
  if (needToken && !isValidClipboardName(name)) {
    return jsonResponse({ error: '剪贴板名称无效' }, 400);
  }
  if (typeof password !== 'string' || !password) {
    return jsonResponse({ error: '请输入密码' }, 400);
  }
  if (allowedCreatePasswords.length === 0) {
    return jsonResponse({ error: '验证配置错误，请联系管理员' }, 500);
  }

  const auth = checkGlobalPassword(request, password, allowedCreatePasswords);
  if (auth === 'rate_limited') {
    return jsonResponse({ error: '尝试次数过多，请稍后再试' }, 429);
  }
  if (auth === 'wrong_password') {
    return jsonResponse({ error: needToken ? '密码错误' : '全局创建密码错误' }, 403);
  }

  if (!needToken) {
    return jsonResponse({ success: true });
  }

  const token = crypto.randomUUID();
  const now = Date.now();
  const expiresAt = now + CREATE_TOKEN_TTL_MS;
  await env.DB.prepare(
    'INSERT INTO create_tokens (token, name, created_at, expires_at) VALUES (?, ?, ?, ?)'
  ).bind(token, name, now, expiresAt).run();

  const secure = new URL(request.url).protocol === 'https:';
  return jsonResponse(
    { success: true },
    200,
    { 'Set-Cookie': buildCreateTokenCookie(token, CREATE_TOKEN_TTL_MS / 1000, secure) }
  );
}
async function createClipboard(body, request, env, createVerificationEnabled, accessPasswordEnabled) {
  const { name, content, password, expiresInDays, enableMarkdown } = body;

  if (!isValidClipboardName(name)) {
    return jsonResponse({ error: '剪贴板名称无效（1-64 个字符，不能包含空格、斜杠或特殊符号 ?#%&+）' }, 400);
  }
  if (typeof content !== 'string' || content.trim() === '') {
    return jsonResponse({ error: '内容不能为空' }, 400);
  }
  if (content.length > MAX_CONTENT_LENGTH) {
    return jsonResponse({ error: '内容过长，最多 100KB' }, 413);
  }
  if (password !== undefined && password !== null && typeof password !== 'string') {
    return jsonResponse({ error: '参数格式错误' }, 400);
  }

  const days = getValidExpiration(expiresInDays);
  if (days === null) {
    return jsonResponse({ error: '无效的过期天数' }, 400);
  }

  // 创建频率限速：防止短时间内批量刷库
  if (recordRateLimitHit(getClientIp(request), 'create-clipboard', RATE_LIMITS.createClipboard)) {
    return jsonResponse({ error: '创建过于频繁，请稍后再试' }, 429);
  }

  let createToken = '';
  if (createVerificationEnabled) {
    createToken = getCookie(request, CREATE_TOKEN_COOKIE);
    if (!createToken) {
      return jsonResponse({ error: '缺少创建令牌' }, 401);
    }
    if (!(await isValidCreateToken(env, createToken, name))) {
      return jsonResponse({ error: '创建令牌无效或已过期' }, 401);
    }
  }

  // 阿里云内容安全审查（在鉴权和基础校验通过后执行，避免无效请求消耗额度）
  const moderation = await moderateClipboardContent(env, name, content);
  if (!moderation.ok) {
    return jsonResponse({ error: moderation.error }, moderation.status);
  }

  // 关闭访问密码功能时忽略密码字段，防止绕过前端设置密码
  const hasPassword = accessPasswordEnabled && typeof password === 'string' && password.trim() !== '';
  let passwordHash = null;
  if (hasPassword) {
    passwordHash = await hashPassword(password, env);
  }

  const now = Date.now();
  const expiresAt = days > 0 ? now + daysToMillis(days) : null;
  const markdownEnabled = enableMarkdown === false ? 0 : 1;

  try {
    await env.DB.prepare(
      'INSERT INTO clipboards (name, content, password_hash, created_at, updated_at, expires_in_days, expires_at, enable_markdown) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
    ).bind(name, content, passwordHash, now, now, days, expiresAt, markdownEnabled).run();
  } catch (err) {
    if (err.message && err.message.includes('UNIQUE constraint failed')) {
      return jsonResponse({ error: '剪贴板已存在，请直接打开' }, 409);
    }
    return jsonResponse({ error: '数据库错误' }, 500);
  }

  // 创建成功后才消费令牌，避免名称冲突/数据库错误导致令牌白白作废
  const secure = new URL(request.url).protocol === 'https:';
  if (createVerificationEnabled && createToken) {
    await env.DB.prepare('DELETE FROM create_tokens WHERE token = ?').bind(createToken).run();
    return jsonResponse(
      { success: true, expiresInDays: days, enableMarkdown: markdownEnabled === 1 },
      200,
      { 'Set-Cookie': clearCreateTokenCookie(secure) }
    );
  }

  return jsonResponse({ success: true, expiresInDays: days, enableMarkdown: markdownEnabled === 1 });
}

async function getClipboardContent(body, request, env) {
  const { name, password } = body;
  if (!name) return jsonResponse({ error: '缺少剪贴板名称' }, 400);

  const row = await getExistingClipboard(env, name);
  if (!row) return jsonResponse({ error: '剪贴板不存在或已过期' }, 404);

  const auth = await checkClipboardPassword(request, row, password, name);
  if (auth === 'need_password') return jsonResponse({ error: '需要密码' }, 401);
  if (auth === 'wrong_password') return jsonResponse({ error: '密码错误' }, 403);
  if (auth === 'rate_limited') return jsonResponse({ error: '尝试次数过多，请稍后再试' }, 429);

  return jsonResponse({
    content: row.content,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    expiresInDays: row.expires_in_days,
    hasPassword: !!row.password_hash,
    enableMarkdown: row.enable_markdown === 1
  });
}

async function updateClipboard(body, request, env, createVerificationEnabled, allowedCreatePasswords, accessPasswordEnabled) {
  const { name, content, password, createPassword, expiresInDays, newPassword } = body;
  if (!name || typeof content !== 'string') {
    return jsonResponse({ error: '参数不完整' }, 400);
  }
  if (content.trim() === '') {
    return jsonResponse({ error: '内容不能为空' }, 400);
  }
  if (content.length > MAX_CONTENT_LENGTH) {
    return jsonResponse({ error: '内容过长，最多 100KB' }, 413);
  }

  const row = await getExistingClipboard(env, name);
  if (!row) return jsonResponse({ error: '剪贴板不存在或已过期' }, 404);

  // 如果启用了全局创建密码，编辑前必须验证（复用同一失败限速桶）
  if (createVerificationEnabled) {
    if (!createPassword || typeof createPassword !== 'string') {
      return jsonResponse({ error: '需要全局创建密码' }, 401);
    }
    const globalAuth = checkGlobalPassword(request, createPassword, allowedCreatePasswords);
    if (globalAuth === 'rate_limited') {
      return jsonResponse({ error: '尝试次数过多，请稍后再试' }, 429);
    }
    if (globalAuth === 'wrong_password') {
      return jsonResponse({ error: '全局创建密码错误' }, 403);
    }
  }

  const auth = await checkClipboardPassword(request, row, password, name);
  if (auth === 'need_password') return jsonResponse({ error: '需要密码' }, 401);
  if (auth === 'wrong_password') return jsonResponse({ error: '密码错误' }, 403);
  if (auth === 'rate_limited') return jsonResponse({ error: '尝试次数过多，请稍后再试' }, 429);

  // 处理过期时间变更
  let newDays = null;
  let newExpiresAt = null;
  if (expiresInDays !== undefined) {
    newDays = getValidExpiration(expiresInDays);
    if (newDays === null) {
      return jsonResponse({ error: '无效的过期天数' }, 400);
    }
    newExpiresAt = newDays > 0 ? Date.now() + daysToMillis(newDays) : null;
  }

  // 阿里云内容安全审查
  const moderation = await moderateClipboardContent(env, name, content);
  if (!moderation.ok) {
    return jsonResponse({ error: moderation.error }, moderation.status);
  }

  // 处理访问密码变更：仅在启用访问密码功能时生效，空字符串表示清除密码
  let newPasswordHash = undefined; // undefined = 不修改；null = 清除密码
  if (accessPasswordEnabled && newPassword !== undefined) {
    if (typeof newPassword !== 'string') {
      return jsonResponse({ error: '参数格式错误' }, 400);
    }
    if (newPassword.trim() !== '') {
      newPasswordHash = await hashPassword(newPassword, env);
    } else {
      newPasswordHash = null;
    }
  }

  const now = Date.now();
  // 构建动态 SQL
  const sets = ['content = ?', 'updated_at = ?'];
  const params = [content, now];
  if (newDays !== null) {
    sets.push('expires_in_days = ?');
    params.push(newDays);
    sets.push('expires_at = ?');
    params.push(newExpiresAt);
  }
  if (newPasswordHash !== undefined) {
    sets.push('password_hash = ?');
    params.push(newPasswordHash);
  }
  params.push(name);

  await env.DB.prepare(
    `UPDATE clipboards SET ${sets.join(', ')} WHERE name = ?`
  ).bind(...params).run();

  return jsonResponse({ success: true });
}

async function deleteClipboard(body, request, env, createVerificationEnabled, allowedCreatePasswords) {
  const { name, password, createPassword } = body;
  if (!name) return jsonResponse({ error: '缺少剪贴板名称' }, 400);

  const row = await getExistingClipboard(env, name);
  if (!row) return jsonResponse({ error: '剪贴板不存在或已过期' }, 404);

  // 如果启用了全局创建密码，删除前必须验证（复用同一失败限速桶）
  if (createVerificationEnabled) {
    if (!createPassword || typeof createPassword !== 'string') {
      return jsonResponse({ error: '需要全局创建密码' }, 401);
    }
    const globalAuth = checkGlobalPassword(request, createPassword, allowedCreatePasswords);
    if (globalAuth === 'rate_limited') {
      return jsonResponse({ error: '尝试次数过多，请稍后再试' }, 429);
    }
    if (globalAuth === 'wrong_password') {
      return jsonResponse({ error: '全局创建密码错误' }, 403);
    }
  }

  const auth = await checkClipboardPassword(request, row, password, name);
  if (auth === 'need_password') return jsonResponse({ error: '需要密码' }, 401);
  if (auth === 'wrong_password') return jsonResponse({ error: '密码错误' }, 403);
  if (auth === 'rate_limited') return jsonResponse({ error: '尝试次数过多，请稍后再试' }, 429);

  await env.DB.prepare('DELETE FROM clipboards WHERE name = ?').bind(name).run();
  return jsonResponse({ success: true });
}

// ---------- 定时清理 ----------
async function cleanupExpiredData(env) {
  const now = Date.now();
  try {
    const result = await env.DB.prepare(
      'DELETE FROM clipboards WHERE expires_at IS NOT NULL AND expires_at <= ?'
    ).bind(now).run();
    console.log(`Cleaned up ${result.meta ? result.meta.changes : 0} expired clipboards`);

    const tokenResult = await env.DB.prepare(
      'DELETE FROM create_tokens WHERE expires_at <= ?'
    ).bind(now).run();
    console.log(`Cleaned up ${tokenResult.meta ? tokenResult.meta.changes : 0} expired create tokens`);
  } catch (err) {
    console.error('Cleanup failed:', err);
  }
}

// ---------- HTML 页面 ----------
function getFooterHtml() {
  return `
  <footer class="py-4 px-4 text-center text-xs text-gray-400 border-t border-gray-200/70 bg-white/60">
    Powered by
    <a href="${PROJECT_URL}" target="_blank" rel="noopener noreferrer" class="text-gray-500 hover:text-blue-600 underline underline-offset-2 transition">${PROJECT_NAME}</a>
    ·
    <a href="${PROJECT_URL}" target="_blank" rel="noopener noreferrer" class="hover:text-blue-600 transition">GitHub</a>
  </footer>`;
}

function getHomePage() {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>云剪贴板</title>
  <link rel="icon" href="data:,">
  <script src="https://cdn.tailwindcss.com/3.4.17"></script>
</head>
<body class="bg-gray-50 min-h-screen flex flex-col">
  <main class="flex-1 flex items-center justify-center">
    <div class="text-center px-4">
      <h1 class="text-5xl font-bold text-gray-900 mb-4">☁️ 云剪贴板</h1>
      <p class="text-xl text-gray-600">在地址栏输入 <code class="bg-gray-200 px-2 py-1 rounded">域名.com/剪贴板名</code> 即可新建或打开</p>
    </div>
  </main>
  ${getFooterHtml()}
</body>
</html>`;
}

function getInvalidNamePage(name) {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>无效的剪贴板名称 - 云剪贴板</title>
  <link rel="icon" href="data:,">
  <script src="https://cdn.tailwindcss.com/3.4.17"></script>
</head>
<body class="bg-gray-50 min-h-screen flex flex-col">
  <main class="flex-1 flex items-center justify-center px-4">
    <div class="w-full max-w-md mx-auto bg-white rounded-xl shadow p-8 text-center">
      <h1 class="text-2xl font-bold text-gray-900 mb-3">剪贴板名称无效</h1>
      <p class="text-sm text-gray-600 mb-2 break-all">名称 <code class="bg-gray-100 px-1.5 py-0.5 rounded">${escapeHtml(name)}</code> 不符合规则。</p>
      <p class="text-xs text-gray-500 mb-6">名称长度需为 1–64 个字符，且不能包含空格、斜杠或特殊符号（? # % &amp; +）。</p>
      <a href="/" class="inline-block bg-blue-600 hover:bg-blue-700 text-white px-5 py-2 rounded-lg text-sm transition">返回首页</a>
    </div>
  </main>
  ${getFooterHtml()}
</body>
</html>`;
}

function getVerifyPage(name) {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>验证 - ${escapeHtml(name)}</title>
  <link rel="icon" href="data:,">
  <script src="https://cdn.tailwindcss.com/3.4.17"></script>
</head>
<body class="bg-gray-50 min-h-screen flex flex-col">
  <main class="flex-1 flex items-center justify-center px-4">
    <div class="w-full max-w-md mx-auto bg-white rounded-xl shadow p-8">
      <h1 class="text-2xl font-bold mb-4">创建剪贴板需要验证</h1>
      <p class="text-gray-600 mb-6">请输入全局创建密码以继续</p>
      <form id="verifyForm">
        <input type="password" id="createPasswordInput" class="w-full border border-gray-300 rounded-lg px-3 py-2 mb-4" placeholder="密码">
        <button type="submit" id="verifyCreateBtn" class="w-full bg-blue-600 text-white py-2 rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed">验证</button>
        <p id="verifyError" class="text-red-500 mt-3"></p>
      </form>
    </div>
  </main>
  ${getFooterHtml()}
  <script>
    const name = ${safeJsonStringify(name)};
    const form = document.getElementById('verifyForm');
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const btn = document.getElementById('verifyCreateBtn');
      const errorEl = document.getElementById('verifyError');
      const password = document.getElementById('createPasswordInput').value.trim();
      errorEl.textContent = '';
      if (!password) {
        errorEl.textContent = '请输入密码';
        return;
      }
      btn.disabled = true;
      btn.textContent = '验证中…';
      try {
        const res = await fetch('/api/verify-create', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name, password })
        });
        const data = await res.json();
        if (res.ok) {
          // 令牌已通过 HttpOnly Cookie 下发，URL 中不再携带
          window.location.href = '/' + encodeURIComponent(name);
        } else {
          errorEl.textContent = data.error || '验证失败';
        }
      } catch (err) {
        errorEl.textContent = '网络错误';
      } finally {
        btn.disabled = false;
        btn.textContent = '验证';
      }
    });
  </script>
</body>
</html>`;
}

function getCreatePage(name, accessPasswordEnabled = true) {
  const passwordInputHtml = accessPasswordEnabled ? `
          <div class="flex items-center gap-2">
            <label class="text-sm text-gray-600 whitespace-nowrap">访问密码</label>
            <input type="password" id="password" class="border border-gray-300 rounded-lg px-3 py-1.5 text-sm w-32 focus:ring-2 focus:ring-blue-500" placeholder="可选">
          </div>` : '';

  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>创建剪贴板 - ${escapeHtml(name)}</title>
  <link rel="icon" href="data:,">
  <script src="https://cdn.tailwindcss.com/3.4.17"></script>
  <!-- 默认启用 Markdown 资源（用户可取消勾选复选框） -->
  <script src="https://cdn.jsdelivr.net/npm/luogu-renderer@1.0.5/dist/luogu-new-renderer.iife.js" integrity="sha384-uvo+AtndM549/9r8QeKtZ5fKy+TjqF/ssIXqMp2Fj4LZovtfKymdOjOkVFGtoX9S" crossorigin="anonymous"></script>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/katex@0.16.10/dist/katex.min.css" integrity="sha384-wcIxkf4k558AjM3Yz3BBFQUbk/zgIYC2R0QpeeYb+TwlBVMrlgLqwRjRtGZiK7ww" crossorigin="anonymous">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/prismjs@1.29.0/themes/prism.min.css" integrity="sha384-rCCjoCPCsizaAAYVoz1Q0CmCTvnctK0JkfCSjx7IIxexTBg+uCKtFYycedUjMyA2" crossorigin="anonymous">
  <script src="https://cdn.jsdelivr.net/npm/dompurify@3.2.4/dist/purify.min.js"></script>
  <style>
    ${getMarkdownStyles()}
    body, html { height: 100%; }
    .app-container { min-height: 100vh; display: flex; flex-direction: column; }
    .content-area { flex: 1; overflow-y: auto; }
    .edit-container > div { min-width: 0; }
    @media (max-width: 768px) {
      .edit-container { flex-direction: column; }
    }
    #preview { overflow-wrap: break-word; word-wrap: break-word; }
  </style>
</head>
<body class="bg-gray-50">
  <div class="app-container">
    <!-- 顶部栏：名称 + 设置项 -->
    <div class="bg-white border-b border-gray-200 px-4 py-3 shadow-sm">
      <div class="max-w-6xl mx-auto">
        <h1 class="text-xl font-bold mb-3">📝 新建剪贴板：${escapeHtml(name)}</h1>
        <div class="flex flex-wrap items-center gap-4">${passwordInputHtml}
          <div class="flex items-center gap-2">
            <label class="text-sm text-gray-600 whitespace-nowrap">过期时间</label>
            <select id="expiresInDays" class="border border-gray-300 rounded-lg px-3 py-1.5 text-sm focus:ring-2 focus:ring-blue-500">
              <option value="0">永不删除</option>
              <option value="1">1 天</option>
              <option value="3" selected>3 天</option>
              <option value="7">7 天</option>
              <option value="14">14 天</option>
              <option value="30">30 天</option>
            </select>
          </div>
          <label class="flex items-center gap-1.5 cursor-pointer">
            <input type="checkbox" id="enableMarkdown" checked class="h-4 w-4 text-blue-600 border-gray-300 rounded focus:ring-blue-500">
            <span class="text-sm text-gray-600">Markdown</span>
          </label>
        </div>
      </div>
    </div>

    <!-- 编辑区 + 实时预览分栏 -->
    <div class="content-area p-6">
      <div class="edit-container flex gap-4 max-w-6xl mx-auto">
        <div class="flex-1">
          <label class="block text-sm font-medium text-gray-700 mb-1">内容编辑</label>
          <textarea id="content" required class="w-full h-[70vh] border border-gray-300 rounded-lg px-3 py-2 font-mono text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent resize-none" placeholder="粘贴或输入文本..."></textarea>
        </div>
        <div class="flex-1">
          <label class="block text-sm font-medium text-gray-700 mb-1">实时预览</label>
          <div id="preview" class="bg-white rounded-xl shadow p-4 h-[70vh] overflow-y-auto markdown-body"></div>
        </div>
      </div>
      <div class="mt-4 max-w-6xl mx-auto">
        <button id="createBtn" class="bg-blue-600 hover:bg-blue-700 text-white px-6 py-2.5 rounded-lg text-sm font-medium transition disabled:opacity-50 disabled:cursor-not-allowed">创建剪贴板</button>
        <p id="error" class="text-red-500 mt-3"></p>
      </div>
    </div>
    ${getFooterHtml()}
  </div>

  <script>
    const name = ${safeJsonStringify(name)};
    let renderAvailable = true;
    let renderer = null;
    if (typeof window.LuoguNewRenderer !== 'undefined' &&
        typeof window.LuoguNewRenderer.render === 'function') {
      renderer = window.LuoguNewRenderer;
    } else {
      renderAvailable = false;
    }

    let renderSeq = 0;
    async function updatePreview() {
      const text = document.getElementById('content').value;
      const preview = document.getElementById('preview');
      const enableMd = document.getElementById('enableMarkdown').checked;
      if (!enableMd || !renderAvailable || !renderer) {
        preview.textContent = text;
        return;
      }
      const seq = ++renderSeq;
      try {
        const html = await renderer.render(text);
        if (seq !== renderSeq) return;
        // DOMPurify 不可用时降级为纯文本，避免未净化的 HTML 引发 XSS
        if (window.DOMPurify && typeof window.DOMPurify.sanitize === 'function') {
          preview.innerHTML = window.DOMPurify.sanitize(html);
        } else {
          preview.textContent = text;
        }
      } catch (e) {
        if (seq !== renderSeq) return;
        renderAvailable = false;
        preview.textContent = text;
      }
    }

    document.getElementById('content').addEventListener('input', updatePreview);
    document.getElementById('enableMarkdown').addEventListener('change', updatePreview);

    document.getElementById('createBtn').addEventListener('click', async () => {
      const btn = document.getElementById('createBtn');
      const errorEl = document.getElementById('error');
      errorEl.textContent = '';
      const content = document.getElementById('content').value;
      const passwordInput = document.getElementById('password');
      const password = passwordInput ? passwordInput.value : '';
      const expiresInDays = parseInt(document.getElementById('expiresInDays').value);
      const enableMarkdown = document.getElementById('enableMarkdown').checked;
      if (!content || content.trim() === '') {
        errorEl.textContent = '内容不能为空';
        return;
      }
      if (content.length > 102400) {
        errorEl.textContent = '内容过长（最多 100KB）';
        return;
      }
      btn.disabled = true;
      btn.textContent = '创建中…';
      try {
        const res = await fetch('/api/create', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name, content, password, expiresInDays, enableMarkdown })
        });
        const data = await res.json();
        if (res.ok) {
          window.location.href = '/' + encodeURIComponent(name);
        } else {
          errorEl.textContent = data.error || '创建失败';
        }
      } catch (err) {
        errorEl.textContent = '网络错误，请检查连接';
      } finally {
        btn.disabled = false;
        btn.textContent = '创建剪贴板';
      }
    });
  </script>
</body>
</html>`;
}

// 共享 Markdown 样式（同时用于打开页和创建页的预览）
function getMarkdownStyles() {
  return `
    .markdown-body { line-height: 1.6; word-break: break-word; }
    .katex { font-size: 1.1em; }

    /* 标题/段落/列表/引用/表格等语义标签（luogu-renderer 不含 CSS，Tailwind Preflight 会重置） */
    .markdown-body h1 { font-size: 2em; font-weight: 700; margin: 0.67em 0; }
    .markdown-body h2 { font-size: 1.5em; font-weight: 600; margin: 0.75em 0; }
    .markdown-body h3 { font-size: 1.25em; font-weight: 600; margin: 0.83em 0; }
    .markdown-body h4 { font-size: 1em; font-weight: 600; margin: 1em 0; }
    .markdown-body h5 { font-size: 0.875em; font-weight: 600; margin: 1em 0; }
    .markdown-body h6 { font-size: 0.85em; font-weight: 600; color: #6b7280; margin: 1em 0; }
    .markdown-body p { margin: 0.75em 0; }
    .markdown-body ul, .markdown-body ol { margin: 0.75em 0; padding-left: 2em; }
    .markdown-body ul { list-style-type: disc; }
    .markdown-body ol { list-style-type: decimal; }
    .markdown-body li { margin: 0.25em 0; }
    .markdown-body blockquote { margin: 0.75em 0; padding: 0.25em 1em; border-left: 4px solid #d1d5db; color: #6b7280; }
    .markdown-body table { border-collapse: collapse; margin: 0.75em 0; }
    .markdown-body th, .markdown-body td { border: 1px solid #d1d5db; padding: 0.5em 0.75em; text-align: left; }
    .markdown-body th { background: #f3f4f6; font-weight: 600; }
    .markdown-body tr:nth-child(even) td { background: #f9fafb; }
    .markdown-body hr { margin: 1.5em 0; border: 0; border-top: 1px solid #e5e7eb; }
    .markdown-body img { max-width: 100%; height: auto; border-radius: 6px; }
    .markdown-body a { color: #2563eb; text-decoration: underline; }
    .markdown-body a:hover { color: #1d4ed8; }

    /* 代码块基础样式（Prism 主题仅负责 token 配色；21px 行高与 luogu-renderer 生成的行号/高亮定位对齐） */
    .markdown-body pre { position: relative; background: #f8f9fa; border-radius: 6px; padding: 21px; overflow-x: auto; }
    .markdown-body pre, .markdown-body pre code { line-height: 21px; }
    .markdown-body code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace; }
    .markdown-body :not(pre) > code { background: #f3f4f6; padding: 0.15em 0.35em; border-radius: 3px; font-size: 0.9em; }
    .markdown-body pre code { padding: 0; background: none; }

    /* 代码块一键复制按钮（luogu-renderer 1.0.5 已内置 .code-container 和 .copy-button HTML 结构） */
    .markdown-body .code-container { position: relative; }
    .markdown-body .copy-button {
      position: absolute; top: 8px; right: 8px;
      display: inline-flex; align-items: center; justify-content: center;
      width: 32px; height: 32px;
      background: rgba(255,255,255,0.85); border: 1px solid #e5e7eb;
      cursor: pointer; color: #6b7280; padding: 4px; border-radius: 6px;
      opacity: 1; z-index: 1;
      transition: color .15s, background .15s, border-color .15s;
      backdrop-filter: blur(4px);
    }
    .markdown-body .copy-button:hover { color: #1f2937; background: #fff; border-color: #9ca3af; }
    .markdown-body .copy-button svg { width: 16px; height: 16px; display: block; }

    /* 代码块行号 */
    .markdown-body pre.line-numbers { padding-left: 3.8em; counter-reset: linenumber; }
    .markdown-body pre.line-numbers code { position: relative; }
    .markdown-body .line-numbers-rows { position: absolute; top: 0; left: -3.8em; width: 3em; border-right: 1px solid #e5e7eb; user-select: none; pointer-events: none; }
    .markdown-body .line-numbers-rows > span { display: block; counter-increment: linenumber; }
    .markdown-body .line-numbers-rows > span::before { content: counter(linenumber); color: #9ca3af; display: block; padding-right: 0.5em; text-align: right; }

    /* 代码块高亮行（luogu-renderer 的 top 以 pre 顶部为基准，下移一个 21px 行高对齐到代码首行） */
    .markdown-body pre .line-highlight { position: absolute; left: 0; right: 0; background: rgba(254, 240, 138, 0.4); pointer-events: none; transform: translateY(21px); }

    /* 自定义容器 info/warning/error/success */
    .markdown-body details { border: 1px solid #e5e7eb; border-radius: 8px; padding: 0.75em 1em; margin: 0.75em 0; }
    .markdown-body details summary { cursor: pointer; font-weight: 600; }
    .markdown-body details.info { background: #eff6ff; border-color: #bfdbfe; }
    .markdown-body details.warning { background: #fffbeb; border-color: #fde68a; }
    .markdown-body details.error { background: #fef2f2; border-color: #fecaca; }
    .markdown-body details.success { background: #f0fdf4; border-color: #bbf7d0; }

    /* 题头 epigraph */
    .markdown-body .epigraph { border-left: 4px solid #e5e7eb; padding-left: 1em; color: #6b7280; margin: 0.75em 0; }
  `;
}

function getOpenPage(meta) {
  const { name, hasPassword, createdAt, updatedAt, expiresInDays, enableMarkdown, inlineContent, createVerificationEnabled, accessPasswordEnabled = true } = meta;
  const expiryText = expiresInDays === 0 ? '永不删除' : `${expiresInDays} 天后自动删除`;

  const editPasswordHtml = accessPasswordEnabled ? `
              <div class="flex items-center gap-2">
                <label class="text-sm text-gray-600 whitespace-nowrap">修改访问密码</label>
                <input type="password" id="editPassword" class="border border-gray-300 rounded-lg px-3 py-1.5 text-sm w-32 focus:ring-2 focus:ring-blue-500 disabled:bg-gray-100 disabled:text-gray-400 disabled:cursor-not-allowed" placeholder="留空不变">
                <label class="flex items-center gap-1 text-sm text-red-500 cursor-pointer select-none">
                  <input type="checkbox" id="editClearPassword" class="h-3.5 w-3.5 accent-red-500">
                  清除密码
                </label>
              </div>` : '';

  const markdownResources = enableMarkdown ? `
  <script src="https://cdn.jsdelivr.net/npm/luogu-renderer@1.0.5/dist/luogu-new-renderer.iife.js" integrity="sha384-uvo+AtndM549/9r8QeKtZ5fKy+TjqF/ssIXqMp2Fj4LZovtfKymdOjOkVFGtoX9S" crossorigin="anonymous"></script>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/katex@0.16.10/dist/katex.min.css" integrity="sha384-wcIxkf4k558AjM3Yz3BBFQUbk/zgIYC2R0QpeeYb+TwlBVMrlgLqwRjRtGZiK7ww" crossorigin="anonymous">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/prismjs@1.29.0/themes/prism.min.css" integrity="sha384-rCCjoCPCsizaAAYVoz1Q0CmCTvnctK0JkfCSjx7IIxexTBg+uCKtFYycedUjMyA2" crossorigin="anonymous">
  <script src="https://cdn.jsdelivr.net/npm/dompurify@3.2.4/dist/purify.min.js"></script>
  ` : '';

  const markdownStyles = enableMarkdown ? getMarkdownStyles() : '';

  const inlineContentJs = inlineContent === null || inlineContent === undefined
    ? 'null'
    : safeJsonStringify(inlineContent);

  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>剪贴板 - ${escapeHtml(name)}</title>
  <link rel="icon" href="data:,">
  <script src="https://cdn.tailwindcss.com/3.4.17"></script>
  ${markdownResources}
  <style>
    ${markdownStyles}
    body, html { height: 100%; }
    .app-container { min-height: 100vh; display: flex; flex-direction: column; }
    .content-area { flex: 1; overflow-y: auto; }
    .warning-banner { background: #fef3c7; border: 1px solid #f59e0b; color: #92400e; padding: 10px; border-radius: 8px; margin-bottom: 15px; }
    /* 长文本自动换行，防止单行过长时溢出容器（overflow-wrap 可继承，覆盖 Markdown 内部元素） */
    #contentDisplay, #editPreview { overflow-wrap: break-word; word-wrap: break-word; }
    /* 编辑分栏的 flex 子项允许收缩，避免长内容把预览框撑大 */
    .edit-container > div { min-width: 0; }
    @media (max-width: 768px) {
      .edit-container { flex-direction: column; }
    }
  </style>
</head>
<body class="bg-gray-50">
  <div id="app" class="app-container">
    <div id="passwordSection" class="${hasPassword ? '' : 'hidden'} flex-1 flex items-center justify-center px-4">
      <div class="w-full max-w-md mx-auto bg-white rounded-xl shadow p-8">
        <h2 class="text-2xl font-semibold mb-4">请输入密码</h2>
        <p class="text-gray-600 mb-6">剪贴板 <strong>${escapeHtml(name)}</strong> 受密码保护</p>
        <form id="passwordForm">
          <input type="password" id="passwordInput" class="w-full border border-gray-300 rounded-lg px-3 py-2 mb-4 focus:ring-2 focus:ring-blue-500" placeholder="密码">
          <button type="submit" id="verifyBtn" class="w-full bg-blue-600 text-white py-2 rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed">验证</button>
        </form>
        <p id="passwordError" class="text-red-500 mt-3"></p>
      </div>
    </div>
    <div id="contentSection" class="${hasPassword ? 'hidden' : ''} flex-1 flex flex-col">
      <div class="bg-white border-b border-gray-200 px-4 py-3 flex items-center justify-between flex-wrap gap-2 shadow-sm">
        <div>
          <h1 class="text-xl font-bold">📋 ${escapeHtml(name)}</h1>
          <p class="text-xs text-gray-500">创建于 <span id="createdAtDisplay">${new Date(createdAt).toLocaleString()}</span><span id="updatedAtWrap" class="${updatedAt && updatedAt !== createdAt ? '' : 'hidden'}"> · 更新于 <span id="updatedAtDisplay">${new Date(updatedAt || createdAt).toLocaleString()}</span></span> · <span id="expiryText">${expiryText}</span></p>
        </div>
        <div class="flex space-x-2">
          <button id="copyBtn" class="bg-gray-200 hover:bg-gray-300 text-gray-800 px-4 py-2 rounded-lg text-sm">复制</button>
          <button id="editBtn" class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg text-sm disabled:opacity-50 disabled:cursor-not-allowed">编辑</button>
          <button id="deleteBtn" class="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-lg text-sm disabled:opacity-50 disabled:cursor-not-allowed">删除</button>
        </div>
      </div>
      <div class="content-area p-6">
        <div id="warningBanner" class="warning-banner hidden"></div>
        <div id="previewMode">
          <div id="contentDisplay" class="bg-white rounded-xl shadow p-6 max-w-4xl mx-auto ${enableMarkdown ? 'markdown-body' : 'whitespace-pre-wrap'}"></div>
        </div>
        <div id="editMode" class="hidden">
          <div class="edit-settings bg-gray-100 rounded-lg px-4 py-3 mb-4 max-w-6xl mx-auto">
            <div class="flex flex-wrap items-center gap-4">${editPasswordHtml}
              <div class="flex items-center gap-2">
                <label class="text-sm text-gray-600 whitespace-nowrap">过期时间</label>
                <select id="editExpiresInDays" class="border border-gray-300 rounded-lg px-3 py-1.5 text-sm focus:ring-2 focus:ring-blue-500"></select>
              </div>
            </div>
          </div>
          <div class="edit-container flex gap-4 max-w-6xl mx-auto">
            <div class="flex-1">
              <label class="block text-sm font-medium mb-1">编辑内容</label>
              <textarea id="editContent" class="w-full h-[70vh] border border-gray-300 rounded-lg px-3 py-2 font-mono focus:ring-2 focus:ring-blue-500"></textarea>
            </div>
            <div class="flex-1">
              <label class="block text-sm font-medium mb-1">实时预览</label>
              <div id="editPreview" class="bg-white rounded-xl shadow p-4 h-[70vh] overflow-y-auto ${enableMarkdown ? 'markdown-body' : 'whitespace-pre-wrap'}"></div>
            </div>
          </div>
          <div class="mt-4 flex space-x-2 max-w-6xl mx-auto">
            <button id="saveBtn" class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg text-sm disabled:opacity-50 disabled:cursor-not-allowed">保存</button>
            <button id="cancelBtn" class="bg-gray-200 hover:bg-gray-300 text-gray-800 px-4 py-2 rounded-lg text-sm">取消</button>
          </div>
          <p id="editError" class="text-red-500 mt-3"></p>
        </div>
      </div>
    </div>
    ${getFooterHtml()}
  </div>

  <script>
    const name = ${safeJsonStringify(name)};
    const hasPassword = ${hasPassword};
    const enableMarkdown = ${enableMarkdown};
    const inlineContent = ${inlineContentJs};
    const createdAt = ${createdAt};
    let updatedAt = ${updatedAt || createdAt};
    const createVerificationEnabled = ${createVerificationEnabled};
    let expiresInDays = ${expiresInDays};
    // 显示创建与更新时间：跟随查看者系统时区，并附带时区标识（如 GMT+8）；
    // 服务端预渲染的 UTC 文本仅作为 JS 被禁用时的回退
    function formatLocalTime(ts) {
      return new Date(ts).toLocaleString(undefined, { timeZoneName: 'short' });
    }
    document.getElementById('createdAtDisplay').textContent = formatLocalTime(createdAt);
    document.getElementById('updatedAtDisplay').textContent = formatLocalTime(updatedAt);
    let currentPassword = '';
    let globalPassword = '';
    let originalContent = '';
    let renderAvailable = enableMarkdown;
    let isEditing = false;
    let isOpeningEditor = false;
    let toastTimer = null;

    function showToast(message) {
      const toast = document.getElementById('toastBanner');
      toast.textContent = message;
      toast.classList.remove('hidden');
      clearTimeout(toastTimer);
      toastTimer = setTimeout(() => toast.classList.add('hidden'), 3500);
    }

    function confirmAction(title, message) {
      return new Promise((resolve) => {
        const modal = document.getElementById('confirmModal');
        const titleEl = document.getElementById('confirmModalTitle');
        const msgEl = document.getElementById('confirmModalMessage');
        const okBtn = document.getElementById('confirmModalOk');
        const cancelBtn = document.getElementById('confirmModalCancel');
        titleEl.textContent = title;
        msgEl.textContent = message;
        modal.classList.remove('hidden');
        function onKeyDown(e) {
          if (e.key === 'Escape') close(false);
        }
        function close(result) {
          modal.classList.add('hidden');
          document.removeEventListener('keydown', onKeyDown);
          resolve(result);
        }
        document.addEventListener('keydown', onKeyDown);
        cancelBtn.onclick = () => close(false);
        okBtn.onclick = () => close(true);
      });
    }

    let renderer = null;
    if (enableMarkdown) {
      if (typeof window.LuoguNewRenderer !== 'undefined' &&
          typeof window.LuoguNewRenderer.render === 'function') {
        renderer = window.LuoguNewRenderer;
      } else {
        renderAvailable = false;
      }
    }

    async function renderMarkdown(text) {
      if (!enableMarkdown || !renderAvailable || !renderer) return null;
      try { return await renderer.render(text); } catch (e) { renderAvailable = false; return null; }
    }

    function showWarning(message) {
      const banner = document.getElementById('warningBanner');
      banner.textContent = message;
      banner.classList.remove('hidden');
    }

    let renderSeq = 0; // 丢弃过期渲染结果，避免快速输入时预览错乱

    async function setContent(container, text) {
      if (enableMarkdown) {
        const seq = ++renderSeq;
        const rendered = await renderMarkdown(text);
        if (seq !== renderSeq) return; // 已有更新的渲染请求，丢弃本次结果
        if (rendered !== null && window.DOMPurify && typeof window.DOMPurify.sanitize === 'function') {
          container.innerHTML = window.DOMPurify.sanitize(rendered);
        } else {
          container.textContent = text;
          if (!renderAvailable) showWarning('⚠️ Markdown 渲染器加载失败，已显示原始文本。');
          else if (rendered !== null) showWarning('⚠️ 安全组件加载失败，为防止 XSS 已显示原始文本。');
          else showWarning('⚠️ 渲染时出现错误，已显示原始文本。');
        }
      } else {
        container.textContent = text;
      }
    }

    function showPreview() {
      isEditing = false;
      document.getElementById('editBtn').disabled = false;
      setContent(document.getElementById('contentDisplay'), originalContent);
      document.getElementById('previewMode').classList.remove('hidden');
      document.getElementById('editMode').classList.add('hidden');
    }

    function showEditor() {
      isEditing = true;
      document.getElementById('editBtn').disabled = true;
      // 初始化过期时间下拉框（仅在首次编辑时填充选项）
      const sel = document.getElementById('editExpiresInDays');
      if (sel.options.length === 0) {
        const opts = [
          [0, '永不删除'], [1, '1 天'], [3, '3 天'], [7, '7 天'], [14, '14 天'], [30, '30 天']
        ];
        opts.forEach(([v, t]) => { const o = document.createElement('option'); o.value = v; o.textContent = t; sel.appendChild(o); });
      }
      sel.value = expiresInDays;
      const editPwdEl = document.getElementById('editPassword');
      const editClearEl = document.getElementById('editClearPassword');
      if (editPwdEl) {
        editPwdEl.value = '';
        editPwdEl.disabled = false;
      }
      if (editClearEl) editClearEl.checked = false;
      document.getElementById('editContent').value = originalContent;
      updateEditPreview();
      document.getElementById('previewMode').classList.add('hidden');
      document.getElementById('editMode').classList.remove('hidden');
    }

    // 勾选“清除密码”时禁用密码输入框，避免状态混淆
    const editClearCheckbox = document.getElementById('editClearPassword');
    if (editClearCheckbox) {
      editClearCheckbox.addEventListener('change', (e) => {
        const pwdEl = document.getElementById('editPassword');
        if (!pwdEl) return;
        pwdEl.disabled = e.target.checked;
        if (e.target.checked) pwdEl.value = '';
      });
    }

    // 全局创建密码验证（复用 /api/verify-create，不传 name 时仅校验密码不签发令牌）
    function promptGlobalPassword() {
      return new Promise((resolve, reject) => {
        const modal = document.getElementById('globalPasswordModal');
        const form = document.getElementById('globalPasswordForm');
        const input = document.getElementById('globalPasswordInput');
        const errorEl = document.getElementById('globalPasswordError');
        const confirmBtn = document.getElementById('globalPasswordConfirm');
        const cancelBtn = document.getElementById('globalPasswordCancel');
        input.value = '';
        errorEl.classList.add('hidden');
        modal.classList.remove('hidden');
        input.focus();
        let checking = false;
        function onKeyDown(e) {
          if (e.key === 'Escape' && !checking) {
            cleanup();
            reject(new Error('取消'));
          }
        }
        function cleanup() {
          modal.classList.add('hidden');
          document.removeEventListener('keydown', onKeyDown);
        }
        document.addEventListener('keydown', onKeyDown);
        cancelBtn.onclick = () => { cleanup(); reject(new Error('取消')); };
        form.onsubmit = async (e) => {
          e.preventDefault();
          if (checking) return;
          const pwd = input.value.trim();
          if (!pwd) { errorEl.textContent = '请输入密码'; errorEl.classList.remove('hidden'); return; }
          checking = true;
          confirmBtn.disabled = true;
          confirmBtn.textContent = '验证中…';
          errorEl.classList.add('hidden');
          try {
            const res = await fetch('/api/verify-create', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ password: pwd })
            });
            if (res.ok) {
              cleanup();
              resolve(pwd);
            } else {
              const data = await res.json().catch(() => ({}));
              errorEl.textContent = data.error || '密码错误';
              errorEl.classList.remove('hidden');
              input.value = '';
              input.focus();
            }
          } catch (e) {
            errorEl.textContent = '网络错误，请检查连接';
            errorEl.classList.remove('hidden');
          } finally {
            checking = false;
            confirmBtn.disabled = false;
            confirmBtn.textContent = '确认';
          }
        };
      });
    }

    function updateEditPreview() {
      const text = document.getElementById('editContent').value;
      setContent(document.getElementById('editPreview'), text);
    }

    async function parseJson(res) {
      try {
        return await res.json();
      } catch (e) {
        return { error: '服务返回异常（HTTP ' + res.status + '）' };
      }
    }

    function displayContent(text) {
      originalContent = text;
      document.getElementById('passwordSection').classList.add('hidden');
      document.getElementById('contentSection').classList.remove('hidden');
      showPreview();
    }

    async function loadContent(password = '') {
      const verifyBtn = document.getElementById('verifyBtn');
      const pwdError = document.getElementById('passwordError');
      if (verifyBtn) {
        verifyBtn.disabled = true;
        verifyBtn.textContent = '验证中…';
      }
      try {
        const res = await fetch('/api/get', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name, password })
        });
        const data = await parseJson(res);
        if (res.ok) {
          pwdError.textContent = '';
          displayContent(data.content);
        } else if (res.status === 401) {
          document.getElementById('passwordSection').classList.remove('hidden');
          document.getElementById('contentSection').classList.add('hidden');
          pwdError.textContent = data.error || '';
        } else if (res.status === 403 || res.status === 429) {
          pwdError.textContent = data.error || '';
        } else {
          showToast(data.error || '加载失败');
        }
      } catch (err) {
        if (!document.getElementById('passwordSection').classList.contains('hidden')) {
          pwdError.textContent = '网络错误，请检查连接';
        } else {
          showToast('网络错误，请检查连接');
        }
      } finally {
        if (verifyBtn) {
          verifyBtn.disabled = false;
          verifyBtn.textContent = '验证';
        }
      }
    }

    async function copyContent() {
      try {
        await navigator.clipboard.writeText(originalContent);
        const btn = document.getElementById('copyBtn');
        btn.textContent = '已复制';
        setTimeout(() => btn.textContent = '复制', 2000);
      } catch (err) {
        const textarea = document.createElement('textarea');
        textarea.value = originalContent;
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
        const btn = document.getElementById('copyBtn');
        btn.textContent = '已复制';
        setTimeout(() => btn.textContent = '复制', 2000);
      }
    }

    document.getElementById('passwordForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const pwd = document.getElementById('passwordInput').value;
      if (!pwd) { document.getElementById('passwordError').textContent = '请输入密码'; return; }
      currentPassword = pwd;
      loadContent(pwd);
    });

    document.getElementById('copyBtn').addEventListener('click', copyContent);
    document.getElementById('editBtn').addEventListener('click', async () => {
      if (isEditing || isOpeningEditor) return;
      isOpeningEditor = true;
      try {
        if (createVerificationEnabled) {
          try { globalPassword = await promptGlobalPassword(); } catch (e) { return; }
        }
        showEditor();
      } finally {
        isOpeningEditor = false;
      }
    });
    document.getElementById('editContent').addEventListener('input', updateEditPreview);
    document.getElementById('cancelBtn').addEventListener('click', showPreview);

    document.getElementById('saveBtn').addEventListener('click', async () => {
      const saveBtn = document.getElementById('saveBtn');
      const content = document.getElementById('editContent').value;
      if (content.length > 102400) {
        document.getElementById('editError').textContent = '内容过长（最多 100KB）';
        return;
      }
      const editPwdEl = document.getElementById('editPassword');
      const editClearEl = document.getElementById('editClearPassword');
      const newPassword = editPwdEl ? editPwdEl.value : '';
      const clearPassword = editClearEl ? editClearEl.checked : false;
      const editExpiresInDays = parseInt(document.getElementById('editExpiresInDays').value, 10);
      document.getElementById('editError').textContent = '';

      function buildBody() {
        const b = { name, content, password: currentPassword, createPassword: globalPassword, expiresInDays: editExpiresInDays };
        if (clearPassword) { b.newPassword = ''; }
        else if (newPassword) { b.newPassword = newPassword; }
        return b;
      }

      saveBtn.disabled = true;
      saveBtn.textContent = '保存中…';
      try {
        let res = await fetch('/api/update', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(buildBody())
        });
        let data = await parseJson(res);
        // 全局密码错误 → 重新弹出密码框，不离开编辑页
        while ((res.status === 401 || res.status === 403) && createVerificationEnabled && data.error && data.error.includes('全局创建密码')) {
          try { globalPassword = await promptGlobalPassword(); } catch (e) { return; }
          document.getElementById('editError').textContent = '';
          res = await fetch('/api/update', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(buildBody())
          });
          data = await parseJson(res);
        }
        if (res.ok) {
          originalContent = content;
          expiresInDays = editExpiresInDays;
          // 同步更新本地访问密码，避免本次页面内再次编辑/删除时仍提交旧密码
          if (clearPassword) {
            currentPassword = '';
          } else if (newPassword) {
            currentPassword = newPassword.trim() !== '' ? newPassword : '';
          }
          updatedAt = Date.now();
          document.getElementById('updatedAtDisplay').textContent = formatLocalTime(updatedAt);
          document.getElementById('updatedAtWrap').classList.remove('hidden');
          document.getElementById('expiryText').textContent =
            expiresInDays === 0 ? '永不删除' : expiresInDays + ' 天后自动删除';
          showPreview();
        } else {
          document.getElementById('editError').textContent = data.error || '更新失败';
        }
      } catch (err) {
        document.getElementById('editError').textContent = '网络错误，请检查连接';
      } finally {
        saveBtn.disabled = false;
        saveBtn.textContent = '保存';
      }
    });

    document.getElementById('deleteBtn').addEventListener('click', async () => {
      const deleteBtn = document.getElementById('deleteBtn');
      if (createVerificationEnabled) {
        try { globalPassword = await promptGlobalPassword(); } catch (e) { return; }
      }
      const confirmed = await confirmAction('确认删除', '确定要删除这个剪贴板吗？此操作不可撤销。');
      if (!confirmed) return;
      deleteBtn.disabled = true;
      deleteBtn.textContent = '删除中…';
      try {
        let res = await fetch('/api/delete', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name, password: currentPassword, createPassword: globalPassword })
        });
        let data = await parseJson(res);
        // 全局密码错误 → 重新弹出密码框确认后重试
        while ((res.status === 401 || res.status === 403) && createVerificationEnabled && data.error && data.error.includes('全局创建密码')) {
          try { globalPassword = await promptGlobalPassword(); } catch (e) { return; }
          const reconfirmed = await confirmAction('确认删除', '确定要删除这个剪贴板吗？此操作不可撤销。');
          if (!reconfirmed) return;
          res = await fetch('/api/delete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, password: currentPassword, createPassword: globalPassword })
          });
          data = await parseJson(res);
        }
        if (res.ok) {
          window.location.href = '/';
        } else {
          showToast(data.error || '删除失败');
        }
      } catch (err) {
        showToast('网络错误，请检查连接');
      } finally {
        deleteBtn.disabled = false;
        deleteBtn.textContent = '删除';
      }
    });

    // luogu-renderer 生成的代码块复制按钮（事件委托，点击复制代码块内容）
    document.addEventListener('click', async (e) => {
      const btn = e.target.closest('.copy-button');
      if (!btn) return;
      const pre = btn.closest('.code-container')?.querySelector('pre');
      if (!pre) return;
      const text = pre.innerText;
      try {
        await navigator.clipboard.writeText(text);
      } catch (err) {
        const ta = document.createElement('textarea');
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
      }
      btn.style.color = '#16a34a';
      setTimeout(() => { btn.style.color = ''; }, 1500);
    });

    if (!hasPassword) {
      if (inlineContent !== null && inlineContent !== undefined) {
        displayContent(inlineContent);
      } else {
        loadContent('');
      }
    }
  </script>
    <div id="globalPasswordModal" class="hidden fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div class="bg-white rounded-xl shadow-2xl p-6 w-full max-w-sm mx-4">
        <h3 class="text-lg font-semibold mb-4">需要全局创建密码</h3>
        <form id="globalPasswordForm">
          <input type="password" id="globalPasswordInput" class="w-full border border-gray-300 rounded-lg px-3 py-2 mb-4 focus:ring-2 focus:ring-blue-500" placeholder="请输入全局密码">
          <p id="globalPasswordError" class="text-red-500 text-sm mb-4 hidden"></p>
          <div class="flex space-x-2 justify-end">
            <button type="button" id="globalPasswordCancel" class="bg-gray-200 hover:bg-gray-300 text-gray-800 px-4 py-2 rounded-lg text-sm">取消</button>
            <button type="submit" id="globalPasswordConfirm" class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg text-sm disabled:opacity-50 disabled:cursor-not-allowed">确认</button>
          </div>
        </form>
      </div>
    </div>
    <div id="confirmModal" class="hidden fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div class="bg-white rounded-xl shadow-2xl p-6 w-full max-w-sm mx-4">
        <h3 id="confirmModalTitle" class="text-lg font-semibold mb-2">确认操作</h3>
        <p id="confirmModalMessage" class="text-sm text-gray-600 mb-5"></p>
        <div class="flex space-x-2 justify-end">
          <button type="button" id="confirmModalCancel" class="bg-gray-200 hover:bg-gray-300 text-gray-800 px-4 py-2 rounded-lg text-sm">取消</button>
          <button type="button" id="confirmModalOk" class="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-lg text-sm">确认删除</button>
        </div>
      </div>
    </div>
    <div id="toastBanner" class="hidden fixed bottom-6 right-6 bg-gray-900 text-white text-sm px-4 py-2.5 rounded-lg shadow-lg z-50 max-w-sm"></div>
  </body>
</html>`;
}