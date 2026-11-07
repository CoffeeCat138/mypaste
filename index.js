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
const RATE_LIMITS = {
  verifyCreate: { limit: 10, windowMs: 10 * 60 * 1000 },    // 创建验证：10 次 / 10 分钟
  passwordAttempt: { limit: 10, windowMs: 10 * 60 * 1000 }, // 剪贴板密码试错：10 次 / 10 分钟
};
const CLIPBOARD_COLUMNS =
  'name, content, password_hash, created_at, updated_at, expires_in_days, expires_at, enable_markdown';

// ---------- 内存限速（按 IP，Worker isolate 级别）----------
const rateLimitStore = new Map();

// 计数 + 判断是否超限；超过 limit 返回 true
function isRateLimited(ip, key, { limit, windowMs }) {
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
  // 禁止空白、斜杠、反斜杠和控制字符（含 / 的名称创建后永远无法通过 URL 打开）
  if (/[/\\\s\u0000-\u001f\u007f]/.test(name)) return false;
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
      'Cache-Control': 'no-store'
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
    const allowedCreatePasswords = parseAllowedPasswords(env.ALLOWED_PASSWORDS);

    // 处理 API 请求
    if (path.startsWith('/api/')) {
      return handleApiRequest(request, env, createVerificationEnabled, allowedCreatePasswords);
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
      // 剪贴板不存在（或已过期）：进入创建流程
      const token = getCookie(request, CREATE_TOKEN_COOKIE);
      const tokenValid = createVerificationEnabled && (await isValidCreateToken(env, token, name));
      if (createVerificationEnabled && !tokenValid) {
        return htmlResponse(getVerifyPage(name));
      }
      return htmlResponse(getCreatePage(name));
    }

    const meta = {
      name,
      hasPassword: !!row.password_hash,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      expiresInDays: row.expires_in_days,
      enableMarkdown: row.enable_markdown === 1,
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
async function handleApiRequest(request, env, createVerificationEnabled, allowedCreatePasswords) {
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
      return createClipboard(body, request, env, createVerificationEnabled);
    case '/api/get':
      return getClipboardContent(body, request, env);
    case '/api/update':
      return updateClipboard(body, request, env);
    case '/api/delete':
      return deleteClipboard(body, request, env);
    default:
      return jsonResponse({ error: '接口不存在' }, 404);
  }
}

// ---------- 核心操作 ----------
async function verifyCreatePassword(body, request, env, createVerificationEnabled, allowedCreatePasswords) {
  const { name, password } = body;
  if (!createVerificationEnabled) {
    return jsonResponse({ error: '未启用创建验证' }, 400);
  }
  if (!isValidClipboardName(name)) {
    return jsonResponse({ error: '剪贴板名称无效' }, 400);
  }
  if (typeof password !== 'string' || !password) {
    return jsonResponse({ error: '请输入密码' }, 400);
  }
  if (allowedCreatePasswords.length === 0) {
    return jsonResponse({ error: '验证配置错误，请联系管理员' }, 500);
  }
  if (isRateLimited(getClientIp(request), 'verify-create', RATE_LIMITS.verifyCreate)) {
    return jsonResponse({ error: '尝试次数过多，请稍后再试' }, 429);
  }
  if (!allowedCreatePasswords.includes(password)) {
    return jsonResponse({ error: '密码错误' }, 403);
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

async function createClipboard(body, request, env, createVerificationEnabled) {
  const { name, content, password, expiresInDays, enableMarkdown } = body;

  if (!isValidClipboardName(name)) {
    return jsonResponse({ error: '剪贴板名称无效（1-64 个字符，不能包含空格或斜杠）' }, 400);
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

  const hasPassword = typeof password === 'string' && password.trim() !== '';
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

// 校验密码；返回 'ok' | 'need_password' | 'wrong_password' | 'rate_limited'
async function checkClipboardPassword(request, row, password, name) {
  if (!row.password_hash) return 'ok';
  if (typeof password !== 'string' || !password) return 'need_password';
  if (!(await verifyPassword(password, row.password_hash))) {
    if (isRateLimited(getClientIp(request), 'pwd:' + name, RATE_LIMITS.passwordAttempt)) {
      return 'rate_limited';
    }
    return 'wrong_password';
  }
  return 'ok';
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

async function updateClipboard(body, request, env) {
  const { name, content, password } = body;
  if (!name || typeof content !== 'string') {
    return jsonResponse({ error: '参数不完整' }, 400);
  }
  if (content.length > MAX_CONTENT_LENGTH) {
    return jsonResponse({ error: '内容过长，最多 100KB' }, 413);
  }

  const row = await getExistingClipboard(env, name);
  if (!row) return jsonResponse({ error: '剪贴板不存在或已过期' }, 404);

  const auth = await checkClipboardPassword(request, row, password, name);
  if (auth === 'need_password') return jsonResponse({ error: '需要密码' }, 401);
  if (auth === 'wrong_password') return jsonResponse({ error: '密码错误' }, 403);
  if (auth === 'rate_limited') return jsonResponse({ error: '尝试次数过多，请稍后再试' }, 429);

  const now = Date.now();
  await env.DB.prepare(
    'UPDATE clipboards SET content = ?, updated_at = ? WHERE name = ?'
  ).bind(content, now, name).run();

  return jsonResponse({ success: true });
}

async function deleteClipboard(body, request, env) {
  const { name, password } = body;
  if (!name) return jsonResponse({ error: '缺少剪贴板名称' }, 400);

  const row = await getExistingClipboard(env, name);
  if (!row) return jsonResponse({ error: '剪贴板不存在或已过期' }, 404);

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
function getHomePage() {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>云剪贴板</title>
  <link rel="icon" href="data:,">
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-50 min-h-screen flex items-center justify-center">
  <div class="text-center px-4">
    <h1 class="text-5xl font-bold text-gray-900 mb-4">☁️ 云剪贴板</h1>
    <p class="text-xl text-gray-600">在地址栏输入 <code class="bg-gray-200 px-2 py-1 rounded">域名.com/剪贴板名</code> 即可新建或打开</p>
  </div>
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
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-50 min-h-screen flex items-center justify-center">
  <div class="max-w-md mx-auto bg-white rounded-xl shadow p-8">
    <h1 class="text-2xl font-bold mb-4">创建剪贴板需要验证</h1>
    <p class="text-gray-600 mb-6">请输入全局创建密码以继续</p>
    <form id="verifyForm">
      <input type="password" id="createPasswordInput" class="w-full border border-gray-300 rounded-lg px-3 py-2 mb-4" placeholder="密码">
      <button type="submit" id="verifyCreateBtn" class="w-full bg-blue-600 text-white py-2 rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed">验证</button>
      <p id="verifyError" class="text-red-500 mt-3"></p>
    </form>
  </div>
  <script>
    const name = ${safeJsonStringify(name)};
    const form = document.getElementById('verifyForm');
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const btn = document.getElementById('verifyCreateBtn');
      const errorEl = document.getElementById('verifyError');
      const password = document.getElementById('createPasswordInput').value;
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

function getCreatePage(name) {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>创建剪贴板 - ${escapeHtml(name)}</title>
  <link rel="icon" href="data:,">
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-50 min-h-screen py-12">
  <div class="max-w-2xl mx-auto bg-white rounded-xl shadow p-8">
    <h1 class="text-3xl font-bold mb-2">新建剪贴板</h1>
    <p class="text-gray-600 mb-6">名称：<strong>${escapeHtml(name)}</strong></p>
    <form id="createForm">
      <div class="mb-4">
        <label class="block text-sm font-medium text-gray-700 mb-1">内容</label>
        <textarea id="content" required class="w-full h-48 border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent" placeholder="粘贴或输入文本..."></textarea>
      </div>
      <div class="mb-4 flex items-center">
        <input type="checkbox" id="enableMarkdown" checked class="h-4 w-4 text-blue-600 border-gray-300 rounded focus:ring-blue-500">
        <label for="enableMarkdown" class="ml-2 block text-sm text-gray-700">启用 Markdown 渲染（支持 LaTeX、代码高亮等）</label>
      </div>
      <div class="mb-4">
        <label class="block text-sm font-medium text-gray-700 mb-1">访问密码（可选）</label>
        <input type="password" id="password" class="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent" placeholder="留空表示无密码">
      </div>
      <div class="mb-6">
        <label class="block text-sm font-medium text-gray-700 mb-1">自动删除时长</label>
        <select id="expiresInDays" class="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent">
          <option value="0">永不删除</option>
          <option value="1">1 天</option>
          <option value="3" selected>3 天</option>
          <option value="7">7 天</option>
          <option value="14">14 天</option>
          <option value="30">30 天</option>
        </select>
      </div>
      <button type="submit" class="w-full bg-blue-600 text-white py-2 rounded-lg hover:bg-blue-700 transition">创建剪贴板</button>
      <div class="error text-red-500 mt-3" id="error"></div>
    </form>
  </div>
  <script>
    const name = ${safeJsonStringify(name)};

    document.getElementById('createForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const errorEl = document.getElementById('error');
      errorEl.textContent = '';
      const content = document.getElementById('content').value;
      const password = document.getElementById('password').value;
      const expiresInDays = parseInt(document.getElementById('expiresInDays').value);
      const enableMarkdown = document.getElementById('enableMarkdown').checked;
      if (content.length > 102400) {
        errorEl.textContent = '内容过长（最多 100KB）';
        return;
      }
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
      }
    });
  </script>
</body>
</html>`;
}

function getOpenPage(meta) {
  const { name, hasPassword, createdAt, updatedAt, expiresInDays, enableMarkdown, inlineContent } = meta;
  const expiryText = expiresInDays === 0 ? '永不删除' : `${expiresInDays} 天后自动删除`;

  const markdownResources = enableMarkdown ? `
  <script src="https://cdn.jsdelivr.net/npm/markdown-it@13/dist/markdown-it.min.js"></script>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/katex@0.16.9/dist/katex.min.css">
  <script src="https://cdn.jsdelivr.net/npm/katex@0.16.9/dist/katex.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/markdown-it-texmath@1.0.0/texmath.min.js"></script>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@highlightjs/cdn-assets@11.9.0/styles/github.min.css">
  <script src="https://cdn.jsdelivr.net/npm/@highlightjs/cdn-assets@11.9.0/highlight.min.js"></script>
  ` : '';

  const markdownStyles = enableMarkdown ? `
    .markdown-body { line-height: 1.6; }
    .markdown-body pre { background: #f6f8fa; padding: 1em; border-radius: 6px; overflow-x: auto; }
    .katex { font-size: 1.1em; }
  ` : '';

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
  <script src="https://cdn.tailwindcss.com"></script>
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
    <div id="passwordSection" class="${hasPassword ? '' : 'hidden'}">
      <div class="max-w-md mx-auto mt-16 bg-white rounded-xl shadow p-8">
        <h2 class="text-2xl font-semibold mb-4">请输入密码</h2>
        <p class="text-gray-600 mb-6">剪贴板 <strong>${escapeHtml(name)}</strong> 受密码保护</p>
        <input type="password" id="passwordInput" class="w-full border border-gray-300 rounded-lg px-3 py-2 mb-4 focus:ring-2 focus:ring-blue-500" placeholder="密码">
        <button id="verifyBtn" class="w-full bg-blue-600 text-white py-2 rounded-lg hover:bg-blue-700">验证</button>
        <p id="passwordError" class="text-red-500 mt-3"></p>
      </div>
    </div>
    <div id="contentSection" class="${hasPassword ? 'hidden' : ''} flex-1 flex flex-col">
      <div class="bg-white border-b border-gray-200 px-4 py-3 flex items-center justify-between flex-wrap gap-2 shadow-sm">
        <div>
          <h1 class="text-xl font-bold">📋 ${escapeHtml(name)}</h1>
          <p class="text-xs text-gray-500">创建于 <span id="createdAtDisplay">${new Date(createdAt).toLocaleString()}</span> · ${expiryText}</p>
        </div>
        <div class="flex space-x-2">
          <button id="copyBtn" class="bg-gray-200 hover:bg-gray-300 text-gray-800 px-4 py-2 rounded-lg text-sm">复制</button>
          <button id="editBtn" class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg text-sm">编辑</button>
          <button id="deleteBtn" class="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-lg text-sm">删除</button>
        </div>
      </div>
      <div class="content-area p-6">
        <div id="warningBanner" class="warning-banner hidden"></div>
        <div id="previewMode">
          <div id="contentDisplay" class="bg-white rounded-xl shadow p-6 max-w-4xl mx-auto ${enableMarkdown ? 'markdown-body' : 'whitespace-pre-wrap'}"></div>
        </div>
        <div id="editMode" class="hidden">
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
            <button id="saveBtn" class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg text-sm">保存</button>
            <button id="cancelBtn" class="bg-gray-200 hover:bg-gray-300 text-gray-800 px-4 py-2 rounded-lg text-sm">取消</button>
          </div>
          <p id="editError" class="text-red-500 mt-3"></p>
        </div>
      </div>
    </div>
  </div>

  <script>
    const name = ${safeJsonStringify(name)};
    const hasPassword = ${hasPassword};
    const enableMarkdown = ${enableMarkdown};
    const inlineContent = ${inlineContentJs};
    const createdAt = ${createdAt};
    // 显示创建时间：跟随查看者系统时区，并附带时区标识（如 GMT+8）；
    // 服务端预渲染的 UTC 文本仅作为 JS 被禁用时的回退
    document.getElementById('createdAtDisplay').textContent =
      new Date(createdAt).toLocaleString(undefined, { timeZoneName: 'short' });
    let currentPassword = '';
    let originalContent = '';
    let renderAvailable = enableMarkdown;

    let md = null;
    if (enableMarkdown) {
      try {
        if (typeof window.markdownit !== 'undefined') {
          md = window.markdownit({
            html: false,
            linkify: true,
            highlight: function (str, lang) {
              if (typeof hljs !== 'undefined' && lang && hljs.getLanguage(lang)) {
                try { return hljs.highlight(str, { language: lang, ignoreIllegals: true }).value; } catch (__) {}
              }
              return '';
            }
          });
          if (typeof window.texmath !== 'undefined' && typeof window.katex !== 'undefined') {
            md.use(window.texmath, {
              engine: window.katex,
              delimiters: ['dollars', 'brackets'],
              katexOptions: { throwOnError: false }
            });
          }
        } else {
          renderAvailable = false;
        }
      } catch (e) {
        renderAvailable = false;
      }
    }

    function renderMarkdown(text) {
      if (!enableMarkdown || !renderAvailable || !md) return null;
      try { return md.render(text); } catch (e) { renderAvailable = false; return null; }
    }

    function showWarning(message) {
      const banner = document.getElementById('warningBanner');
      banner.textContent = message;
      banner.classList.remove('hidden');
    }

    function setContent(container, text) {
      if (enableMarkdown) {
        const rendered = renderMarkdown(text);
        if (rendered !== null) {
          container.innerHTML = rendered;
        } else {
          container.textContent = text;
          if (!renderAvailable) showWarning('⚠️ Markdown 渲染库加载失败，已显示原始文本。');
          else showWarning('⚠️ 渲染时出现错误，已显示原始文本。');
        }
      } else {
        container.textContent = text;
      }
    }

    function showPreview() {
      setContent(document.getElementById('contentDisplay'), originalContent);
      document.getElementById('previewMode').classList.remove('hidden');
      document.getElementById('editMode').classList.add('hidden');
    }

    function showEditor() {
      document.getElementById('editContent').value = originalContent;
      updateEditPreview();
      document.getElementById('previewMode').classList.add('hidden');
      document.getElementById('editMode').classList.remove('hidden');
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
      try {
        const res = await fetch('/api/get', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name, password })
        });
        const data = await parseJson(res);
        if (res.ok) {
          displayContent(data.content);
        } else if (res.status === 401) {
          document.getElementById('passwordSection').classList.remove('hidden');
          document.getElementById('contentSection').classList.add('hidden');
          document.getElementById('passwordError').textContent = data.error || '';
        } else if (res.status === 403) {
          document.getElementById('passwordError').textContent = data.error || '';
        } else {
          alert(data.error || '加载失败');
        }
      } catch (err) { alert('网络错误，请检查连接'); }
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

    document.getElementById('verifyBtn').addEventListener('click', async () => {
      const pwd = document.getElementById('passwordInput').value;
      if (!pwd) { document.getElementById('passwordError').textContent = '请输入密码'; return; }
      currentPassword = pwd;
      loadContent(pwd);
    });

    document.getElementById('copyBtn').addEventListener('click', copyContent);
    document.getElementById('editBtn').addEventListener('click', showEditor);
    document.getElementById('editContent').addEventListener('input', updateEditPreview);
    document.getElementById('cancelBtn').addEventListener('click', showPreview);

    document.getElementById('saveBtn').addEventListener('click', async () => {
      const content = document.getElementById('editContent').value;
      if (content.length > 102400) {
        document.getElementById('editError').textContent = '内容过长（最多 100KB）';
        return;
      }
      try {
        const res = await fetch('/api/update', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name, content, password: currentPassword })
        });
        const data = await parseJson(res);
        if (res.ok) {
          originalContent = content;
          showPreview();
        } else {
          document.getElementById('editError').textContent = data.error || '更新失败';
          if (res.status === 401 || res.status === 403) {
            document.getElementById('passwordSection').classList.remove('hidden');
            document.getElementById('contentSection').classList.add('hidden');
          }
        }
      } catch (err) { document.getElementById('editError').textContent = '网络错误，请检查连接'; }
    });

    document.getElementById('deleteBtn').addEventListener('click', async () => {
      if (!confirm('确定要删除这个剪贴板吗？此操作不可撤销。')) return;
      try {
        const res = await fetch('/api/delete', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name, password: currentPassword })
        });
        const data = await parseJson(res);
        if (res.ok) {
          window.location.href = '/';
        } else {
          alert(data.error || '删除失败');
          if (res.status === 401 || res.status === 403) {
            document.getElementById('passwordSection').classList.remove('hidden');
            document.getElementById('contentSection').classList.add('hidden');
          }
        }
      } catch (err) { alert('网络错误，请检查连接'); }
    });

    if (!hasPassword) {
      if (inlineContent !== null && inlineContent !== undefined) {
        displayContent(inlineContent);
      } else {
        loadContent('');
      }
    }
  </script>
</body>
</html>`;
}
