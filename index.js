export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // 读取配置
    const createVerificationEnabled = env.CREATE_PASSWORD === 'true'; // 是否启用创建验证
    const allowedCreatePasswords = parseAllowedPasswords(env.ALLOWED_PASSWORDS); // 允许通过创建验证的密码列表

    // 处理 API 请求
    if (path.startsWith('/api/')) {
      return handleApiRequest(request, env, ctx, createVerificationEnabled, allowedCreatePasswords);
    }

    // 首页
    if (path === '/') {
      return new Response(getHomePage(), {
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
      });
    }

    // 剪贴板页面
    const name = decodeURIComponent(path.slice(1));
    if (name.includes('/')) {
      return new Response('Not Found', { status: 404 });
    }

    // 检查剪贴板是否存在
    const row = await env.DB.prepare(
      'SELECT name, password_hash, created_at, updated_at, expires_in_days, expires_at, enable_markdown FROM clipboards WHERE name = ?'
    ).bind(name).first();

    if (!row) {
      // 剪贴板不存在
      if (createVerificationEnabled) {
        return new Response(getVerifyPage(name), {
          headers: { 'Content-Type': 'text/html; charset=utf-8' }
        });
      } else {
        return new Response(getCreatePage(name, false), {
          headers: { 'Content-Type': 'text/html; charset=utf-8' }
        });
      }
    }

    // 检查是否过期（惰性删除）
    if (row.expires_at !== null && row.expires_at <= Date.now()) {
      await env.DB.prepare('DELETE FROM clipboards WHERE name = ?').bind(name).run();
      if (createVerificationEnabled) {
        return new Response(getVerifyPage(name), {
          headers: { 'Content-Type': 'text/html; charset=utf-8' }
        });
      } else {
        return new Response(getCreatePage(name, false), {
          headers: { 'Content-Type': 'text/html; charset=utf-8' }
        });
      }
    }

    const meta = {
      name,
      hasPassword: !!row.password_hash,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      expiresInDays: row.expires_in_days,
      enableMarkdown: row.enable_markdown === 1
    };
    return new Response(getOpenPage(meta), {
      headers: { 'Content-Type': 'text/html; charset=utf-8' }
    });
  },

  // 定时清理过期剪贴板和令牌（每小时执行）
  async scheduled(event, env, ctx) {
    await cleanupExpiredData(env);
  }
};

// ---------- API 处理 ----------
async function handleApiRequest(request, env, ctx, createVerificationEnabled, allowedCreatePasswords) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  if (method !== 'POST') {
    return jsonResponse({ error: 'Method not allowed' }, 405);
  }

  let body;
  try {
    body = await request.json();
  } catch (e) {
    return jsonResponse({ error: 'Invalid JSON' }, 400);
  }

  if (path === '/api/verify-create') {
    return verifyCreatePassword(body, env, createVerificationEnabled, allowedCreatePasswords);
  }
  if (path === '/api/create') {
    return createClipboard(body, env, createVerificationEnabled);
  }
  if (path === '/api/get') {
    return getClipboardContent(body, env);
  }
  if (path === '/api/update') {
    return updateClipboard(body, env);
  }
  if (path === '/api/delete') {
    return deleteClipboard(body, env);
  }

  return jsonResponse({ error: 'API endpoint not found' }, 404);
}

// ---------- 核心操作 ----------
async function verifyCreatePassword(body, env, createVerificationEnabled, allowedCreatePasswords) {
  const { password } = body;
  if (!createVerificationEnabled) {
    return jsonResponse({ error: '未启用创建验证' }, 400);
  }
  if (!password) {
    return jsonResponse({ error: '请输入密码' }, 400);
  }
  // 检查密码是否在允许列表中
  if (allowedCreatePasswords.length > 0 && !allowedCreatePasswords.includes(password)) {
    return jsonResponse({ error: '密码错误' }, 403);
  }
  // 如果启用验证但允许列表为空，则拒绝（配置错误）
  if (allowedCreatePasswords.length === 0) {
    return jsonResponse({ error: '验证配置错误，请联系管理员' }, 500);
  }

  // 生成随机令牌，存入数据库，有效期10分钟
  const token = crypto.randomUUID();
  const now = Date.now();
  const expiresAt = now + 10 * 60 * 1000; // 10分钟
  await env.DB.prepare(
    'INSERT INTO create_tokens (token, created_at, expires_at) VALUES (?, ?, ?)'
  ).bind(token, now, expiresAt).run();

  return jsonResponse({ success: true, token });
}

async function createClipboard(body, env, createVerificationEnabled) {
  const { name, content, password, expiresInDays, enableMarkdown, token } = body;
  if (!name || typeof name !== 'string' || name.trim() === '') {
    return jsonResponse({ error: '剪贴板名称不能为空' }, 400);
  }
  if (typeof content !== 'string') {
    return jsonResponse({ error: '内容不能为空' }, 400);
  }

  // 如果启用了创建验证，则必须验证 token
  if (createVerificationEnabled) {
    if (!token) {
      return jsonResponse({ error: '缺少创建令牌' }, 401);
    }
    const tokenRow = await env.DB.prepare(
      'SELECT expires_at FROM create_tokens WHERE token = ?'
    ).bind(token).first();
    if (!tokenRow || tokenRow.expires_at <= Date.now()) {
      return jsonResponse({ error: '创建令牌无效或已过期' }, 401);
    }
    // 验证通过后删除令牌（一次性使用）
    await env.DB.prepare('DELETE FROM create_tokens WHERE token = ?').bind(token).run();
  }

  const hasPassword = password && password.trim() !== '';
  let passwordHash = null;
  if (hasPassword) {
    passwordHash = await sha256(password);
  }

  const days = getValidExpiration(expiresInDays);
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

  return jsonResponse({ success: true, expiresInDays: days, enableMarkdown: markdownEnabled === 1 });
}

async function getClipboardContent(body, env) {
  const { name, password } = body;
  if (!name) return jsonResponse({ error: '缺少剪贴板名称' }, 400);

  const row = await env.DB.prepare(
    'SELECT content, password_hash, created_at, updated_at, expires_in_days, expires_at, enable_markdown FROM clipboards WHERE name = ?'
  ).bind(name).first();

  if (!row) {
    return jsonResponse({ error: '剪贴板不存在或已过期' }, 404);
  }

  if (row.expires_at !== null && row.expires_at <= Date.now()) {
    await env.DB.prepare('DELETE FROM clipboards WHERE name = ?').bind(name).run();
    return jsonResponse({ error: '剪贴板不存在或已过期' }, 404);
  }

  if (row.password_hash) {
    if (!password) return jsonResponse({ error: '需要密码' }, 401);
    const hash = await sha256(password);
    if (hash !== row.password_hash) return jsonResponse({ error: '密码错误' }, 403);
  }

  return jsonResponse({
    content: row.content,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    expiresInDays: row.expires_in_days,
    hasPassword: !!row.password_hash,
    enableMarkdown: row.enable_markdown === 1
  });
}

async function updateClipboard(body, env) {
  const { name, content, password } = body;
  if (!name || typeof content !== 'string') return jsonResponse({ error: '参数不完整' }, 400);

  const row = await env.DB.prepare(
    'SELECT password_hash, expires_in_days, expires_at FROM clipboards WHERE name = ?'
  ).bind(name).first();

  if (!row) return jsonResponse({ error: '剪贴板不存在' }, 404);

  if (row.expires_at !== null && row.expires_at <= Date.now()) {
    await env.DB.prepare('DELETE FROM clipboards WHERE name = ?').bind(name).run();
    return jsonResponse({ error: '剪贴板不存在' }, 404);
  }

  if (row.password_hash) {
    if (!password) return jsonResponse({ error: '需要密码' }, 401);
    const hash = await sha256(password);
    if (hash !== row.password_hash) return jsonResponse({ error: '密码错误' }, 403);
  }

  const now = Date.now();
  await env.DB.prepare(
    'UPDATE clipboards SET content = ?, updated_at = ? WHERE name = ?'
  ).bind(content, now, name).run();

  return jsonResponse({ success: true });
}

async function deleteClipboard(body, env) {
  const { name, password } = body;
  if (!name) return jsonResponse({ error: '缺少剪贴板名称' }, 400);

  const row = await env.DB.prepare(
    'SELECT password_hash, expires_at FROM clipboards WHERE name = ?'
  ).bind(name).first();

  if (!row) return jsonResponse({ error: '剪贴板不存在' }, 404);

  if (row.expires_at !== null && row.expires_at <= Date.now()) {
    await env.DB.prepare('DELETE FROM clipboards WHERE name = ?').bind(name).run();
    return jsonResponse({ error: '剪贴板不存在' }, 404);
  }

  if (row.password_hash) {
    if (!password) return jsonResponse({ error: '需要密码' }, 401);
    const hash = await sha256(password);
    if (hash !== row.password_hash) return jsonResponse({ error: '密码错误' }, 403);
  }

  await env.DB.prepare('DELETE FROM clipboards WHERE name = ?').bind(name).run();
  return jsonResponse({ success: true });
}

// ---------- 定时清理 ----------
async function cleanupExpiredData(env) {
  const now = Date.now();
  try {
    // 清理过期剪贴板
    const result = await env.DB.prepare(
      'DELETE FROM clipboards WHERE expires_at IS NOT NULL AND expires_at <= ?'
    ).bind(now).run();
    console.log(`Cleaned up ${result.changes} expired clipboards`);

    // 清理过期创建令牌
    const tokenResult = await env.DB.prepare(
      'DELETE FROM create_tokens WHERE expires_at <= ?'
    ).bind(now).run();
    console.log(`Cleaned up ${tokenResult.changes} expired create tokens`);
  } catch (err) {
    console.error('Cleanup failed:', err);
  }
}

// ---------- 辅助函数 ----------
function jsonResponse(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8' }
  });
}

async function sha256(text) {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function getValidExpiration(days) {
  const validDays = [0, 1, 3, 7, 14, 30];
  if (typeof days === 'number' && validDays.includes(days)) {
    return days;
  }
  return 3; // 默认 3 天
}

function daysToMillis(days) {
  return days * 24 * 60 * 60 * 1000;
}

function parseAllowedPasswords(str) {
  if (!str || typeof str !== 'string') return [];
  try {
    const arr = JSON.parse(str);
    if (Array.isArray(arr)) return arr.filter(item => typeof item === 'string' && item.trim() !== '');
  } catch (e) {}
  return [];
}

// ---------- HTML 页面 ----------
function getHomePage() {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>云剪贴板</title>
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

// 验证密码页面
function getVerifyPage(name) {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>验证 - ${escapeHtml(name)}</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-50 min-h-screen flex items-center justify-center">
  <div class="max-w-md mx-auto bg-white rounded-xl shadow p-8">
    <h1 class="text-2xl font-bold mb-4">创建剪贴板需要验证</h1>
    <p class="text-gray-600 mb-6">请输入全局创建密码以继续</p>
    <input type="password" id="createPasswordInput" class="w-full border border-gray-300 rounded-lg px-3 py-2 mb-4" placeholder="密码">
    <button id="verifyCreateBtn" class="w-full bg-blue-600 text-white py-2 rounded-lg hover:bg-blue-700">验证</button>
    <p id="verifyError" class="text-red-500 mt-3"></p>
  </div>
  <script>
    const name = ${JSON.stringify(name)};
    document.getElementById('verifyCreateBtn').addEventListener('click', async () => {
      const password = document.getElementById('createPasswordInput').value;
      if (!password) {
        document.getElementById('verifyError').textContent = '请输入密码';
        return;
      }
      try {
        const res = await fetch('/api/verify-create', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ password })
        });
        const data = await res.json();
        if (res.ok) {
          window.location.href = '/' + encodeURIComponent(name) + '?token=' + encodeURIComponent(data.token);
        } else {
          document.getElementById('verifyError').textContent = data.error || '验证失败';
        }
      } catch (err) {
        document.getElementById('verifyError').textContent = '网络错误';
      }
    });
  </script>
</body>
</html>`;
}

// 创建页面（无需 requirePassword 参数，密码字段仅为可选剪贴板访问密码）
function getCreatePage(name, isVerified) {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>创建剪贴板 - ${escapeHtml(name)}</title>
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
        <input type="text" id="password" class="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent" placeholder="留空表示无密码">
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
    const name = ${JSON.stringify(name)};
    // 从 URL 获取 token（如果有）
    const urlParams = new URLSearchParams(window.location.search);
    const createToken = urlParams.get('token') || '';

    document.getElementById('createForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const errorEl = document.getElementById('error');
      errorEl.textContent = '';
      const content = document.getElementById('content').value;
      const password = document.getElementById('password').value;
      const expiresInDays = parseInt(document.getElementById('expiresInDays').value);
      const enableMarkdown = document.getElementById('enableMarkdown').checked;
      try {
        const res = await fetch('/api/create', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name, content, password, expiresInDays, enableMarkdown, token: createToken })
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

// 打开剪贴板页面（与之前相同）
function getOpenPage(meta) {
  const { name, hasPassword, createdAt, updatedAt, expiresInDays, enableMarkdown } = meta;
  const expiryText = expiresInDays === 0 ? '永不删除' : `${expiresInDays} 天后自动删除`;

  const markdownResources = enableMarkdown ? `
  <script src="https://cdn.jsdelivr.net/npm/markdown-it@13/dist/markdown-it.min.js"></script>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/katex@0.16.9/dist/katex.min.css">
  <script src="https://cdn.jsdelivr.net/npm/katex@0.16.9/dist/katex.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/markdown-it-texmath@1.0.0/texmath.min.js"></script>
  <link rel="stylesheet" href="https://unpkg.com/@highlightjs/cdn-assets@11.9.0/styles/github.min.css">
  <script src="https://unpkg.com/@highlightjs/cdn-assets@11.9.0/highlight.min.js"></script>
  ` : '';

  const markdownStyles = enableMarkdown ? `
    .markdown-body { line-height: 1.6; }
    .markdown-body pre { background: #f6f8fa; padding: 1em; border-radius: 6px; overflow-x: auto; }
    .katex { font-size: 1.1em; }
  ` : '';

  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>剪贴板 - ${escapeHtml(name)}</title>
  <script src="https://cdn.tailwindcss.com"></script>
  ${markdownResources}
  <style>
    ${markdownStyles}
    body, html { height: 100%; }
    .app-container { min-height: 100vh; display: flex; flex-direction: column; }
    .content-area { flex: 1; overflow-y: auto; }
    .warning-banner { background: #fef3c7; border: 1px solid #f59e0b; color: #92400e; padding: 10px; border-radius: 8px; margin-bottom: 15px; }
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
          <p class="text-xs text-gray-500">创建于 ${new Date(createdAt).toLocaleString()} · ${expiryText}</p>
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
    const name = ${JSON.stringify(name)};
    const hasPassword = ${hasPassword};
    const enableMarkdown = ${enableMarkdown};
    let currentPassword = '';
    let originalMarkdown = '';
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
      setContent(document.getElementById('contentDisplay'), originalMarkdown);
      document.getElementById('previewMode').classList.remove('hidden');
      document.getElementById('editMode').classList.add('hidden');
    }

    function showEditor() {
      document.getElementById('editContent').value = originalMarkdown;
      updateEditPreview();
      document.getElementById('previewMode').classList.add('hidden');
      document.getElementById('editMode').classList.remove('hidden');
    }

    function updateEditPreview() {
      const text = document.getElementById('editContent').value;
      setContent(document.getElementById('editPreview'), text);
    }

    async function loadContent(password = '') {
      try {
        const res = await fetch('/api/get', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name, password })
        });
        const data = await res.json();
        if (res.ok) {
          originalMarkdown = data.content;
          document.getElementById('passwordSection').classList.add('hidden');
          document.getElementById('contentSection').classList.remove('hidden');
          showPreview();
        } else {
          if (res.status === 401) {
            document.getElementById('passwordSection').classList.remove('hidden');
            document.getElementById('contentSection').classList.add('hidden');
            document.getElementById('passwordError').textContent = data.error || '';
          } else if (res.status === 403) {
            document.getElementById('passwordError').textContent = data.error || '';
          } else {
            alert(data.error || '加载失败');
          }
        }
      } catch (err) { alert('网络错误，请检查连接'); }
    }

    async function copyContent() {
      try {
        await navigator.clipboard.writeText(originalMarkdown);
        const btn = document.getElementById('copyBtn');
        btn.textContent = '已复制';
        setTimeout(() => btn.textContent = '复制', 2000);
      } catch (err) {
        const textarea = document.createElement('textarea');
        textarea.value = originalMarkdown;
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
      try {
        const res = await fetch('/api/update', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name, content, password: currentPassword })
        });
        const data = await res.json();
        if (res.ok) {
          originalMarkdown = content;
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
        const data = await res.json();
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

    if (!hasPassword) { loadContent(''); }
  </script>
</body>
</html>`;
}

function escapeHtml(str) {
  return str.replace(/[&<>"']/g, function(m) {
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