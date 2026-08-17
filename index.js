export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    const requirePassword = env.REQUIRE_PASSWORD === 'true';
    const allowedPasswords = parseAllowedPasswords(env.ALLOWED_PASSWORDS);

    // 处理 API 请求
    if (path.startsWith('/api/')) {
      return handleApiRequest(request, env, ctx, requirePassword, allowedPasswords);
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

    const data = await env.CLIPBOARD_KV.get(name, 'json');
    if (!data) {
      return new Response(getCreatePage(name, requirePassword, allowedPasswords), {
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
      });
    }

    const meta = {
      name,
      hasPassword: !!data.passwordHash,
      createdAt: data.createdAt,
      updatedAt: data.updatedAt,
      expiresInDays: data.expiresInDays
    };
    return new Response(getOpenPage(meta), {
      headers: { 'Content-Type': 'text/html; charset=utf-8' }
    });
  }
};

// ---------- API 处理 ----------
async function handleApiRequest(request, env, ctx, requirePassword, allowedPasswords) {
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

  if (path === '/api/create') return createClipboard(body, env, requirePassword, allowedPasswords);
  if (path === '/api/get') return getClipboardContent(body, env);
  if (path === '/api/update') return updateClipboard(body, env);
  if (path === '/api/delete') return deleteClipboard(body, env);

  return jsonResponse({ error: 'API endpoint not found' }, 404);
}

// ---------- 核心操作 ----------
async function createClipboard(body, env, requirePassword, allowedPasswords) {
  const { name, content, password, expiresInDays } = body;
  if (!name || typeof name !== 'string' || name.trim() === '') {
    return jsonResponse({ error: '剪贴板名称不能为空' }, 400);
  }
  if (typeof content !== 'string') {
    return jsonResponse({ error: '内容不能为空' }, 400);
  }

  const existing = await env.CLIPBOARD_KV.get(name, 'json');
  if (existing) return jsonResponse({ error: '剪贴板已存在，请直接打开' }, 409);

  const hasPassword = password && password.trim() !== '';
  if (requirePassword && !hasPassword) {
    return jsonResponse({ error: '此服务要求剪贴板必须设置密码' }, 400);
  }
  if (hasPassword && allowedPasswords.length > 0 && !allowedPasswords.includes(password)) {
    return jsonResponse({ error: '密码不在允许的列表中' }, 400);
  }

  let passwordHash = null;
  if (hasPassword) passwordHash = await sha256(password);

  const days = getValidExpiration(expiresInDays);
  const now = Date.now();
  const data = {
    content,
    passwordHash,
    createdAt: now,
    updatedAt: now,
    expiresInDays: days
  };

  const ttl = daysToSeconds(days);
  await env.CLIPBOARD_KV.put(name, JSON.stringify(data), ttl ? { expirationTtl: ttl } : {});

  return jsonResponse({ success: true, expiresInDays: days });
}

async function getClipboardContent(body, env) {
  const { name, password } = body;
  if (!name) return jsonResponse({ error: '缺少剪贴板名称' }, 400);

  const data = await env.CLIPBOARD_KV.get(name, 'json');
  if (!data) return jsonResponse({ error: '剪贴板不存在或已过期' }, 404);

  if (data.passwordHash) {
    if (!password) return jsonResponse({ error: '需要密码' }, 401);
    const hash = await sha256(password);
    if (hash !== data.passwordHash) return jsonResponse({ error: '密码错误' }, 403);
  }

  return jsonResponse({
    content: data.content,
    createdAt: data.createdAt,
    updatedAt: data.updatedAt,
    expiresInDays: data.expiresInDays,
    hasPassword: !!data.passwordHash
  });
}

async function updateClipboard(body, env) {
  const { name, content, password } = body;
  if (!name || typeof content !== 'string') return jsonResponse({ error: '参数不完整' }, 400);

  const data = await env.CLIPBOARD_KV.get(name, 'json');
  if (!data) return jsonResponse({ error: '剪贴板不存在' }, 404);

  if (data.passwordHash) {
    if (!password) return jsonResponse({ error: '需要密码' }, 401);
    const hash = await sha256(password);
    if (hash !== data.passwordHash) return jsonResponse({ error: '密码错误' }, 403);
  }

  data.content = content;
  data.updatedAt = Date.now();
  const ttl = daysToSeconds(data.expiresInDays);
  await env.CLIPBOARD_KV.put(name, JSON.stringify(data), ttl ? { expirationTtl: ttl } : {});

  return jsonResponse({ success: true });
}

async function deleteClipboard(body, env) {
  const { name, password } = body;
  if (!name) return jsonResponse({ error: '缺少剪贴板名称' }, 400);

  const data = await env.CLIPBOARD_KV.get(name, 'json');
  if (!data) return jsonResponse({ error: '剪贴板不存在' }, 404);

  if (data.passwordHash) {
    if (!password) return jsonResponse({ error: '需要密码' }, 401);
    const hash = await sha256(password);
    if (hash !== data.passwordHash) return jsonResponse({ error: '密码错误' }, 403);
  }

  await env.CLIPBOARD_KV.delete(name);
  return jsonResponse({ success: true });
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
  const validDays = [1, 3, 7, 14, 30];
  if (typeof days === 'number' && validDays.includes(days)) return days;
  return 3; // 默认 3 天
}

function daysToSeconds(days) {
  return days * 24 * 60 * 60;
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
    <p class="text-xl text-gray-600 mb-8">在地址栏输入 <code class="bg-gray-200 px-2 py-1 rounded">域名.com/剪贴板名</code> 即可新建或打开</p>
    <a href="/example" class="inline-block bg-blue-600 text-white px-6 py-3 rounded-lg hover:bg-blue-700 transition">试试 /example</a>
  </div>
</body>
</html>`;
}

function getCreatePage(name, requirePassword, allowedPasswords) {
  const requireAttr = requirePassword ? 'required' : '';
  const allowedListJson = JSON.stringify(allowedPasswords);
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
        <label class="block text-sm font-medium text-gray-700 mb-1">内容（支持 Markdown + LaTeX）</label>
        <textarea id="content" required class="w-full h-48 border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent" placeholder="粘贴或输入文本..."></textarea>
      </div>
      <div class="mb-4">
        <label class="block text-sm font-medium text-gray-700 mb-1">密码${requirePassword ? '（必填）' : '（可选）'}</label>
        <input type="text" id="password" ${requireAttr} class="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent" placeholder="留空表示无密码">
        <div class="hint text-sm text-gray-500 mt-1" id="passwordHint"></div>
      </div>
      <div class="mb-6">
        <label class="block text-sm font-medium text-gray-700 mb-1">自动删除时长</label>
        <select id="expiresInDays" class="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent">
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
    const requirePassword = ${requirePassword};
    const allowedPasswords = ${allowedListJson};
    const passwordHint = document.getElementById('passwordHint');
    if (allowedPasswords.length > 0) {
      passwordHint.textContent = '允许的密码：' + allowedPasswords.join(', ');
    } else if (requirePassword) {
      passwordHint.textContent = '此服务要求必须设置密码';
    }
    document.getElementById('createForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const errorEl = document.getElementById('error');
      errorEl.textContent = '';
      const content = document.getElementById('content').value;
      const password = document.getElementById('password').value;
      const expiresInDays = parseInt(document.getElementById('expiresInDays').value);
      try {
        const res = await fetch('/api/create', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name, content, password, expiresInDays })
        });
        const data = await res.json();
        if (res.ok) {
          window.location.href = '/' + encodeURIComponent(name);
        } else {
          errorEl.textContent = data.error || '创建失败';
        }
      } catch (err) {
        errorEl.textContent = '网络错误';
      }
    });
  </script>
</body>
</html>`;
}

function getOpenPage(meta) {
  const { name, hasPassword, createdAt, updatedAt, expiresInDays } = meta;
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>剪贴板 - ${escapeHtml(name)}</title>
  <!-- Tailwind CSS -->
  <script src="https://cdn.tailwindcss.com"></script>
  <!-- markdown-it -->
  <script src="https://cdn.jsdelivr.net/npm/markdown-it@13/dist/markdown-it.min.js"></script>
  <!-- KaTeX -->
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/katex@0.16.9/dist/katex.min.css">
  <script src="https://cdn.jsdelivr.net/npm/katex@0.16.9/dist/katex.min.js"></script>
  <!-- markdown-it-texmath 插件 -->
  <script src="https://cdn.jsdelivr.net/npm/markdown-it-texmath@1.0.0/texmath.min.js"></script>
  <!-- highlight.js 代码高亮 -->
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/highlight.js@11.9.0/styles/github.min.css">
  <script src="https://cdn.jsdelivr.net/npm/highlight.js@11.9.0/lib/common.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/highlight.js@11.9.0/lib/markdown.min.js"></script>
  <style>
    .markdown-body { line-height: 1.6; }
    .markdown-body pre { background: #f6f8fa; padding: 1em; border-radius: 6px; overflow-x: auto; }
    .katex { font-size: 1.1em; }
    /* 全屏布局 */
    body, html { height: 100%; }
    .app-container { min-height: 100vh; display: flex; flex-direction: column; }
    .content-area { flex: 1; overflow-y: auto; }
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
      <!-- 顶部工具栏 -->
      <div class="bg-white border-b border-gray-200 px-4 py-3 flex items-center justify-between flex-wrap gap-2 shadow-sm">
        <div>
          <h1 class="text-xl font-bold">📋 ${escapeHtml(name)}</h1>
          <p class="text-xs text-gray-500">创建于 ${new Date(createdAt).toLocaleString()} · ${expiresInDays} 天后自动删除</p>
        </div>
        <div class="flex space-x-2">
          <button id="copyBtn" class="bg-gray-200 hover:bg-gray-300 text-gray-800 px-4 py-2 rounded-lg text-sm">复制</button>
          <button id="editBtn" class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg text-sm">编辑</button>
          <button id="deleteBtn" class="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-lg text-sm">删除</button>
        </div>
      </div>
      <!-- 内容区域（全屏） -->
      <div class="content-area p-6">
        <div id="previewMode">
          <div id="contentDisplay" class="markdown-body bg-white rounded-xl shadow p-6 max-w-4xl mx-auto"></div>
        </div>
        <div id="editMode" class="hidden">
          <div class="edit-container flex gap-4 max-w-6xl mx-auto">
            <div class="flex-1">
              <label class="block text-sm font-medium mb-1">编辑内容</label>
              <textarea id="editContent" class="w-full h-[70vh] border border-gray-300 rounded-lg px-3 py-2 font-mono focus:ring-2 focus:ring-blue-500"></textarea>
            </div>
            <div class="flex-1">
              <label class="block text-sm font-medium mb-1">实时预览</label>
              <div id="editPreview" class="markdown-body bg-white rounded-xl shadow p-4 h-[70vh] overflow-y-auto"></div>
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
    let currentPassword = '';
    let originalMarkdown = '';

    // 初始化 markdown-it
    const md = window.markdownit({
      html: false,
      linkify: true,
      highlight: function (str, lang) {
        if (lang && hljs.getLanguage(lang)) {
          try {
            return hljs.highlight(str, { language: lang }).value;
          } catch (__) {}
        }
        return '';
      }
    }).use(window.texmath, {
      engine: window.katex,
      delimiters: ['dollars', 'brackets'],
      katexOptions: { throwOnError: false }
    });

    function renderMarkdown(text) {
      return md.render(text);
    }

    function showPreview() {
      document.getElementById('contentDisplay').innerHTML = renderMarkdown(originalMarkdown);
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
      document.getElementById('editPreview').innerHTML = renderMarkdown(text);
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
      } catch (err) {
        alert('网络错误');
      }
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
      if (!pwd) {
        document.getElementById('passwordError').textContent = '请输入密码';
        return;
      }
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
      } catch (err) {
        document.getElementById('editError').textContent = '网络错误';
      }
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
      } catch (err) {
        alert('网络错误');
      }
    });

    // 初始加载
    if (!hasPassword) {
      loadContent('');
    }
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