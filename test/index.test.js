// 云剪贴板自动化测试（node test/index.test.js，需 Node 18+）
// 使用内存 Mock 模拟 D1，直接调用 Worker 的 fetch/scheduled，无需网络。
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import worker, { _resetRateLimitsForTest } from '../index.js';

const BASE = 'https://clipboard.example.com';

// 每个测试前清空限速桶，避免测试间互相污染
beforeEach(() => {
  _resetRateLimitsForTest();
});

// ---------- 内存 D1 Mock（仅支持本项目用到的 SQL 语句）----------
class MockDb {
  constructor() {
    this.clipboards = new Map();
    this.tokens = new Map();
  }

  prepare(sql) {
    return {
      bind: (...args) => ({
        run: () => this.run(sql, args),
        first: () => this.first(sql, args)
      })
    };
  }

  run(sql, args) {
    if (sql.startsWith('INSERT INTO clipboards')) {
      const [name, content, password_hash, created_at, updated_at, expires_in_days, expires_at, enable_markdown] = args;
      if (this.clipboards.has(name)) throw new Error('UNIQUE constraint failed: clipboards.name');
      this.clipboards.set(name, { name, content, password_hash, created_at, updated_at, expires_in_days, expires_at, enable_markdown });
      return { success: true, meta: { changes: 1 } };
    }
    if (sql.startsWith('INSERT INTO create_tokens')) {
      const [token, name, created_at, expires_at] = args;
      this.tokens.set(token, { token, name, created_at, expires_at });
      return { success: true, meta: { changes: 1 } };
    }
    if (sql.startsWith('DELETE FROM clipboards WHERE name')) {
      const before = this.clipboards.size;
      this.clipboards.delete(args[0]);
      return { success: true, meta: { changes: before - this.clipboards.size } };
    }
    if (sql.startsWith('DELETE FROM clipboards WHERE expires_at')) {
      const now = args[0];
      let changes = 0;
      for (const [key, row] of this.clipboards) {
        if (row.expires_at !== null && row.expires_at <= now) { this.clipboards.delete(key); changes++; }
      }
      return { success: true, meta: { changes } };
    }
    if (sql.startsWith('DELETE FROM create_tokens WHERE token')) {
      const before = this.tokens.size;
      this.tokens.delete(args[0]);
      return { success: true, meta: { changes: before - this.tokens.size } };
    }
    if (sql.startsWith('DELETE FROM create_tokens WHERE expires_at')) {
      const now = args[0];
      let changes = 0;
      for (const [key, row] of this.tokens) {
        if (row.expires_at <= now) { this.tokens.delete(key); changes++; }
      }
      return { success: true, meta: { changes } };
    }
    if (sql.startsWith('UPDATE clipboards')) {
      const [content, updated_at, name] = args;
      const row = this.clipboards.get(name);
      if (!row) return { success: true, meta: { changes: 0 } };
      row.content = content;
      row.updated_at = updated_at;
      return { success: true, meta: { changes: 1 } };
    }
    throw new Error('MockDb: unexpected SQL in run(): ' + sql);
  }

  first(sql, args) {
    if (sql.includes('FROM clipboards WHERE name')) {
      const row = this.clipboards.get(args[0]);
      return row ? { ...row } : null;
    }
    if (sql.includes('FROM create_tokens WHERE token')) {
      const row = this.tokens.get(args[0]);
      return row ? { ...row } : null;
    }
    throw new Error('MockDb: unexpected SQL in first(): ' + sql);
  }
}

function makeEnv(overrides = {}) {
  return { DB: new MockDb(), ...overrides };
}

// 模拟浏览器同源 POST（带 Origin 与 JSON Content-Type）
async function callApi(env, path, body, options = {}) {
  const headers = {
    'Content-Type': 'application/json',
    Origin: BASE,
    ...(options.headers || {})
  };
  if (options.omitOrigin) delete headers.Origin;
  const request = new Request(BASE + path, {
    method: options.method || 'POST',
    headers,
    body: options.rawBody !== undefined ? options.rawBody : (body !== undefined ? JSON.stringify(body) : undefined)
  });
  return worker.fetch(request, env, {});
}

async function getPage(env, path, headers = {}) {
  const request = new Request(BASE + path, { headers });
  return worker.fetch(request, env, {});
}

async function createClipboard(env, name, content, bodyExtra = {}, options = {}) {
  return callApi(env, '/api/create', { name, content, ...bodyExtra }, options);
}

// ---------- 测试：API 基础 ----------
test('创建并读取无密码剪贴板', async () => {
  const env = makeEnv();
  const res = await createClipboard(env, 'hello', 'hello world', { enableMarkdown: false });
  assert.equal(res.status, 200);
  const get = await callApi(env, '/api/get', { name: 'hello' });
  assert.equal(get.status, 200);
  const data = await get.json();
  assert.equal(data.content, 'hello world');
  assert.equal(data.enableMarkdown, false);
  assert.equal(data.hasPassword, false);
});

test('默认启用 Markdown', async () => {
  const env = makeEnv();
  const res = await createClipboard(env, 'md-default', 'x');
  const data = await res.json();
  assert.equal(data.enableMarkdown, true);
});

test('名称冲突返回 409', async () => {
  const env = makeEnv();
  await createClipboard(env, 'dup', 'one');
  const res = await createClipboard(env, 'dup', 'two');
  assert.equal(res.status, 409);
});

test('null JSON 请求体返回 400（不再 500）', async () => {
  const env = makeEnv();
  const res = await callApi(env, '/api/get', null);
  assert.equal(res.status, 400);
});

test('非对象 JSON 请求体返回 400', async () => {
  const env = makeEnv();
  assert.equal((await callApi(env, '/api/create', 123)).status, 400);
  assert.equal((await callApi(env, '/api/create', 'text')).status, 400);
  assert.equal((await callApi(env, '/api/create', [1, 2])).status, 400);
});

test('非法 JSON 请求体返回 400', async () => {
  const env = makeEnv();
  const res = await callApi(env, '/api/create', undefined, { rawBody: 'not-json{' });
  assert.equal(res.status, 400);
});

test('空白内容创建被拒绝', async () => {
  const env = makeEnv();
  const res = await createClipboard(env, 'empty', '   ');
  assert.equal(res.status, 400);
});

test('内容超过 100KB 被拒绝', async () => {
  const env = makeEnv();
  const res = await createClipboard(env, 'big', 'x'.repeat(102401));
  assert.equal(res.status, 413);
});

test('无效过期天数被拒绝（不再静默回退）', async () => {
  const env = makeEnv();
  assert.equal((await createClipboard(env, 'e1', 'x', { expiresInDays: 5 })).status, 400);
  assert.equal((await createClipboard(env, 'e2', 'x', { expiresInDays: '7' })).status, 400);
});

test('非法名称被拒绝', async () => {
  const env = makeEnv();
  assert.equal((await createClipboard(env, 'a/b', 'x')).status, 400);
  assert.equal((await createClipboard(env, 'a b', 'x')).status, 400);
  assert.equal((await createClipboard(env, '  padded  ', 'x')).status, 400);
  assert.equal((await createClipboard(env, 'x'.repeat(65), 'x')).status, 400);
});

test('密码为非字符串返回 400（不再 500）', async () => {
  const env = makeEnv();
  const res = await createClipboard(env, 'pw-type', 'x', { password: 123 });
  assert.equal(res.status, 400);
});

test('GET 请求 API 返回 405', async () => {
  const env = makeEnv();
  const res = await callApi(env, '/api/get', undefined, { method: 'GET' });
  assert.equal(res.status, 405);
});

test('未知 API 端点返回 404', async () => {
  const env = makeEnv();
  const res = await callApi(env, '/api/unknown', {});
  assert.equal(res.status, 404);
});

// ---------- 测试：密码保护 ----------
test('密码保护：读取/更新/删除均需正确密码', async () => {
  const env = makeEnv();
  await createClipboard(env, 'secret-clip', 'secret content', { password: 'hunter2' });

  let res = await callApi(env, '/api/get', { name: 'secret-clip' });
  assert.equal(res.status, 401);
  res = await callApi(env, '/api/get', { name: 'secret-clip', password: 'wrong' });
  assert.equal(res.status, 403);
  res = await callApi(env, '/api/get', { name: 'secret-clip', password: 'hunter2' });
  assert.equal(res.status, 200);
  assert.equal((await res.json()).content, 'secret content');

  res = await callApi(env, '/api/update', { name: 'secret-clip', content: 'new', password: 'wrong' });
  assert.equal(res.status, 403);
  res = await callApi(env, '/api/update', { name: 'secret-clip', content: 'new content', password: 'hunter2' });
  assert.equal(res.status, 200);

  res = await callApi(env, '/api/delete', { name: 'secret-clip', password: 'wrong' });
  assert.equal(res.status, 403);
  res = await callApi(env, '/api/delete', { name: 'secret-clip', password: 'hunter2' });
  assert.equal(res.status, 200);
  res = await callApi(env, '/api/get', { name: 'secret-clip', password: 'hunter2' });
  assert.equal(res.status, 404);
});

test('密码使用带盐 PBKDF2 哈希存储', async () => {
  const env = makeEnv();
  await createClipboard(env, 'salt1', 'x', { password: 'same-password' });
  await createClipboard(env, 'salt2', 'x', { password: 'same-password' });
  const h1 = env.DB.clipboards.get('salt1').password_hash;
  const h2 = env.DB.clipboards.get('salt2').password_hash;
  assert.notEqual(h1, h2); // 同密码不同盐 → 哈希不同
  assert.equal(h1.split(':').length, 3); // 格式：salt:iterations:hash
  const res = await callApi(env, '/api/get', { name: 'salt1', password: 'same-password' });
  assert.equal(res.status, 200);
});

// ---------- 测试：过期与清理 ----------
test('过期剪贴板读取时被惰性删除', async () => {
  const env = makeEnv();
  env.DB.clipboards.set('gone', {
    name: 'gone', content: 'x', password_hash: null,
    created_at: 1, updated_at: 1, expires_in_days: 1,
    expires_at: Date.now() - 1000, enable_markdown: 0
  });
  const res = await callApi(env, '/api/get', { name: 'gone' });
  assert.equal(res.status, 404);
  assert.equal(env.DB.clipboards.has('gone'), false);
});

test('scheduled 清理过期剪贴板与令牌（并记录 meta.changes）', async () => {
  const env = makeEnv();
  env.DB.clipboards.set('expired', {
    name: 'expired', content: 'x', password_hash: null, created_at: 1, updated_at: 1,
    expires_in_days: 1, expires_at: Date.now() - 1000, enable_markdown: 0
  });
  env.DB.clipboards.set('keep', {
    name: 'keep', content: 'x', password_hash: null, created_at: 1, updated_at: 1,
    expires_in_days: 0, expires_at: null, enable_markdown: 0
  });
  env.DB.tokens.set('old-token', { token: 'old-token', name: 'n', created_at: 1, expires_at: Date.now() - 1000 });
  env.DB.tokens.set('new-token', { token: 'new-token', name: 'n', created_at: 1, expires_at: Date.now() + 60000 });
  await worker.scheduled({}, env, {});
  assert.equal(env.DB.clipboards.has('expired'), false);
  assert.equal(env.DB.clipboards.has('keep'), true);
  assert.equal(env.DB.tokens.has('old-token'), false);
  assert.equal(env.DB.tokens.has('new-token'), true);
});

// ---------- 测试：创建验证（Cookie 令牌流程）----------
test('未启用创建验证时验证接口返回 400', async () => {
  const env = makeEnv();
  const res = await callApi(env, '/api/verify-create', { name: 'n', password: 'x' });
  assert.equal(res.status, 400);
});

test('创建验证：密码错误 403、正确返回 HttpOnly Cookie', async () => {
  const env = makeEnv({ CREATE_PASSWORD: 'true', ALLOWED_PASSWORDS: '["pw1","pw2"]' });
  let res = await callApi(env, '/api/verify-create', { name: 'n1', password: 'wrong' });
  assert.equal(res.status, 403);
  res = await callApi(env, '/api/verify-create', { name: 'n1', password: 'pw1' });
  assert.equal(res.status, 200);
  const cookie = res.headers.get('Set-Cookie');
  assert.ok(cookie && cookie.includes('create_token='));
  assert.ok(cookie.includes('HttpOnly'));
  assert.ok(cookie.includes('SameSite=Lax'));
  const data = await res.json();
  assert.ok(!('token' in data)); // 令牌不出现在响应体/URL 中
});

test('创建验证：无令牌或伪造令牌创建被拒绝', async () => {
  const env = makeEnv({ CREATE_PASSWORD: 'true', ALLOWED_PASSWORDS: '["pw1"]' });
  assert.equal((await createClipboard(env, 'n1', 'x')).status, 401);
  assert.equal(
    (await createClipboard(env, 'n1', 'x', {}, { headers: { Cookie: 'create_token=fake' } })).status,
    401
  );
});

test('创建验证：持有效令牌创建成功，令牌被消费并清除 Cookie', async () => {
  const env = makeEnv({ CREATE_PASSWORD: 'true', ALLOWED_PASSWORDS: '["pw1"]' });
  const verify = await callApi(env, '/api/verify-create', { name: 'n1', password: 'pw1' });
  const token = verify.headers.get('Set-Cookie').split(';')[0].split('=')[1];

  const res = await createClipboard(env, 'n1', 'content', {}, { headers: { Cookie: `create_token=${token}` } });
  assert.equal(res.status, 200);
  assert.equal(env.DB.tokens.has(token), false); // 令牌已消费（INSERT 成功后才删除）
  assert.ok(res.headers.get('Set-Cookie').includes('Max-Age=0')); // 清除 Cookie

  // 已消费的令牌不能再次使用
  const again = await createClipboard(env, 'n2', 'content', {}, { headers: { Cookie: `create_token=${token}` } });
  assert.equal(again.status, 401);
});

test('创建验证：令牌绑定名称，不能用于其他名称', async () => {
  const env = makeEnv({ CREATE_PASSWORD: 'true', ALLOWED_PASSWORDS: '["pw1"]' });
  const verify = await callApi(env, '/api/verify-create', { name: 'nameA', password: 'pw1' });
  const token = verify.headers.get('Set-Cookie').split(';')[0].split('=')[1];
  const res = await createClipboard(env, 'nameB', 'x', {}, { headers: { Cookie: `create_token=${token}` } });
  assert.equal(res.status, 401);
});

test('创建验证：过期令牌创建被拒绝', async () => {
  const env = makeEnv({ CREATE_PASSWORD: 'true', ALLOWED_PASSWORDS: '["pw1"]' });
  env.DB.tokens.set('exp-token', { token: 'exp-token', name: 'n1', created_at: 1, expires_at: Date.now() - 1000 });
  const res = await createClipboard(env, 'n1', 'x', {}, { headers: { Cookie: 'create_token=exp-token' } });
  assert.equal(res.status, 401);
});

test('创建验证：名称冲突不会消耗令牌', async () => {
  const env = makeEnv({ CREATE_PASSWORD: 'true', ALLOWED_PASSWORDS: '["pw1"]' });
  // 预置：剪贴板 n1 已存在，且有一枚绑定 n1 的有效令牌
  env.DB.clipboards.set('n1', {
    name: 'n1', content: 'existing', password_hash: null, created_at: 1, updated_at: 1,
    expires_in_days: 0, expires_at: null, enable_markdown: 0
  });
  env.DB.tokens.set('tk', { token: 'tk', name: 'n1', created_at: Date.now(), expires_at: Date.now() + 60000 });

  const conflict = await createClipboard(env, 'n1', 'second', {}, { headers: { Cookie: 'create_token=tk' } });
  assert.equal(conflict.status, 409);
  assert.equal(env.DB.tokens.has('tk'), true); // INSERT 失败不消耗令牌，用户可重试
});

// ---------- 测试：安全防护 ----------
test('跨站请求（Origin 不匹配）被拒绝', async () => {
  const env = makeEnv();
  const res = await callApi(env, '/api/create', { name: 'csrf', content: 'x' }, { headers: { Origin: 'https://evil.example.com' } });
  assert.equal(res.status, 403);
  assert.equal(env.DB.clipboards.has('csrf'), false);
});

test('无 Origin 请求（如 curl）不受影响', async () => {
  const env = makeEnv();
  const res = await callApi(env, '/api/create', { name: 'no-origin', content: 'x' }, { omitOrigin: true });
  assert.equal(res.status, 200);
});

test('创建验证暴力尝试限速（10 次/10 分钟后 429）', async () => {
  const env = makeEnv({ CREATE_PASSWORD: 'true', ALLOWED_PASSWORDS: '["pw1"]' });
  let last;
  for (let i = 0; i < 11; i++) {
    last = await callApi(env, '/api/verify-create', { name: 'n1', password: 'wrong-' + i });
  }
  assert.equal(last.status, 429);
});

test('剪贴板密码试错限速，且正确密码不受影响', async () => {
  const env = makeEnv();
  await createClipboard(env, 'ratelimit-pwd', 'x', { password: 'correct' });
  let last;
  for (let i = 0; i < 11; i++) {
    last = await callApi(env, '/api/get', { name: 'ratelimit-pwd', password: 'wrong-' + i });
  }
  assert.equal(last.status, 429);
  // 只统计失败尝试，密码正确仍然可用
  const ok = await callApi(env, '/api/get', { name: 'ratelimit-pwd', password: 'correct' });
  assert.equal(ok.status, 200);
});

// ---------- 测试：页面路由 ----------
test('首页返回 HTML', async () => {
  const env = makeEnv();
  const res = await getPage(env, '/');
  assert.equal(res.status, 200);
  assert.match(res.headers.get('Content-Type'), /text\/html/);
  assert.ok((await res.text()).includes('云剪贴板'));
});

test('API 与页面响应均带 Cache-Control: no-store', async () => {
  const env = makeEnv();
  const apiRes = await createClipboard(env, 'cache-test', 'x');
  assert.equal(apiRes.headers.get('Cache-Control'), 'no-store');
  const pageRes = await getPage(env, '/');
  assert.equal(pageRes.headers.get('Cache-Control'), 'no-store');
});

test('不存在的名称返回创建页（未启用验证）', async () => {
  const env = makeEnv();
  const res = await getPage(env, '/brand-new');
  assert.ok((await res.text()).includes('新建剪贴板'));
});

test('启用验证时不存在名称返回验证页；持 Cookie 返回创建页', async () => {
  const env = makeEnv({ CREATE_PASSWORD: 'true', ALLOWED_PASSWORDS: '["pw1"]' });
  let page = await getPage(env, '/new-clip');
  assert.ok((await page.text()).includes('创建剪贴板需要验证'));

  const verify = await callApi(env, '/api/verify-create', { name: 'new-clip', password: 'pw1' });
  const token = verify.headers.get('Set-Cookie').split(';')[0].split('=')[1];
  page = await getPage(env, '/new-clip', { Cookie: `create_token=${token}` });
  assert.ok((await page.text()).includes('新建剪贴板'));
});

test('存在的名称返回打开页，无密码内容直接内联', async () => {
  const env = makeEnv();
  await createClipboard(env, 'page-test', 'inline-visible-content');
  const res = await getPage(env, '/page-test');
  assert.equal(res.status, 200);
  assert.ok((await res.text()).includes('inline-visible-content'));
});

test('有密码剪贴板页面不内联内容', async () => {
  const env = makeEnv();
  await createClipboard(env, 'page-secret', 'should-not-appear', { password: 'pw' });
  const res = await getPage(env, '/page-secret');
  const html = await res.text();
  assert.ok(html.includes('请输入密码'));
  assert.ok(!html.includes('should-not-appear'));
});

test('含 <script> 的内容内联时被安全转义', async () => {
  const env = makeEnv();
  await createClipboard(env, 'xss-test', '</script><script>alert(1)</script>');
  const res = await getPage(env, '/xss-test');
  const html = await res.text();
  assert.ok(!html.includes('</script><script>'));
});

test('favicon 与 robots 快速 404', async () => {
  const env = makeEnv();
  assert.equal((await getPage(env, '/favicon.ico')).status, 404);
  assert.equal((await getPage(env, '/robots.txt')).status, 404);
});

test('畸形 URL 编码返回 400（不再 500）', async () => {
  const env = makeEnv();
  assert.equal((await getPage(env, '/%zz')).status, 400);
});

test('含斜杠路径返回 404', async () => {
  const env = makeEnv();
  assert.equal((await getPage(env, '/a%2Fb')).status, 404);
});

test('过期剪贴板打开时回落创建页', async () => {
  const env = makeEnv();
  env.DB.clipboards.set('expired-page', {
    name: 'expired-page', content: 'x', password_hash: null, created_at: 1, updated_at: 1,
    expires_in_days: 1, expires_at: Date.now() - 1000, enable_markdown: 0
  });
  const res = await getPage(env, '/expired-page');
  const html = await res.text();
  assert.ok(html.includes('新建剪贴板'));
  assert.equal(env.DB.clipboards.has('expired-page'), false);
});
