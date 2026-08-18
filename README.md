# 云剪贴板（Cloudflare Workers + D1）

一个基于 **Cloudflare Workers + D1** 的现代在线剪贴板，支持 Markdown、LaTeX 数学公式、代码高亮、密码保护（PBKDF2 加盐哈希）、自动过期（含永不删除）、实时编辑预览、一键复制。创建剪贴板时可选是否启用 Markdown 渲染；可配置全局创建验证，只有通过验证的用户才能新建剪贴板（验证令牌通过 HttpOnly Cookie 传递）。数据存储于 D1 数据库，具备并发安全（主键唯一约束）、CSRF 防护、暴力破解限速和定时清理过期数据能力。

---

## ✨ 功能特性

- 🖥️ **全屏布局**：剪贴板页面充满视口，顶部工具栏固定，内容区域自适应滚动。
- 🎨 **现代 UI**：基于 Tailwind CSS，简洁美观，响应式设计。
- 📝 **可选 Markdown 渲染**：创建时可勾选“启用 Markdown”，支持 GFM；若未勾选，纯文本显示，不加载渲染库，加载更快。
- 🔢 **LaTeX 数学公式**：启用 Markdown 后，通过 `markdown-it-texmath` + `KaTeX` 渲染 `$...$` 和 `$$...$$`。
- 🌈 **代码高亮**：启用 Markdown 后，集成 `highlight.js`，支持多种编程语言。
- 🔒 **剪贴板密码**：每个剪贴板可设置访问密码（可选），密码使用 PBKDF2 加随机盐哈希存储。
- 🛡️ **全局创建验证**：可配置 `CREATE_PASSWORD` 和 `ALLOWED_PASSWORDS`，要求用户输入正确密码后才能创建剪贴板；令牌 10 分钟有效、绑定剪贴板名称、通过 HttpOnly Cookie 传递（不出现在 URL 中）。
- 🚦 **暴力破解防护**：创建验证与剪贴板密码均按 IP 限速（10 次 / 10 分钟，超过返回 429）。
- 🧱 **CSRF 防护**：API 校验请求来源（Origin），阻止跨站删除/篡改剪贴板。
- 📏 **大小限制**：单条内容最多 100KB，剪贴板名称 1-64 字符且不含空格与斜杠。
- ⏱️ **自动过期**：可设置 0（永不删除）、1、3、7、14、30 天，默认 3 天；通过 Cron 触发器每小时清理过期数据。
- ✍️ **实时编辑预览**：左右分屏，边输入边渲染（若启用 Markdown），或纯文本同步显示。
- 📋 **一键复制**：复制原始内容（无论渲染与否）。
- 🔄 **同源部署**：前端与 API 集成在同一个 Worker 中，无跨域问题，API 地址不暴露。
- ⚠️ **渲染失败回退**：若 Markdown 库加载失败或渲染出错，自动回退为纯文本并提示原因，不显示“网络错误”。

---

## 🏗️ 架构

- **后端**：Cloudflare Worker 提供 REST API，数据存储在 D1 数据库中。
- **前端**：由 Worker 直接返回 HTML 页面（包含 CSS 和 JavaScript），使用 `fetch` 调用同域 `/api/*` 接口。
- **定时任务**：Worker 的 `scheduled` 事件每小时执行一次，删除过期的剪贴板和创建验证令牌。

---

## 🚀 部署步骤

### 1. 创建 D1 数据库并初始化表

1. 登录 [Cloudflare Dashboard](https://dash.cloudflare.com)。
2. 进入 **Workers & Pages** → **D1**。
3. 点击 **Create database**，命名例如 `clipboard-db`，记下数据库 ID。
4. 进入该数据库的 **Console** 或 **SQL** 标签页，执行以下 SQL 语句（请分开执行，不要添加注释）：

**第一条：创建剪贴板表**
```sql
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
```

**第二条：创建索引和令牌表**
```sql
CREATE INDEX idx_expires_at ON clipboards(expires_at);

CREATE TABLE create_tokens (
  token TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
```

> 或者使用项目附带的迁移文件：在 `wrangler.toml` 中填入数据库 ID 后执行 `npx wrangler d1 migrations apply DB --remote`，会自动创建上述表结构。

### 2. 创建 Worker 并部署代码

**方式 A：Dashboard 粘贴（与原来一致）**

1. 进入 **Workers & Pages** → **Create application** → **Create Worker**。
2. 给你的 Worker 命名，例如 `cloud-clipboard`。
3. 将完整的 Worker 代码粘贴到编辑器中（代码见 `index.js`）。
4. 点击 **Settings** → **Variables**。
5. 在 **D1 database bindings** 下，添加绑定：
   - **Variable name**: `DB`
   - **D1 database**: 选择你在第 1 步创建的数据库。
6. 在 **Environment Variables** 下，按需添加配置变量（见“环境变量配置”）。
7. 点击 **Save and Deploy**。

**方式 B：wrangler CLI（推荐）**

1. 安装 wrangler 并登录：`npm install -g wrangler`、`wrangler login`。
2. 编辑 `wrangler.toml`，将 `database_id` 替换为你的 D1 数据库 ID。
3. 初始化数据库表：`npx wrangler d1 migrations apply DB --remote`。
4. 部署：`npx wrangler deploy`。
5. 如需启用创建验证，取消 `wrangler.toml` 中 `[vars]` 段对应注释后重新部署。

### 3. 配置定时清理（Cron Trigger）

1. 进入 Worker 页面，点击 **Triggers** 标签（中文界面为“触发器”）。
2. 点击 **Add Cron Trigger**。
3. 输入 Cron 表达式 `0 * * * *`（每小时整点执行一次）。
4. 保存。

### 4. 访问使用

- 打开你的 Worker 域名（例如 `https://your-worker.workers.dev`），即可看到首页。
- 访问 `https://your-worker.workers.dev/任意名称` 创建或打开一个剪贴板。

---

## ⚙️ 环境变量配置

| 变量名 | 类型 | 说明 | 示例 |
|--------|------|------|------|
| `CREATE_PASSWORD` | String | 设为 `"true"` 时启用全局创建验证；其他值（或未设置）表示禁用。 | `true` |
| `ALLOWED_PASSWORDS` | String | JSON 数组字符串，列出能够通过创建验证的密码列表。启用验证时必填。 | `["114514","abc123"]` |
| `PBKDF2_ITERATIONS` | Number | 可选。密码哈希的 PBKDF2 迭代次数，默认 10000（允许范围 1000-1000000）。越大越安全但越耗 CPU，注意 Workers 免费计划的 CPU 限制。 | `10000` |

**注意**：
- `CREATE_PASSWORD` 的值必须是字符串 `"true"`，在 Dashboard 中直接输入 `true` 即可，不要添加额外引号。
- `ALLOWED_PASSWORDS` 必须是合法的 JSON 数组字符串，使用英文双引号，例如 `["114514"]`。
- 如果启用创建验证但 `ALLOWED_PASSWORDS` 为空或格式错误，验证将提示“验证配置错误”。
- 剪贴板自身的访问密码不再受 `ALLOWED_PASSWORDS` 限制，该变量仅用于创建验证。

---

## 📖 使用说明

### 创建剪贴板

1. 在浏览器地址栏输入 `https://你的域名.com/剪贴板名`。  
2. 如果该名称不存在：
   - 若启用了全局创建验证，会先出现密码输入页面，输入 `ALLOWED_PASSWORDS` 中的任意密码，验证通过后进入创建表单。
   - 若未启用，则直接显示创建表单。
3. 填写内容，选择是否启用 Markdown 渲染（默认启用），设置剪贴板访问密码（可选），选择自动删除时长（含“永不删除”）。  
4. 点击“创建剪贴板”，成功后自动跳转到剪贴板页面。

### 打开剪贴板

- **无密码**：直接显示渲染后的内容（或纯文本）。  
- **有密码**：先输入剪贴板密码验证，通过后显示内容。  

### 编辑剪贴板

- 在预览模式下点击顶部工具栏的“编辑”按钮。  
- 进入编辑模式，左侧输入内容，右侧实时预览（若启用 Markdown）。  
- 编辑完成后点击“保存”更新内容，或点击“取消”放弃修改。  

### 复制内容

- 在预览模式下点击“复制”按钮，将原始内容复制到剪贴板。  
- 复制功能不依赖渲染是否成功，始终复制原始文本。

### 删除剪贴板

- 在预览模式下点击“删除”按钮，确认后永久删除该剪贴板。  

---

## 🛠️ 自定义

### 修改默认过期天数

默认过期天数为 3 天，由两处共同决定：
- 后端 `index.js` 顶部的 `VALID_EXPIRY_DAYS` 数组（合法天数）与 `DEFAULT_EXPIRY_DAYS`（缺省值）；
- 前端创建页 `<select>` 中对应 `<option>` 的 `selected` 属性。

两者需同步修改。

### 增加更多过期选项

编辑 `VALID_EXPIRY_DAYS` 数组和创建页面中的 `<select>` 内容。注意：新增选项后需确保 D1 表中的 `expires_in_days` 值可正确存储。API 显式传入不在列表中的天数会返回 400（不再静默回退默认值）。

### 修改样式

前端使用 Tailwind CSS，可以直接在 HTML 模板中调整类名。如需深度定制，可以修改 `<style>` 标签中的自定义 CSS。

### 替换 CDN 资源

所有前端库（Tailwind、markdown-it、KaTeX、highlight.js）均通过 CDN 加载。如需离线可用，可将这些库下载后通过 Worker 提供静态资源托管。

---

## 🧪 本地测试

项目附带基于 Node 内置测试框架（`node:test`）的自动化测试，使用内存 Mock 模拟 D1，无需联网或部署即可运行：

```bash
node test/index.test.js   # 或 npm test
```

要求 Node 18+。测试覆盖：CRUD、密码校验、过期清理、创建验证令牌流程、CSRF 防护、限速、页面内联内容与 XSS 转义等（共 39 个用例）。

---

## ⚠️ 注意事项

- **依赖 CDN**：前端需要加载 Tailwind CSS、markdown-it、KaTeX 等库（仅当启用 Markdown 时）。请确保用户网络可以访问这些 CDN。  
- **数据安全**：剪贴板密码使用 PBKDF2（随机盐 + 默认 10000 次迭代）哈希存储，不同剪贴板即使密码相同哈希也不同；传输过程依赖 HTTPS 加密，请务必启用 TLS。若曾使用旧版本（无盐 SHA-256），旧哈希无法通过新校验逻辑验证，需重新设置密码。  
- **限速说明**：暴力破解限速基于 Worker 内存计数（按 IP），多 isolate 间不共享且重启后重置，属于基础防护而非绝对保障。  
- **创建令牌**：通过 HttpOnly + SameSite=Lax Cookie 传递，10 分钟有效，创建成功后立即作废，且与剪贴板名称绑定。  
- **免费配额**：D1 免费计划提供 5 百万行读取/天，10 万行写入/天，通常足够个人使用。滥用可能导致配额耗尽，建议设置合理的过期时间，或启用 `CREATE_PASSWORD` 提高创建门槛。  
- **定时清理**：请确保已配置 Cron Trigger，否则过期数据不会自动删除（只能靠读取时惰性删除）。  
- **KV 迁移**：本版本使用 D1，不支持自动从 KV 迁移数据。  
- **Markdown 可选**：创建后无法更改是否启用 Markdown，若有需要请在创建时决定。

---

## 📄 许可证

MIT License

---

## 🙏 致谢

本项目使用了以下开源库：

- [Tailwind CSS](https://tailwindcss.com/)  
- [markdown-it](https://github.com/markdown-it/markdown-it)  
- [KaTeX](https://katex.org/)  
- [highlight.js](https://highlightjs.org/)  
- [markdown-it-texmath](https://github.com/goessner/markdown-it-texmath)