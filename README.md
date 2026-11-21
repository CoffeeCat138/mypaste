# mypaste — 云剪贴板（Cloudflare Workers + D1）

一个部署在 **Cloudflare Workers + D1** 上的单文件在线云剪贴板，零构建依赖、同源部署。支持 Markdown / LaTeX / 代码高亮与代码块复制、实时分栏预览、PBKDF2 密码保护、全局创建/编辑/删除验证、自动过期清理，以及可选接入**阿里云内容安全增强版**进行自动内容审核。

项目地址：[https://github.com/CoffeeCat138/mypaste](https://github.com/CoffeeCat138/mypaste)

---

## ✨ 功能特性

### 核心体验
- **即开即用**：访问 `https://你的域名/任意名称` 即可新建或打开对应剪贴板；无密码剪贴板直接服务端内联内容，减少一次 API 请求。
- **可选 Markdown 渲染**：新建时可选开启或关闭 Markdown（默认开启）。开启后集成 `luogu-renderer`（内置 KaTeX 数学公式、PrismJS 语法高亮、行号、高亮行、自定义提示容器与代码块一键复制）；关闭时仅作纯文本展示，不加载额外渲染资源。
- **实时分栏预览**：新建和编辑页面均采用左右分栏实时预览，移动端自动切换为上下布局。
- **灵活的过期策略**：支持 `0`（永不删除）、`1`、`3`（默认）、`7`、`14`、`30` 天，编辑时可随时修改过期时长；读取时惰性清理，配合每小时 Cron 定时清理过期记录与令牌。
- **本地化时间与便捷交互**：创建与更新时间自动按查看者本地时区显示；内置页内确认弹窗与 Toast 提示（无原生 `alert`/`confirm`），支持回车提交与 `Esc` 关闭弹窗。
- **一键复制**：支持复制完整原文以及单个代码块内容，不依赖 Markdown 渲染状态。

### 权限与安全
- **全局密码保护（可选）**：启用 `CREATE_PASSWORD` 后，新建、编辑、删除剪贴板均需验证全局密码。新建验证通过后通过 `HttpOnly` + `SameSite=Lax` Cookie 下发 10 分钟有效、绑定名称的一次性令牌，不暴露在 URL 中。
- **剪贴板独立访问密码（可开关）**：每条剪贴板可单独设置访问密码（支持在编辑时修改或清除），后端使用 PBKDF2-SHA256 + 16 字节随机盐哈希存储；可通过 `ENABLE_ACCESS_PASSWORD=false` 全局关闭此功能。
- **暴力破解与频率限速**：按 IP 在 Worker 内存中限速——全局密码与单条剪贴板密码**仅在输错时计数，验证成功即清零**（10 次失败 / 10 分钟）；创建接口限制 20 次 / 10 分钟。
- **XSS 与 CSRF 防护**：渲染结果经 `DOMPurify` 消毒（若安全组件或渲染器加载失败自动降级为纯文本显示）；所有 `POST /api/*` 校验 `Origin` 防止跨站请求；HTML 响应附带 `X-Frame-Options: DENY`、`X-Content-Type-Options: nosniff` 等安全头。
- **参数与大小限制**：单条内容上限 100KB；剪贴板名称 1–64 字符，禁止空白、斜杠及 `? # % & +` 等 URI 保留字符，访问非法名称路径时直接返回 400 提示页。

### 内容安全审核
- **阿里云内容安全增强版（可选）**：零外部依赖，基于 Web Crypto API 实现 `ACS3-HMAC-SHA256` V3 签名，默认对接 `TextModerationPlus` + `ugc_moderation_byllm` 大模型审核服务。
- **自动分段与容错**：在创建与编辑写入数据库前自动对名称和正文进行审查（`ugc_moderation_byllm` 系列按 2000 字分段，其余服务按 600 字分段），支持配置审核服务异常时的拦截/放行策略（Fail-Closed / Fail-Open）。

---

## 🏗️ 架构概览

- **单文件 Worker（`index.js`）**：同时承担 HTML 页面渲染、同源 REST API 与定时清理任务（`scheduled`），无跨域问题。
- **Cloudflare D1**：存储剪贴板内容（`clipboards`）与创建验证令牌（`create_tokens`），依靠主键唯一约束保证并发安全。

---

## 🚀 部署步骤

### 1. 创建并初始化 D1 数据库

1. 登录 [Cloudflare Dashboard](https://dash.cloudflare.com)，进入 **Workers & Pages** → **D1**。
2. 点击 **Create database**（例如命名为 `clipboard-db`），记下数据库 ID。
3. 在数据库的 **Console** 中依次执行以下 SQL：

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

```sql
CREATE INDEX idx_expires_at ON clipboards(expires_at);

CREATE TABLE create_tokens (
  token TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
```



### 2. 部署 Worker

1. 进入 **Workers & Pages** → **Create application** → **Create Worker**。
2. 将 `index.js` 完整代码粘贴到编辑器中并保存部署。
3. 进入 Worker 的 **Settings** → **Bindings**，添加 D1 数据库绑定：
   - **Variable name**：`DB`
   - **D1 database**：选择第 1 步创建的数据库
4. 在 **Settings** → **Variables and Secrets** 中按需添加下方环境变量。

### 3. 配置定时清理（Cron Trigger）

1. 进入 Worker → **Settings** → **Trigger Events**（触发器）。
2. 添加 Cron Trigger：`0 * * * *`（每小时整点清理一次过期剪贴板与过期令牌）。

---

## ⚙️ 环境变量与 Secrets 配置

### 基础与认证配置

| 变量名 | 默认值 | 说明 | 示例 |
|--------|--------|------|------|
| `CREATE_PASSWORD` | 未启用 | 设为 `"true"` 时开启全局密码验证（新建、编辑、删除均需校验）。 | `true` |
| `ALLOWED_PASSWORDS` | `[]` | JSON 数组字符串，列出允许通过全局验证的密码列表。开启 `CREATE_PASSWORD` 时必填。 | `["pass1","pass2"]` |
| `ENABLE_ACCESS_PASSWORD` | `"true"` | 设为 `"false"` 时关闭单条剪贴板的访问密码功能（隐藏相关输入框且 API 忽略密码字段；已有密码的历史剪贴板仍保持验证）。 | `false` |
| `PBKDF2_ITERATIONS` | `10000` | 可选。访问密码的 PBKDF2 迭代次数，合法范围 `1000`–`1000000`。值越大越耗 CPU，请结合 Workers 配额调整。 | `10000` |

### 阿里云内容安全审核配置（可选）

| 变量名 | 默认值 | 说明 | 示例 |
|--------|--------|------|------|
| `ALIYUN_MODERATION_ENABLED` | 未启用 | 设为 `"true"` 时开启阿里云文本内容审核。 | `true` |
| `ALIYUN_ACCESS_KEY_ID` | 无 | 阿里云 AccessKey ID（**强烈建议配置为 Secret**，并仅授予内容安全最小权限）。 | `LTAI5t...` |
| `ALIYUN_ACCESS_KEY_SECRET` | 无 | 阿里云 AccessKey Secret（**强烈建议配置为 Secret**）。 | `******` |
| `ALIYUN_MODERATION_ENDPOINT` | `green-cip.cn-shanghai.aliyuncs.com` | 阿里云内容安全增强版接入点域名（无需带 `https://`）。 | `green-cip.cn-beijing.aliyuncs.com` |
| `ALIYUN_MODERATION_SERVICE` | `ugc_moderation_byllm` | 审核服务代码。`ugc_moderation_byllm` 系列按 2000 字分段，其余服务（如 `comment_detection_pro`）按 600 字分段。 | `ugc_moderation_byllm` |
| `ALIYUN_MODERATION_ACTION` | `TextModerationPlus` | 接口名称。大模型审核使用 `TextModerationPlus`，传统文本审核可改为 `TextModeration`。 | `TextModerationPlus` |
| `ALIYUN_MODERATION_FAIL_OPEN` | `"false"` | 设为 `"true"` 时，若阿里云接口超时或异常则放行；默认 `"false"`，异常时返回 `503` 拦截写入。 | `false` |

> **提示**：在 Dashboard 中填写 `"true"` / `"false"` 时直接输入 `true` 或 `false`，无需额外加引号；`ALLOWED_PASSWORDS` 必须是合法的英文双引号 JSON 数组。

---

## 📡 API 接口概览

所有 API 均为同源 `POST` JSON 请求，带 `Origin` 校验，响应头包含 `Cache-Control: no-store`。

| 接口路径 | 作用 | 说明 |
|----------|------|------|
| `POST /api/verify-create` | 全局密码验证 | 传入 `{ name, password }` 时校验密码并下发 HttpOnly 创建令牌 Cookie；仅传 `{ password }` 时用于编辑/删除前的密码校验。 |
| `POST /api/create` | 创建剪贴板 | 校验名称、内容、过期时间、创建令牌（若开启）与内容安全审核后写入 D1，成功后立即消费令牌。 |
| `POST /api/get` | 获取剪贴板内容 | 用于受密码保护的剪贴板验证密码后拉取正文与元信息。 |
| `POST /api/update` | 更新剪贴板 | 支持修改正文、过期时间及访问密码（可重设或清除）；启用全局密码或内容审核时同步校验。 |
| `POST /api/delete` | 删除剪贴板 | 校验全局密码（若开启）与访问密码（若有）后永久删除记录。 |

---

## 📖 使用说明

1. **新建剪贴板**：浏览器访问 `https://你的域名/剪贴板名`。若该名称尚未创建（或已过期），通过全局验证（如已开启）后即可填写内容、选择过期时间与是否启用 Markdown，并可选设置访问密码。
2. **查看与复制**：打开已存在的链接即可查看内容；若有访问密码，输入密码解锁后展示。点击顶部“复制”可复制完整原文，代码块右上角支持单块复制。
3. **编辑剪贴板**：点击“编辑”（开启全局验证时会弹出验证框），在左右分栏中修改内容、调整过期时间、修改或勾选“清除密码”，点击“保存”即生效。
4. **删除剪贴板**：点击“删除”，完成密码验证（若开启）与二次确认后永久删除。

---

## 🛠️ 自定义与测试

### 修改过期时间选项
如需调整默认过期天数或可选列表，请同步修改：
- 后端 `index.js` 顶部的 `VALID_EXPIRY_DAYS` 和 `DEFAULT_EXPIRY_DAYS`；
- 前端创建页 `#expiresInDays` 下拉框以及编辑页 `showEditor()` 中的 `opts` 数组。

---

## ⚠️ 注意事项

- **前端 CDN 依赖**：页面通过 CDN 加载 Tailwind CSS，启用 Markdown 时还会加载 `luogu-renderer`、`KaTeX`、`PrismJS` 与 `DOMPurify`。若网络无法访问 CDN，Markdown 内容会自动降级为纯文本以保证可用性与安全性。
- **内存限速局限**：内置限速基于单个 Worker isolate 内存计数，冷启动或跨边缘节点时不共享。如需严格的全局防刷，建议在 Cloudflare 控制台配合 WAF Rate Limiting 规则使用。
- **阿里云审核配额与耗时**：开启内容审核后，每次创建和编辑都会实时请求阿里云接口（单段超时 10 秒），超长文本会触发多次分段调用，请注意阿里云账号的免费额度/计费策略，并尽量使用 RAM 子账号最小权限 AccessKey。
- **Markdown 开关不可逆**：是否在页面加载 Markdown 渲染器在创建时决定，创建后无法切换。
- **务必启用 HTTPS**：密码传输依赖 TLS 加密，请始终通过 HTTPS 访问你的 Worker 或自定义域名。

---

## 📄 许可证

MIT License

---

## 🙏 致谢

- [Tailwind CSS](https://tailwindcss.com/)
- [luogu-renderer](https://github.com/luogu-dev/luogu-renderer)
- [KaTeX](https://katex.org/)
- [PrismJS](https://prismjs.com/)
- [DOMPurify](https://github.com/cure53/DOMPurify)