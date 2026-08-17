# 云剪贴板（支持Markdown）

一个基于 **Cloudflare Workers + D1** 的在线剪贴板，支持 Markdown、LaTeX 数学公式、代码高亮、密码保护、自动过期（含永不删除）、实时编辑预览、一键复制。创建剪贴板时可选择是否启用 Markdown 渲染，禁用时以纯文本显示，速度更快且不依赖前端渲染库。数据存储在 D1 数据库中，具备并发安全（主键唯一约束）和定时清理过期数据的能力。

---

## 🏗️ 架构

- **后端**：Cloudflare Worker 提供 REST API，数据存储在 D1 数据库中。
- **前端**：由 Worker 直接返回 HTML 页面（包含 CSS 和 JavaScript），使用 `fetch` 调用同域 `/api/*` 接口。
- **定时任务**：Worker 的 `scheduled` 事件每小时执行一次，删除 `expires_at` 小于当前时间的记录。

---

## 🚀 部署步骤

### 1. 创建 D1 数据库并初始化表

1. 登录 [Cloudflare Dashboard](https://dash.cloudflare.com)。
2. 进入 **Workers & Pages** → **D1**。
3. 点击 **Create database**，命名例如 `clipboard-db`，记下数据库 ID。
4. 进入该数据库的 **Console** 或 **SQL** 标签页，执行以下两条 SQL 语句（请分开执行，不要添加注释）：

**第一条：创建表**
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

**第二条：创建索引**
```sql
CREATE INDEX idx_expires_at ON clipboards(expires_at);
```

### 2. 创建 Worker 并粘贴代码

1. 进入 **Workers & Pages** → **Create application** → **Create Worker**。
2. 给你的 Worker 命名，例如 `cloud-clipboard`。
3. 将本项目中的 Worker 代码（完整代码见代码文件）粘贴到编辑器中。
4. 点击 **Settings** → **Variables**。
5. 在 **D1 database bindings** 下，添加绑定：
   - **Variable name**: `DB`
   - **D1 database**: 选择你在第 1 步创建的数据库。
6. （可选）在 **Environment Variables** 下添加配置变量（见“环境变量配置”）。
7. 点击 **Save and Deploy**。

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
| `REQUIRE_PASSWORD` | String | 设为 `"true"` 时，创建剪贴板必须设置密码；否则密码可选（默认） | `"true"` |
| `ALLOWED_PASSWORDS` | String | JSON 数组字符串，限制可用的密码值。留空或未设置表示不限制。 | `["abc123","secret456"]` |

**注意**：  
- 如果设置了 `ALLOWED_PASSWORDS` 且用户在创建时填写了密码，则该密码必须包含在列表中，否则创建失败。  
- 如果 `REQUIRE_PASSWORD` 为 `"true"` 且 `ALLOWED_PASSWORDS` 为空，则接受任意非空密码。

---

## 📖 使用说明

### 创建剪贴板

1. 在浏览器地址栏输入 `https://你的域名.com/剪贴板名`。  
2. 如果该名称不存在，会显示创建页面。  
3. 填写内容（支持 Markdown、LaTeX），选择是否启用 Markdown 渲染（默认启用）。  
4. 设置密码（可选），选择自动删除时长（含“永不删除”）。  
5. 点击“创建剪贴板”，成功后自动跳转到剪贴板页面。

### 打开剪贴板

- **无密码**：直接显示渲染后的内容（或纯文本）。  
- **有密码**：先输入密码验证，通过后显示内容。  

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

后端 `getValidExpiration` 函数中：  
```javascript
return 3; // 将 3 改为你需要的默认天数（需在 validDays 数组中）
```

同时修改创建页面 `<select>` 中对应 `<option>` 的 `selected` 属性。

### 增加更多过期选项

编辑 `validDays` 数组和创建页面中的 `<select>` 内容。注意：如果新增选项，需要在 D1 表中存储相应的 `expires_in_days` 值，并确保 `expires_at` 计算正确。

### 修改样式

前端使用 Tailwind CSS，可以直接在 HTML 模板中调整类名。如需深度定制，可以修改 `<style>` 标签中的自定义 CSS。

### 替换 CDN 资源

所有前端库（Tailwind、markdown-it、KaTeX、highlight.js）均通过 CDN 加载。如需离线可用，可将这些库下载后通过 Worker 提供静态资源托管。

---

## ⚠️ 注意事项

- **依赖 CDN**：前端需要加载 Tailwind CSS、markdown-it、KaTeX 等库（仅当启用 Markdown 时）。请确保用户网络可以访问这些 CDN。  
- **数据安全**：密码使用 SHA-256 哈希存储，但传输过程为明文（HTTPS 加密），建议配合 TLS。  
- **免费配额**：D1 免费计划提供 5 百万行读取/天，10 万行写入/天，通常足够个人使用。滥用可能导致配额耗尽，建议设置合理的过期时间，或启用 `REQUIRE_PASSWORD` 提高创建门槛。  
- **定时清理**：请确保已配置 Cron Trigger，否则过期数据不会自动删除（只能靠读取时惰性删除）。  
- **KV 迁移**：如果你之前使用 KV 存储数据，需要手动迁移到 D1（本版本不提供自动迁移脚本）。  
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

欢迎提出Issue或Pull Request，共同完善项目。
