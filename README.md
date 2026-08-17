# 云剪贴板

一个基于 **Cloudflare Workers + KV** 的轻量级在线剪贴板，提供美观的全屏界面，支持 Markdown、LaTeX 数学公式、代码高亮、密码保护、自动过期、实时编辑预览和一键复制。

---

## ✨ 功能特性

- 🎨 **现代 UI**：基于 Tailwind CSS，简洁美观，响应式设计，移动端友好。
- 📝 **Markdown 渲染**：使用 `markdown-it`，安全（默认不支持原始 HTML），支持 GFM。
- 🔢 **LaTeX 数学公式**：通过 `markdown-it-texmath` + `KaTeX` 渲染 `$...$` 和 `$$...$$`。
- 🌈 **代码高亮**：集成 `highlight.js`，支持多种编程语言。
- 🔒 **密码保护**：可选密码，使用 SHA-256 哈希存储，可配置强制密码和白名单。
- ⏱️ **自动过期**：可设置 1/3/7/14/30 天，默认 3 天，基于 KV 的 `expirationTtl` 自动删除。
- ✍️ **实时编辑预览**：左右分屏，边输入边渲染。
- 📋 **一键复制**：复制原始 Markdown 内容。
- 🔄 **同源部署**：前端与 API 集成在同一个 Worker 中，无跨域问题，API 地址不暴露。

---

## 🚀 部署步骤

### 1. 创建 KV 命名空间

1. 登录 [Cloudflare Dashboard](https://dash.cloudflare.com)。
2. 进入 **Workers & Pages** → **KV**。
3. 点击 **Create namespace**，命名为 `CLIPBOARD_KV`（或任意名称），复制其 ID。

### 2. 创建 Worker 并部署代码

1. 进入 **Workers & Pages** → **Create application** → **Create Worker**。
2. 给你的 Worker 命名，例如 `cloud-clipboard`。
3. 将本项目中的 `index.js` 完整代码粘贴到 Worker 编辑器中。
4. 点击 **Settings** → **Variables**。
5. 在 **KV namespace bindings** 下，添加绑定：
   - **Variable name**: `CLIPBOARD_KV`
   - **KV namespace**: 选择你在第 1 步创建的命名空间。
6. （可选）在 **Environment Variables** 下，添加配置变量（见下文）。
7. 点击 **Save and Deploy**。

### 3. 访问使用

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
3. 填写内容（支持 Markdown、LaTeX），设置密码（可选），选择自动删除时长。  
4. 点击“创建剪贴板”，成功后自动跳转到剪贴板页面。

### 打开剪贴板

- **无密码**：直接显示渲染后的内容。  
- **有密码**：先输入密码验证，通过后显示内容。  

### 编辑剪贴板

- 在预览模式下点击顶部工具栏的“编辑”按钮。  
- 进入编辑模式，左侧输入 Markdown/LaTeX，右侧实时预览。  
- 编辑完成后点击“保存”更新内容，或点击“取消”放弃修改。

### 复制内容

- 在预览模式下点击“复制”按钮，将原始 Markdown 内容复制到剪贴板。  

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

编辑 `validDays` 数组和创建页面中的 `<select>` 内容。

### 修改样式

前端使用 Tailwind CSS，可以直接在 HTML 模板中调整类名。如需深度定制，可以修改 `<style>` 标签中的自定义 CSS。

### 替换 CDN 资源

所有前端库（Tailwind、markdown-it、KaTeX、highlight.js）均通过 CDN 加载。如需离线可用，可将这些库下载后通过 Worker 提供静态资源托管。

---

## ⚠️ 注意事项

- **依赖 CDN**：前端需要加载 Tailwind CSS、markdown-it、KaTeX 等库，请确保用户网络可以访问这些 CDN。  
- **数据安全**：密码使用 SHA-256 哈希存储，但传输过程为明文（HTTPS 加密），建议配合 TLS。  
- **免费配额**：Cloudflare Workers 和 KV 均有免费额度，滥用可能导致配额耗尽。建议根据需求设置合理的过期时间，或启用 `REQUIRE_PASSWORD` 提高创建门槛。  
- **KV 限制**：KV 的 `expirationTtl` 最大支持 30 天（2592000 秒），因此自动删除时长上限为 30 天。  

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


欢迎对本项目提起Issue或PR，共同完善。