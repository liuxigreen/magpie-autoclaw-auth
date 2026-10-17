# magpie-autoclaw-auth

[magpie](https://usemagpie.ai) / [OpenCode](https://opencode.ai) provider 插件：**AutoClaw（智谱澳龙 / OpenClaw 云端账号体系）**。

一个包注册供应商 `autoclaw`，支持三种登录方式，并内置 **CN ↔ 全球双通道互备**：

| 供应商 id | 登录方式 | 上游 host | 模型引用 |
|---|---|---|---|
| `autoclaw` | ① 网页 OAuth（Google / z.ai）<br>② **手机验证码（国内号）**<br>③ 授权链接粘贴 | `autoglm-api.autoglm.ai`（国际）<br>`autoglm-acceleration-api.zhipuai.cn`（国内） | `autoclaw/zai_auto` 等 |

支持 magpie 的多账号、故障切换、token 自动轮换与积分余额显示。模型为带前缀的 routeModelId（`zai_` 智谱 / `zaicoding_` coding plan）：

- `zai_auto` / `zai_auto-fast`（自动路由，推荐默认）
- `zaicoding_glm-5.3`
- `zai_glm-5.3-flash`

> 旧表里的 `zai_glm-5-turbo`、`tdpsk_deepseek-v4-*` 上游已下架（实测 `400 非法模型`），已移除。

## 安装

```sh
magpie plugin add github:<你的用户名>/magpie-autoclaw-auth   # 推荐：发布到 GitHub 后
# 或本地调试：
magpie plugin add ./magpie-autoclaw-auth

# 登录方式三选一（GUI 里是三个按钮，CLI 会询问）：
#  ①「AutoClaw 网页登录」——本机引导页（滑块 + 授权自动回跳），适合本机桌面环境
#  ②「AutoClaw 手机验证码登录」——输入国内手机号收短信，**全程无需浏览器**，
#     服务器 / 远程环境最省事（也是唯一不依赖 127.0.0.1 和滑块的方式）
#  ③「AutoClaw 授权链接登录」——打开上游授权页，登录后把跳转地址栏的完整 URL 粘贴回来，
#     不伺服任何本地页面，适合 127.0.0.1 打不开的环境（远程服务器 / 代理劫持 / 浏览器与 magpie 不同机）
magpie plugin login autoclaw

magpie provider test autoclaw zai_auto   # 连通测试
magpie quota                              # 积分余额与签到状态
```

OpenCode 同样可加载（`opencode auth login`）。登录信息保存在 magpie 的 `plugin-auth.json`（600 权限）/ OpenCode 的 `auth.json`。

## CN ↔ 全球双通道互备（v0.9.0 新增）

上游账号是**分区**的：国内手机号账号只认国内 host，Google / z.ai 账号只认国际 host。拿错侧调会 `401`。

插件从 token 的 JWT claim `source_id` 自动判断归属，**先挑对家，再谈切换**：

| `source_id` | 账号类型 | 首选 host | 备选 host |
|---|---|---|---|
| `agent*`（实测形如 `agentrefresh_token`） | 国内手机号 | 国内（加速域） | 国际 |
| 其余（`autoclaw*` / `google` / `zai`） | 国际 | 国际 | 国内 |

- 实测（2026-10-17，DMIT）：`185****5211` 账号 `source_id = agentrefresh_token` → CN 优先；其余国际账号 → 全球优先 ✅
- 两个方向互为备份：首选返回 **401** 时自动切到另一侧重试；两侧都 401 才判定登录失效并在面板标红
- ⚠️ **只有 401 才换 host**。403 有三种业务形态（`forbidden` 平台绑定 / `pay-view` 810001 额度 / `810002` 限流），换侧既无用又会把真实原因伪装成「登录失效」，故原样透传
- 🔴 国内 host 必须是**加速域** `autoglm-acceleration-api.zhipuai.cn`。主站 `autoglm-api.zhipuai.cn` 实测一律 `410000 / 401`


## 每日签到（核心功能）

两种方式，推荐**原生签到**：

**① magpie 原生签到（magpie ≥ v0.1.1083，推荐）**：插件实现 `auth.checkin` 钩子，走 magpie 统一调度——Settings → Usage → Plugins 里每个供应商有 **Daily check-in** 开关（默认关）。打开后每天每账号自动签一次（北京时间；启动 2 分钟后首查、每 30 分钟轮询，`failed` 30 分钟后重试），账户 Usage 卡片显示签到结果（`+N · 连续 N 天`），也可 **Check in now** 手动签。与 WorkBuddy / Qoder 等内置签到是同一套 UI。

**② 旧链路自动补签（默认关）**：查额度（`magpie quota`、GUI 刷新）与 token 刷新时发现未签就补签（服务端幂等，本地按天去重、失败按小时重试）。旧版 magpie / OpenCode 宿主或偏好该行为的用户开启 `signinOnUsage`。

`magpie quota` 的额度窗口里始终显示**每日签到**状态行（今日已签 ✓ / 今日未签 +N）。

### 签到选项

三个通道：插件 options（优先）→ 配置文件（兜底）→ 默认值。原生签到开关只在 GUI 的 Settings 里，不走这两个通道。

```sh
# 通道 1：插件 options（magpie CLI）
magpie plugin options magpie-autoclaw-auth '{"signin": false}'        # 关闭旧链路自动补签总开关
magpie plugin options magpie-autoclaw-auth '{"signinHour": 8}'        # 只在 8:00–8:59 补签
magpie plugin options magpie-autoclaw-auth '{"signinOnUsage": true}'  # 开启查额度/刷新自动补签

# 通道 2：配置文件 ~/.config/magpie/autoclaw.json（保存即生效，热读取）
echo '{ "signin": true, "signinHour": null, "signinOnUsage": false }' > ~/.config/magpie/autoclaw.json
```

| 选项 | 默认 | 说明 |
|---|---|---|
| `signin` | `true` | 旧链路自动补签总开关（不影响原生 checkin） |
| `signinOnUsage` | `false` | 查额度/刷新时自动补签（原生 checkin 开关接管后默认关） |
| `signinHour` | `null` | 限定补签小时：`8` = 仅 8:00–8:59 补签；`null` 不限 |

## 直连说明（不经本地网关）

插件**直连上游云 API**，登录/对话/刷新/积分全部自行完成：

- 对话走 `POST {host}/autoclaw-proxy/proxy/autoclaw/v1/chat/completions`（`X-Authorization` 鉴权）；
- token 过期前自动轮换（refresh token 一次一换，`auth.refresh` 钩子交给 magpie 串行化，不会双花）；
- 积分余额通过 `auth.usage` 显示（纯积分制，无总量上限，aside 窗口展示余额）；
- **国际版登录是完整本地实现**：插件在 127.0.0.1 上取官方 TokenServer 端口池中的一个端口（18432/19654/19723/53699，OAuth client 回调白名单；被占自动顺延）起临时服务器，内嵌引导页完成阿里滑块验证（AliyunCaptcha SDK）→ 获取授权页 → 自动跳转 Google/z.ai → 回调自动捕获 code，全程浏览器完成、无需粘贴；登录结束服务器即关。

## 已知行为

- 对话 fetch 已内置 401 自动换侧重试（**按账号归属排序**：国内号 CN 优先、国际号全球优先，两侧真互备）。**403 不当作登录失效**——上游 403 有 `forbidden`（平台绑定）、`pay-view/810001`（额度/高峰）、`810002`（限流）三种业务形态，原样透传给客户端。
- 上游模型白名单随版本变化，模型下线时上游返回 `400 非法模型`（原样透传错误消息）。模型清单已按上游真实目录收敛为 4 个。
- refresh token 与 AutoClaw 桌面端**共用会互踢**（双方都轮换），插件账号请勿同时在桌面端登录。
- 上游偶发改协议时，`CLIENT_VERSION` / 端点路径可能需要随官方客户端更新。
- **`device_id` 是 OAuth 的会话绑定键**：引导页调 `{vendor}-oauth-url` 与插件调 `{vendor}-oauth-login` 必须用同一个值。方式2 已由插件通过 `?device_id=` 透传；手工复制旧链接（或误用方式1 的页面）会导致 `631001 抱歉,登录失败,请重新尝试`。

### 出站请求的五道上游闸（v0.8.0 全部对齐）

本插件的对话出站请求必须同时满足上游五条硬约束，任一条不满足都会被拒（且错误形态各不相同，极易误判成「登录失效」）：

| # | 约束 | 不满足时 |
|---|---|---|
| 1 | `User-Agent` 必须是 `AutoClaw/*` 形态 | **405 + 阿里云 WAF HTML 页**（运行时默认 UA 如 bun 的会被判非法客户端） |
| 2 | **不发** `X-Harness-Type: zcode` | 403 `pay-view/810001` 或 406 空体 |
| 3 | `X-Tm` 只发 `win`/`mac`，**绝不发 `linux`** | 403 `{"message":"forbidden"}` |
| 4 | body 的 `max_tokens` 要么缺省、要么 ≥10000 | 小正整数（256/4096/8192…）→ 406 空体 |
| 5 | **首条 system/developer 消息的正文**必须以 `You are a personal assistant running inside OpenClaw.` **开头**，且含 `## Tooling` 段，且不含外来 harness 身份句 | 只有身份句 → 403 `pay-view`；无 system / 中性句 / 外来身份句 → 406 空体 |

第 5 条是**经 magpie 网关转发时唯一的 406 来源**：网关会注入自己的 system 提示词，而该提示词不满足上游白名单；插件直调（无网关注入）则天然满足 —— 这正是「插件自测 200、经网关 406」的分界。v0.8.0 起插件在出站前自动规范化：**前置** OpenClaw 身份前缀（客户端自己的提示词逐字保留在后），并把 `ZCode` / `Claude Code` / `Codex` / `DeepSeek Harness` 等外来身份句**改写**成中性说法（忽略大小写、长匹配优先、幂等、只动 system/developer）。

另有两条模型标识纪律：`X-Request-Model` 必须发**带前缀的路由 ID**（`zaicoding_glm-5.3`），`body.model` 必须发**剥前缀的目录名**（`glm-5.3`）。发反了上游回 `400 非法模型`。

以上结论来自独立逆向项目 [aimod-cc/agent2api](https://github.com/aimod-cc/agent2api) 的 `providers/autoclaw/*`，并已在本机按同法实测逐条复现。

## 远程部署说明

本插件的 OAuth 需要在插件进程本机监听官方白名单端口（18432 等）并在本机浏览器打开 `http://127.0.0.1:<port>/`。如果 magpie 跑在远程服务器且浏览器在你本机，**优先使用「AutoClaw 授权链接登录」**（第二种登录方式）：引导页托管在公网 HTTPS，不依赖 `127.0.0.1`，登录后把回调 URL 粘回 magpie 即可。

若坚持用第一种「网页登录」，必须 SSH 端口转发：

```sh
ssh -N -L 18432:127.0.0.1:18432 user@server
```

### 常见登录失败

| 现象 | 原因 | 处理 |
|---|---|---|
| 打开引导页白屏 | 方式1 在本机浏览器打开 `127.0.0.1:18432`，而 magpie 在远程 | 改用「授权链接登录」，或做上文的 SSH 转发 |
| `631001 抱歉,登录失败,请重新尝试` | 授权与兑换的 `device_id` 不一致（用了旧链接/方式1 页面） | 从 magpie 面板重新点「授权链接登录」，用新弹出的链接完成授权后立刻粘回 |
| `630014 抱歉,审核失败,请重新尝试` | 阿里云滑块回执无效/过期 | 回引导页重新过滑块后马上继续 |
| `400001 请求数据有问题` | 缺少 `ali_captcha_verify_param` 或参数不全 | 用全新打开的引导页，勿手工拼参数 |
| 测试模型 405 / 看到 `<!doctypehtml>` WAF 页 | 出站 `User-Agent` 不是 `AutoClaw/*` | 升级到 ≥ v0.7.0（已强制设置 UA） |
| 测试模型 406 空响应体 | ① `max_tokens` 是小正整数；② 误发 `X-Harness-Type: zcode`；③ **经网关时 system 首句不合白名单** | 升级到 ≥ v0.8.0（已自动抬 `max_tokens`、已移除该头、已自动规范化 system 提示词） |
| **插件直调 200、经 magpie 网关 406** | 网关注入了自己的 system 提示词，未满足上游白名单（第 5 道闸） | 升级到 ≥ v0.8.0（出站前自动前置 OpenClaw 身份前缀 + 改写外来身份句） |
| 测试模型 403 `pay-view` / `810001` | 上游高峰期限流或额度提示（**非** bug） | 稍后重试；持续出现说明该账号免费额度已用尽 |
| 测试模型 `400 非法模型` | 发了无前缀的模型名，或选了已下架模型 | 升级到 ≥ v0.7.0（已按真实目录收敛模型表） |

## 开发与测试

```sh
node --check index.mjs          # 语法检查
node --test tests/index.test.mjs  # 纯函数单测（无网络，Node ≥ 18 自带 test runner）
```

可测辅助函数经 `_internal` 导出；涉及上游交互的函数（`dailySignin` / `signinStatus` / `refreshTokens` 等）需真实凭据，不在 CI 覆盖范围。

本地完整验证（沙箱 HOME，不影响本机配置）：

```sh
magpie plugin add ./            # 在包目录内
magpie plugin                   # 检查钩子加载
```

## 致谢与免责声明

本插件基于 [hubo1989/opencode-autoclaw-auth](https://github.com/hubo1989/opencode-autoclaw-auth)（MIT 协议）构建，签到/登录/刷新协议实现来自其作者的逆向分析与实测，原始版权声明见 [LICENSE](LICENSE)，在此致谢。

本项目为**非官方**社区插件，与智谱 AI / OpenClaw / AutoClaw 无任何关联。使用本插件产生的账号风险（包括但不限于违反上游服务条款导致的限制或封禁）由使用者自行承担。上游协议变更可能导致插件随时失效。

## License

MIT
