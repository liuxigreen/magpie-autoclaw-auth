/**
 * magpie-autoclaw-auth —— magpie/OpenCode provider 插件：AutoClaw（智谱）。
 *
 * 单供应商：autoclaw（国际版，Google / z.ai 邮箱网页 OAuth 登录）。
 * 功能：登录、token 自动轮换、积分余额（auth.usage）、原生每日签到（auth.checkin，
 * magpie ≥ v0.1.1083）、旧链路自动补签（默认关）。
 *
 * Based on opencode-autoclaw-auth by hubo1989 (MIT License).
 *
 * 国际版网页 OAuth —— 完整本地实现，不依赖 workbuddy2api / opencodex 面板。
 *
 * 宿主协议形态：authorize(inputs) 启动本地临时 HTTP 服务器（127.0.0.1 上
 * 官方 TokenServer 端口池之一），立即返回 { url: 本地引导页, method: "auto", callback }；
 * 浏览器全流程在本地页完成：
 *
 *   引导页(内嵌) ──拉 /captcha-config──▶ 未启用滑块 ──▶ 直接「继续授权」
 *                     │启用
 *                     ▼
 *              加载 AliyunCaptcha SDK(CDN) → 用户拖滑块 → 回执 POST /captcha
 *                     ▼
 *   「继续授权」──POST /open-auth──▶ 插件带回执调上游 {vendor}-oauth-url
 *                     ▼
 *        页面自动跳授权页（Google/z.ai）→ 302 回 /callback?code=…&state=…
 *                     ▼
 *        callback() 里用 code 调 {vendor}-oauth-login 换 token → {type:"success"}
 */

import { createHash, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { Buffer } from "node:buffer";
import * as http from "node:http";
import { spawn } from "node:child_process";

const APP_ID = "100003";
const APP_KEY = "38d2391985e2369a5fb8227d8e6cd5e5";
const PRODUCT = "autoclaw";
const CHANNEL = "AutoClaw4";
const CLIENT_VERSION = "1.18.1";
/**
 * 平台标识（源实现 `platformTm()` / agent2api `adapter.rs::platform_tm()`）。
 *
 * 🔴 **linux 必须回落成 `win`，不能发 `linux`** —— 这是本插件在服务器上跑
 * 必然失败的直接原因。上游只认官方桌面端存在的平台（Windows / macOS）；
 * 实测 `X-Tm: linux` 被拒（403 `{"message":"forbidden"}` / 405 / 406），
 * 而 `win` / `mac` / 不带该头都放行。进一步二分：上游只拒绝**恰好等于
 * `linux`** 的值，`windows` / `other` 也都放行。
 *
 * 依据：agent2api `providers/autoclaw/adapter.rs` 模块头第 4 条「平台绑定」
 * （2026-10-08，#115/PR #116）与 `platform_tm()` 实现：
 *   `if cfg!(target_os = "macos") { "mac" } else { "win" }`
 * 服务端/Docker 镜像恒在 Linux 上，容器里不存在「真实桌面平台」可选，
 * 故非 macOS 一律回落 `win`。
 */
const PLATFORM_TM = process.platform === "darwin" ? "mac" : "win";
const USER_AGENT = `AutoClaw/${CLIENT_VERSION} (${PLATFORM_TM}-arm64)`;

const GLOBAL_HOST = "https://autoglm-api.autoglm.ai";
// 🔴 国内版是「加速域」，不是主站：实测 autoglm-api.zhipuai.cn 一律 410000/401，
// 正确基址是 autoglm-acceleration-api.zhipuai.cn（来源：agent2api 的 region.rs）。
// ⚠️ 社区版用的是主站 autoglm-api.zhipuai.cn —— 那条会 401/410000，别照抄。
const CN_HOST = "https://autoglm-acceleration-api.zhipuai.cn";

/**
 * CN ↔ 全球互备：按账号来源给 host 排序。
 *
 * 上游账号是「分区」的 —— 国内短信账号只在 CN 侧认，Google/z.ai 账号只在全球侧认。
 * 拿错侧调会 401/403，所以要**先挑对家，再谈切换**。
 *
 * 判定依据是 refresh token 的 JWT claim `source_id`：
 *   `agent*`（agent / agent-cn / …）→ 国内短信账号 → CN 优先
 *   其余（google / zai / …）        → 国际账号     → 全球优先
 *
 * 🔴 实测（实测 真实账号）：上游填的其实是**带后缀的 token 种类**
 * `access_token` / `refresh_token`，形如：
 *   国内号（<account-b>）  → `source_id = "agentrefresh_token"` / `"agentaccess_token"`
 *   国际号 → `source_id = "autoclawrefresh_token"` / `"autoclawaccess_token"`
 * 所以 `^agent` 前缀判定依然成立，且 `autoclaw` 以 `a` 开头但**不会**被误判成 `agent`
 * （逐字比对已验证）。社区版同规则。
 *
 * 拿不到 refresh（例如只有 access）时退回全局优先 —— 国际版是绝大多数情况。
 * 与社区版 `refreshTokens()` 的排序规则保持一致。
 */
function isSmsAccountToken(token) {
  return /^agent/i.test(String(jwtClaim(bareToken(token), "source_id") ?? ""));
}

/** 返回 [首选 host, 备选 host]（去重、去空）。 */
function hostsForAuth(auth) {
  const sources = [auth?.refresh, auth?.access].filter(Boolean);
  let sms = false;
  for (const t of sources) {
    const s = jwtClaim(bareToken(t), "source_id");
    if (s) { sms = /^agent/i.test(String(s)); break; }
  }
  return sms ? dedupe([CN_HOST, GLOBAL_HOST]) : dedupe([GLOBAL_HOST, CN_HOST]);
}

// 🔴 路径不带 `/v1`：upstreamPath = '/chat/completions'（源实现 forwardModelRequest）。
// ⚠️ 2026-10-17 A/B 实测修正：**带 `/v1` 也能通**（同 token 单变量：带/不带都是 200）。
// 真正触发 406 的是 `X-Harness-Type: zcode` 这个头，与路径无关。此处仍保留无 `/v1`
// 的写法，因为它是源实现的原样路径，不是因为我们验证过 `/v1` 会失败。
const CHAT_PATH = "/autoclaw-proxy/proxy/autoclaw/chat/completions";
const WALLETS_PATH = `/agent-assetmgr/api/v2/wallets?biz_app_id=${PRODUCT}`;

const OAUTH_EXPIRY_SKEW_MS = 10 * 60 * 1000;
const FALLBACK_EXPIRES_IN_S = 5 * 3600;

/**
 * 模型清单：键 = magpie 里显示的 id（客户端选它）；值里的 id = 上游 **routeModelId**
 * （`X-Request-Model` 要发的那个，带通道前缀）。
 *
 * 🔴 两个 id 不能混：`X-Request-Model` 必须带路由前缀（`zaicoding_` / `zai_`），
 * `body.model` 必须是剥掉前缀的名字。发反了上游一律 `400 非法模型`（实测：
 * `X-Request-Model: glm-5.3` → 400；`zaicoding_glm-5.3` → 200）。
 *
 * 本表**按上游真实目录收敛**（权威来源：`GET .../autoclaw-model-config`，
 * 2026-10-16 在 DMIT 实测，国内/国际版各 4 条）：
 *   zai_auto(文本+图) / zai_auto-fast / zaicoding_glm-5.3 / zai_glm-5.3-flash
 * 旧表里的 `zai_glm-5-turbo`、`tdpsk_deepseek-v4-*` 实测全部 `400 非法模型`
 * （上游已下架），保留它们只会让用户选中一个必然报错的模型 —— 故移除。
 *
 * 注意 provider 的 `api` 基址为裸 host，SDK 会拼 `/v1/chat/completions`；
 * 实际出站路径由 loader 的 `CHAT_PATH` 覆写，与此表无关。
 */
function autoclawModels() {
  return {
    "zai_auto": { name: "Auto", id: "zai_auto", limit: { context: 1048576, output: 131072 }, reasoning: true, tool_call: true },
    "zai_auto-fast": { name: "Auto Fast", id: "zai_auto-fast", limit: { context: 1048576, output: 393216 }, reasoning: true, tool_call: true },
    "zaicoding_glm-5.3": { name: "GLM-5.3", id: "zaicoding_glm-5.3", limit: { context: 1048576, output: 307200 }, reasoning: true, tool_call: true },
    "zai_glm-5.3-flash": { name: "GLM-5.3-Flash", id: "zai_glm-5.3-flash", limit: { context: 1048576, output: 131072 }, reasoning: true, tool_call: true },
  };
}

/** 路由前缀表（剥前缀用；**顺序有意义**：先 `zaicoding_` 再 `zai_`）。 */
const ROUTE_PREFIXES = ["zaicoding_", "zai_"];

/** 剥掉已知路由前缀：`zaicoding_glm-5.3` → `glm-5.3`。 */
function stripRoutePrefix(routeId) {
  for (const p of ROUTE_PREFIXES) {
    if (routeId.startsWith(p)) return routeId.slice(p.length);
  }
  return routeId;
}

/**
 * 客户端给的模型名 → 上游路由 ID（`X-Request-Model`）。
 *
 * 客户端可以是三种写法，统一解析到**规范 routeId**（依据 agent2api
 * `providers/autoclaw/models.rs::resolve_model_route`）：
 *   1. 路由 ID 本身（`zaicoding_glm-5.3`）→ 原样；
 *   2. 目录名 / 展示名（`glm-5.3` / `GLM-5.3-Flash`）→ 查表得规范 routeId；
 *   3. 已带未知前缀的 `x_yyy` 形态 → 原样透传（上游自己认）。
 * 都不中时回落 `zai_auto`（与源实现的非严格模式一致）。
 *
 * 🔴 为什么必须查表而不是「把 body.model 直接当路由 ID 发」：
 * 那样会发成 `glm-5.3`（无前缀）→ 上游 `400 非法模型` —— 这正是旧版
 * 「测试模型失败」的第二个成因（实测见诊断报告第三节）。
 */
function resolveRouteId(clientModel) {
  const name = String(clientModel ?? "").trim();
  if (!name) return "zai_auto";
  const lower = name.toLowerCase();

  // 1) 路由 ID 本身（含大小写变体）：表里的 id 就是 routeId
  for (const [id, meta] of Object.entries(autoclawModels())) {
    if (id.toLowerCase() === lower) return meta.id;
  }
  // 2) 目录名 / 展示名：剥前缀后比对
  const stripped = stripRoutePrefix(lower);
  for (const meta of Object.values(autoclawModels())) {
    if (stripRoutePrefix(meta.id).toLowerCase() === stripped) return meta.id;
  }
  // 2b) 展示名（`GLM-5.3` / `Auto Fast`）
  for (const meta of Object.values(autoclawModels())) {
    if (String(meta.name).toLowerCase() === lower) return meta.id;
  }
  // 3) 已带未知前缀的合法路由形态：原样透传（上游自己判定）
  if (/^[a-z][a-z0-9]*_[A-Za-z0-9._:-]{1,127}$/.test(name)) return name;
  // 4) 未知名字：回落默认路由（源实现非严格模式）
  return "zai_auto";
}

// ---------------------------------------------------------------------------
// 基础工具
// ---------------------------------------------------------------------------

function md5Hex(input) {
  return createHash("md5").update(input).digest("hex");
}

function randomHex(n) {
  return randomBytes(n).toString("hex");
}

/** 64 位十六进制 device_id（官方客户端形态）。 */
function newDeviceId() {
  return randomHex(32);
}

/** 业务签名头（task/wallet/登录/refresh），WAF 要求带客户端 UA。 */
function bizHeaders(accessToken) {
  const ts = String(Math.floor(Date.now() / 1000));
  const h = {
    "Content-Type": "application/json",
    "Accept": "*/*",
    "User-Agent": USER_AGENT,
    "X-Version": CLIENT_VERSION,
    "X-Tm": PLATFORM_TM,
    "X-Product": PRODUCT,
    "X-Auth-Appid": APP_ID,
    "X-Auth-TimeStamp": ts,
    "X-Auth-Sign": md5Hex(`${APP_ID}&${ts}&${APP_KEY}`),
    "X-Trace-Id": randomHex(16),
    "X-Lang": "zh-CN",
    "X-Channel": CHANNEL,
    "Origin": "http://localhost:18432",
    "Referer": "http://localhost:18432/",
  };
  if (accessToken) h["Authorization"] = `Bearer ${accessToken}`;
  return h;
}

function nonEmptyString(v) {
  return typeof v === "string" && v.length > 0 ? v : undefined;
}

/**
 * 上游对出站 body 的 `max_tokens` 有预校验：**小正整数一律 406 空响应体**。
 *
 * 实测（agent2api `providers/autoclaw/adapter.rs::normalize_max_tokens` 的结论，
 * 本仓库在 DMIT 上按同法复现，逐格一致）：
 *   max_tokens 缺省   → 200
 *   max_tokens=256    → 406 空体
 *   max_tokens=4096   → 406 空体
 *   max_tokens=8192   → 406 空体
 *   max_tokens=10000  → 200 ✓
 *   max_tokens=131072 → 200 ✓
 * 下界落在 8192（拒）与 10000（过）之间，取实测安全值 10000。
 *
 * 绝大多数 OpenAI 客户端 / SDK 默认带 `max_tokens`（4096 / 2048 / 1024…），
 * 所以「某些客户端 100% 406 且响应体为空」的真正变量就是它 —— 而不是提示词
 * 或登录态。本函数只抬「小正整数」这一种形态，其余原样交上游：
 *   - 缺省 / null / 非正整数 / 浮点 / 字符串 → 不动（不凭猜测注入或改写）；
 *   - `0` / 负数 → 不动（那是请求方语义错误，交上游报错）；
 *   - `max_completion_tokens` → 一字不动（实测不参与该校验）。
 *
 * @param {object} body 已解析的请求体（就地修改）
 * @returns {boolean} 是否真的改写了（调用方据此决定要不要重建 init）
 */
function normalizeMaxTokens(body) {
  const MIN = 10_000;
  if (!body || typeof body !== "object") return false;
  const v = body.max_tokens;
  if (typeof v !== "number" || !Number.isInteger(v)) return false;
  if (v <= 0 || v >= MIN) return false;
  body.max_tokens = MIN;
  return true;
}

/**
 * 出站身份句（官方 system prompt 的第一句，逐字照抄）。
 * 上游闸门要求首条 system / developer 消息的正文**以它开头**。
 */
const IDENTITY_LINE = "You are a personal assistant running inside OpenClaw.";

/**
 * 出站身份前缀 = 身份句 + `## Tooling` 段（官方 prompt 的开头两行，逐字照抄）。
 *
 * 🔴 缺 `## Tooling` 段 → 403 pay-view；只有身份句 → 403 pay-view；
 * 两者齐备 → 200。这不是「建议」，是硬闸门。
 *
 * 来源：agent2api `providers/autoclaw/prompt.rs::IDENTITY_PREFIX`（`resources/
 * gateway/openclaw/dist/system-prompt-config-*.js` 的 `buildSystemPrompt` 开头）。
 */
const IDENTITY_PREFIX =
  "You are a personal assistant running inside OpenClaw.\n\n" +
  "## Tooling\n" +
  "Available tools are policy-filtered. Names are case-sensitive; call exactly as listed.\n";

/**
 * 外来身份句 → 中性说法（**长的必须在前**）。
 *
 * 上游对 system 首句做**逐字指纹**拦截：命中 `<产品名> 的 harness 身份句` 就
 * 406 空体。把产品名换成中性说法即可放行。
 *
 * 🔴 排序纪律：短的在前会把长匹配串切碎 —— 先命中 `You are ZCode` 就再也匹配
 * 不到 `You are ZCode, an interactive coding agent`，于是「改写后仍含产品名」
 * 的半吊子结果原样出站被拦。**新词条一律按长度降序插**。
 *
 * 🔴 匹配**忽略大小写**：闸门自己就不敏感（把 `DeepSeek` 的 e 写成 E 仍 406），
 * 替换若敏感，同一句指纹换个大小写就漏网。
 *
 * 实测口径：国内版 ZCode / Claude Code / 老 Codex CLI 三句实测过「改写后 200」；
 * 国际版 DeepSeek Harness 与新版 Codex 首句实测过「原样 406」。
 */
const FOREIGN_IDENTITIES = [
  ["You are ZCode, an interactive coding agent", "You are an interactive coding agent"],
  ["You are a coding agent running in the Codex CLI tool", "You are a coding agent running in a terminal CLI tool"],
  ["You are a coding agent running in the Codex CLI", "You are a coding agent running in a terminal CLI"],
  ["You are running as a coding agent in the Codex CLI", "You are running as a coding agent in a terminal CLI"],
  ["You are Claude Code", "You are a coding assistant"],
  ["You are ZCode", "You are an interactive coding agent"],
  ["You are an AI agent powered by DeepSeek Harness", "You are an AI agent powered by a local coding harness"],
  ["You are Codex", "You are a coding agent"],
];

/** 角色是否承载 system 级指令：**精确**等于 `system` / `developer`，其余一律不动。 */
function isSystemRole(message) {
  if (!message || typeof message !== "object") return false;
  const role = message.role;
  return role === "system" || role === "developer";
}

/**
 * `from` 在 `text` 里首次出现的**字节下标**（只折叠 ASCII 大小写）。
 *
 * 不用 `toLowerCase()` 再找：Unicode 折叠会改变字节长度（`İ` 折成两个字符），
 * 折后的下标回不到原文，切片就错位。这里按字节滑窗 + 逐字节 ASCII 折叠比较
 * （`from` 全是 ASCII，非 ASCII 字节 >= 0x80 不可能匹配），起止点必在字符边界。
 */
function findIgnoreAsciiCase(text, from) {
  const hay = Buffer.from(text, "utf8");
  const needle = Buffer.from(from, "utf8");
  if (needle.length === 0 || hay.length < needle.length) return null;
  outer: for (let start = 0; start <= hay.length - needle.length; start++) {
    for (let i = 0; i < needle.length; i++) {
      let a = hay[start + i];
      let b = needle[i];
      if (a >= 0x41 && a <= 0x5a) a += 0x20;
      if (b >= 0x41 && b <= 0x5a) b += 0x20;
      if (a !== b) continue outer;
    }
    return start;
  }
  return null;
}

/** `from` 在 `text` 里**全量**替换（忽略 ASCII 大小写）；未命中返回 null（不动原串）。 */
function replaceAllIgnoreAsciiCase(text, from, to) {
  if (findIgnoreAsciiCase(text, from) === null) return null;
  const hay = Buffer.from(text, "utf8");
  const needle = Buffer.from(from, "utf8");
  const parts = [];
  let offset = 0;
  let cursor = 0;
  for (;;) {
    const rel = findIgnoreAsciiCase(hay.subarray(offset).toString("utf8"), from);
    if (rel === null) break;
    // 相对下标（字符）→ 绝对字节下标：在剩余子串上做同样的字节窗扫描。
    const rest = hay.subarray(offset);
    let byteRel = null;
    outer: for (let start = 0; start <= rest.length - needle.length; start++) {
      for (let i = 0; i < needle.length; i++) {
        let a = rest[start + i];
        let b = needle[i];
        if (a >= 0x41 && a <= 0x5a) a += 0x20;
        if (b >= 0x41 && b <= 0x5a) b += 0x20;
        if (a !== b) continue outer;
      }
      byteRel = start;
      break;
    }
    if (byteRel === null) break;
    parts.push(hay.subarray(cursor, offset + byteRel).toString("utf8"));
    parts.push(to);
    cursor = offset + byteRel + needle.length;
    offset = cursor;
  }
  parts.push(hay.subarray(cursor).toString("utf8"));
  return parts.join("");
}

/** 逐条套用 {@link FOREIGN_IDENTITIES}（全量替换；忽略大小写）。 */
function rewriteIdentities(text) {
  let out = text;
  for (const [from, to] of FOREIGN_IDENTITIES) {
    const next = replaceAllIgnoreAsciiCase(out, from, to);
    if (next !== null) out = next;
  }
  return out;
}

/** 就地改写 content（字符串 / 文本 part 数组）里的外来身份句。 */
function rewriteIdentitiesInPlace(content) {
  if (typeof content === "string") return rewriteIdentities(content);
  if (Array.isArray(content)) {
    return content.map((part) => {
      if (part && typeof part === "object" && typeof part.text === "string") {
        return { ...part, text: rewriteIdentities(part.text) };
      }
      return part;
    });
  }
  return content;
}

/** 前缀 + 空行 + 原文（原文为空则不留多余空行）。 */
function joinPrefix(original) {
  if (!original) return IDENTITY_PREFIX;
  return `${IDENTITY_PREFIX}\n${original}`;
}

/** 给一条消息的 content 前置身份前缀（已以身份句开头则一字不动）。 */
function prependPrefix(message) {
  const content = message.content;
  if (typeof content === "string") {
    if (content.startsWith(IDENTITY_LINE)) return message;
    return { ...message, content: joinPrefix(content) };
  }
  if (Array.isArray(content)) {
    const idx = content.findIndex((part) => part && typeof part.text === "string");
    if (idx === -1) {
      return { ...message, content: [{ type: "text", text: IDENTITY_PREFIX }, ...content] };
    }
    const part = content[idx];
    if (part.text.startsWith(IDENTITY_LINE)) return message;
    const next = content.slice();
    next[idx] = { ...part, text: joinPrefix(part.text) };
    return { ...message, content: next };
  }
  // content 缺字段 / null / 对象 / 数字：这种 content 当 system 提示词本就不成立
  // （上游当空提示词 → 稳定 406），换成前缀本身。
  return { ...message, content: IDENTITY_PREFIX };
}

/**
 * 出站前规范化 body 里的 system 提示词（**就地修改** `body.messages`）。
 *
 * 🔴 这是经 magpie 网关转发时**唯一**会 406 的原因：网关会把自己注入的 system
 * 提示词一并发出去，而该 system 不满足上游白名单（必须是 OpenClaw 身份句开头 +
 * `## Tooling` 段，且不得含外来 harness 身份句）。
 *
 * 两步：
 *   ① 所有 system / developer 消息里的**外来身份句改写**成中性说法；
 *   ② 保证**首条**消息是 system / developer 且正文以身份句开头 —— 是则前置
 *      前缀（客户端提示词逐字保留在后面），否则在 `messages[0]` 插一条只带前缀
 *      的 system 消息（**不重排**后面那些 system 消息的位置：重排消息序列会破坏
 *      客户端的轮次结构，风险远大于收益）。
 *
 * 边界（与 prompt.rs 同口径）：
 *   - **只动 system / developer**，user / assistant / tool 一律不碰（不碰用户内容）；
 *   - **不替换、也不追加** system 消息，只在首条不是 system 时**插入**一条；
 *   - `messages` 缺失或不是数组 → 直接返回（交给上游报格式错误比在这里造一个
 *     空 `messages` 更能说明问题）。
 *
 * 幂等：正文已以 {@link IDENTITY_LINE} 开头时只改写、不再前置。
 *
 * @param {object} body 已解析的请求体（就地修改）
 * @returns {boolean} 是否真的改写了（调用方据此决定要不要重建 init）
 */
function normalizeSystemPrompt(body) {
  if (!body || typeof body !== "object") return false;
  const messages = body.messages;
  if (!Array.isArray(messages)) return false;

  const before = JSON.stringify(messages);

  const next = messages.map((message) => {
    if (!isSystemRole(message)) return message;
    const rewritten = rewriteIdentitiesInPlace(message.content);
    const withContent =
      rewritten === message.content ? message : { ...message, content: rewritten };
    return withContent;
  });

  if (next.length > 0 && isSystemRole(next[0])) {
    next[0] = prependPrefix(next[0]);
  } else {
    next.unshift({ role: "system", content: IDENTITY_PREFIX });
  }

  body.messages = next;
  return JSON.stringify(next) !== before;
}

/** 剥掉 token 上误带的 "Bearer " 前缀（老凭据/代理回包可能带；7863 侧同样的容错）。 */
function bareToken(v) {
  let t = String(v ?? "").trim();
  while (t.toLowerCase().startsWith("bearer ")) t = t.slice(7).trim();
  return t;
}

function dedupe(values) {
  return [...new Set(values.filter(Boolean))];
}

/** 读 JWT payload 字段（不校验签名——只取自己账号的 device_id / exp）。 */
function jwtClaim(token, key) {
  const raw = bareToken(token);
  const part = raw.split(".")[1];
  if (!part) return undefined;
  try {
    const json = Buffer.from(part.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
    return JSON.parse(json)[key];
  } catch {
    return undefined;
  }
}

/** access token 真实过期时间（epoch ms）。 */
function jwtExpiresAtMs(token) {
  const exp = jwtClaim(token, "exp");
  return typeof exp === "number" && Number.isFinite(exp) && exp > 0 ? exp * 1000 : undefined;
}

async function callEnvelope(path, { method = "GET", body, base }) {
  let response, text;
  try {
    response = await fetch(`${base}${path}`, {
      method,
      headers: bizHeaders(),
      ...(body !== undefined ? { body } : {}),
    });
    text = await response.text();
  } catch (cause) {
    throw Object.assign(new Error(`AutoClaw request failed: ${cause?.message ?? cause}`), { cause });
  }
  let parsed;
  try { parsed = text ? JSON.parse(text) : undefined; } catch { parsed = undefined; }
  if (!parsed || (parsed.code === undefined && response.status >= 400)) {
    throw new Error(`AutoClaw ${path.split("?")[0]} non-envelope response (HTTP ${response.status}): ${text.slice(0, 200)}`);
  }
  return { status: response.status, code: parsed.code, msg: parsed.msg, data: parsed.data };
}

/** token 响应 → magpie 凭据字段（不含 type——由 magpie 按 oauth 方式包装）。 */
function tokenFields(data, fallbackRefresh) {
  const access = bareToken(nonEmptyString(data.access_token));
  if (!access) throw new Error("AutoClaw token response contained no access_token");
  const refresh = bareToken(nonEmptyString(data.refresh_token) ?? fallbackRefresh);
  if (!refresh) throw new Error("AutoClaw token response contained no refresh_token");
  // expires_in 常缺省；JWT exp 才是事实来源（约 24h）。按 5h 记会白跑 refresh（轮换有吊销风险）。
  const jwtExpires = jwtExpiresAtMs(access);
  const expiresInS = typeof data.expires_in === "number" && data.expires_in > 0 ? data.expires_in : undefined;
  const expires = jwtExpires !== undefined
    ? jwtExpires - OAUTH_EXPIRY_SKEW_MS
    : Date.now() + (expiresInS ?? FALLBACK_EXPIRES_IN_S) * 1000 - OAUTH_EXPIRY_SKEW_MS;
  return { access, refresh, expires };
}

// ---------------------------------------------------------------------------
// 签到与积分
// ---------------------------------------------------------------------------

async function fetchWallets(accessToken, hosts) {
  for (const host of dedupe(hosts)) {
    let payload;
    try {
      const res = await fetch(host + WALLETS_PATH, {
        method: "GET",
        headers: bizHeaders(accessToken),
        redirect: "error",
        signal: AbortSignal.timeout(20_000),
      });
      if (!res.ok) continue;
      payload = await res.json();
    } catch { continue; }
    if (!payload || payload.code !== 0 || !payload.data) continue;
    return payload.data;
  }
  return null;
}

/** 每日签到（幂等）。返回解析后的结果（可能为 null）。 */
async function dailySignin(accessToken, host) {
  try {
    const res = await fetch(`${host}/autoclaw-proxy/proxy/autoclaw-task-complete`, {
      method: "POST",
      headers: bizHeaders(accessToken),
      body: JSON.stringify({ task_id: "daily_signin", source_id: PRODUCT }),
      signal: AbortSignal.timeout(15_000),
    });
    const env = await res.json().catch(() => null);
    return env?.data ?? null; // { success, already_completed, reward_points, continuous_days }
  } catch {
    return null;
  }
}

/** 查任务列表；401/403 throw（登录失效），HTTP 其他失败/非 envelope 返回 null，网络错误 throw。 */
async function taskList(accessToken, host) {
  const res = await fetch(`${host}/autoclaw-proxy/proxy/autoclaw-task-list`, {
    method: "GET",
    headers: bizHeaders(accessToken),
    signal: AbortSignal.timeout(15_000),
  });
  if (res.status === 401 || res.status === 403) {
    throw new Error(`登录已失效（HTTP ${res.status}）`);
  }
  if (!res.ok) return null;
  const env = await res.json().catch(() => null);
  return Array.isArray(env?.data) ? env.data : null;
}

/** 查询 daily_signin 任务状态（容错版：任何失败返回 null）。 */
async function signinStatus(accessToken, host) {
  try {
    const tasks = await taskList(accessToken, host);
    if (!tasks) return null;
    const t = tasks.find((x) => x?.task_id === "daily_signin");
    return t ? { status: String(t.status ?? ""), desc: String(t.status_description ?? ""), reward: Number(t.reward_points ?? 0) } : null;
  } catch {
    return null;
  }
}

/** 可选数字：>0 才返回，否则 undefined（checkin 的 credit/streak 允许缺省）。 */
function optNumber(v) {
  const n = Number(v);
  return Number.isFinite(n) && n > 0 ? n : undefined;
}

/** dailySignin 结果 → magpie 原生 checkin outcome（{outcome, credit?, streak?, message?}）。 */
function checkinOutcome(r) {
  if (!r) return { outcome: "failed", message: "签到接口无响应" };
  if (r.success) {
    return {
      outcome: "claimed",
      credit: optNumber(r.reward_points),
      streak: optNumber(r.continuous_days),
      message: `已签到${r.reward_points ? ` +${r.reward_points}` : ""}${r.continuous_days ? ` · 连续 ${r.continuous_days} 天` : ""}`,
    };
  }
  if (r.already_completed) return { outcome: "done", credit: optNumber(r.reward_points) };
  return { outcome: "failed", message: String(r.message ?? r.msg ?? "签到失败") };
}

/** 本地去重键（成功才记；按小时允许重试）。 */
const signinTriedLocal = new Map(); // key → hour-stamp of last SUCCESSFUL signin

/**
 * 签到配置合并：插件 options（plugins.json 的 options 字段）优先，
 * 其次配置文件 ~/.config/magpie/autoclaw.json（热读取，GUI 没有选项入口时的保底通道）：
 *   { "signin": true, "signinHour": null, "signinOnUsage": false }
 * 两处都没有 → signin=true、signinOnUsage=false（自动补签默认关：
 * 签到交给 magpie 原生 checkin 开关；旧版宿主/需要旧行为时显式开 signinOnUsage）。
 */
function signinConfig(options) {
  let fileCfg = {};
  try {
    // magpie 配置目录固定（文档：~/.config/magpie 或 $XDG_CONFIG_HOME/magpie）
    const cfgDir = process.env.XDG_CONFIG_HOME
      ? `${process.env.XDG_CONFIG_HOME}/magpie`
      : `${process.env.HOME ?? ""}/.config/magpie`;
    fileCfg = JSON.parse(readFileSync(`${cfgDir}/autoclaw.json`, "utf8"));
  } catch { /* 无文件/解析失败 → 用默认 */ }
  const merged = { ...fileCfg, ...(options ?? {}) };
  return {
    signin: merged.signin !== false,               // 自动补签总开关（默认开）
    signinOnUsage: merged.signinOnUsage === true,  // usage/refresh 链路自动补签（默认关，见上）
    signinHour: typeof merged.signinHour === "number" ? merged.signinHour : null,
  };
}

/** 依据合并配置决定是否补签（usage/refresh 旧链路；原生 checkin 不经过这里）。 */
async function maybeSignin(accessToken, host, options, reason, accountKey) {
  void reason;
  const cfg = signinConfig(options);
  if (!cfg.signin || !cfg.signinOnUsage) return;
  if (cfg.signinHour !== null && new Date().getHours() !== cfg.signinHour) return;
  const hourStamp = `${new Date().toISOString().slice(0, 13)}`; // YYYY-MM-DDTHH（每小时可重试一次）
  const dayKey = `${accountKey ?? "x"}`;
  const lastOk = signinTriedLocal.get(dayKey);
  if (typeof lastOk === "string" && lastOk.slice(0, 10) === hourStamp.slice(0, 10)) return; // 今天已成功
  const r = await dailySignin(accessToken, host);
  if (r && (r.success || r.already_completed)) {
    signinTriedLocal.set(dayKey, hourStamp);
  }
}

// ---------------------------------------------------------------------------
// 用户资料（GUI 账户命名：昵称/手机号，替代无意义的 uid 哈希 → 「已登录」）
// ---------------------------------------------------------------------------

/** POST /userapi/v1/user-profile → { user_name, user_phone, user_id, … }；失败返回 null。 */
async function fetchUserProfile(accessToken, base) {
  try {
    const res = await fetch(`${base}/userapi/v1/user-profile`, {
      method: "POST",
      headers: bizHeaders(accessToken),
      body: JSON.stringify({ source_id: PRODUCT, device_id: "magpie-plugin" }),
      signal: AbortSignal.timeout(15_000),
    });
    if (!res.ok) return null;
    const env = await res.json().catch(() => null);
    const d = env?.data;
    if (!d || typeof d !== "object") return null;
    return {
      userId: nonEmptyString(d.user_id),
      name: nonEmptyString(d.user_name),
      phone: nonEmptyString(d.user_phone),
    };
  } catch {
    return null;
  }
}

/** GUI 显示名：昵称 > 手机号 > uid（workbuddy 社区插件同款优先级 nickname/phone/uid）。 */
function accountDisplayName(profile, fallback) {
  if (!profile) return fallback;
  return profile.name ?? profile.phone ?? profile.userId ?? fallback;
}

// ---------------------------------------------------------------------------
// 刷新（refresh token 轮换；host 必须与账号来源匹配）
// ---------------------------------------------------------------------------

async function refreshTokens(refreshToken, preferredHosts) {
  const deviceId = nonEmptyString(jwtClaim(refreshToken, "device_id")) ?? "";
  const body = JSON.stringify({ source_id: PRODUCT, device_id: deviceId, refresh_token: refreshToken });
  const isSmsAccount = /^agent/i.test(String(jwtClaim(refreshToken, "source_id") ?? ""));
  const ordered = isSmsAccount
    ? [CN_HOST, GLOBAL_HOST, ...preferredHosts]
    : [GLOBAL_HOST, CN_HOST, ...preferredHosts];

  let result = null;
  for (const base of dedupe(ordered)) {
    result = await callEnvelope("/userapi/v1/refresh", { method: "POST", body, base });
    if (result.code !== 0 && result.code === 400002) {
      result = await callEnvelope("/userapi/v1/agent-refresh", { method: "POST", body, base });
    }
    if (result.code !== 400000) break;
  }
  if (!result) throw new Error("AutoClaw refresh: no host attempted");
  if (result.code !== 0 || !result.data) {
    const dead = result.status === 401 || result.status === 403
      || /invalid[_ ]?grant|revoked|expired|登录已失效|token 失效/i.test(String(result.msg ?? ""));
    const err = new Error(`AutoClaw token refresh failed (HTTP ${result.status}): ${result.msg ?? `code ${result.code}`}`);
    if (dead) err.signIn = "expired";
    throw err;
  }
  return tokenFields(result.data, refreshToken);
}

// ---------------------------------------------------------------------------
// 插件工厂
// ---------------------------------------------------------------------------

function makeAutoclawPlugin({ providerId, providerName, homeHost, loginMethod }) {
  return async ({ client }, options) => ({
    config: async (cfg) => {
      cfg.provider ??= {};
      cfg.provider[providerId] ??= {
        name: providerName,
        npm: "@ai-sdk/openai-compatible",
        api: homeHost,
        models: autoclawModels(),
      };
    },

    auth: {
      provider: providerId,
      // 顺序即 GUI 里的按钮顺序：网页登录优先（体验最顺），
      // 手机验证码次之（无需浏览器，服务器/远程环境最实用），
      // 授权链接兜底（本地页打不开时手动粘贴）。
      //
      // 🔴 去重：autoclaw-cn 把 loginMethod 设成了 phoneSmsMethod，
      //    直接展开会让「手机验证码」出现两次（镜像里点哪个都一样）。
      methods: [...new Set([loginMethod, phoneSmsMethod, manualOauthMethod])],

      async refresh(auth) {
        const t = await refreshTokens(bareToken(auth.refresh), [homeHost]);
        await maybeSignin(t.access, homeHost, options, "refresh", providerId);
        // 存量账号就地正名：登录响应缺昵称的旧账号（GUI 显示「已登录」），
        // 刷新时补拉 user-profile。magpie 的 refresh 返回字段会合并进账号。
        const old = String(auth.accountId ?? auth.email ?? "");
        if (!old || /^(已登录|[0-9a-f]{24,})$/.test(old)) {
          const profile = await fetchUserProfile(t.access, homeHost);
          const name = accountDisplayName(profile, "");
          if (name) {
            t.accountId = name;
            t.email = name;
          }
        }
        return t;
      },

      async loader(getAuth) {
        const auth = await getAuth();
        if (auth?.type !== "oauth" || !auth.access) return {};
        const accessToken = bareToken(auth.access);
        // 🔴 CN ↔ 全球互备：按账号来源排序（国内短信账号 → CN 优先；
        // Google/z.ai 账号 → 全球优先）。拿错侧调会 401，两个方向互为备份。
        const hosts = hostsForAuth(auth);

        return {
          baseURL: hosts[0],
          async fetch(input, init) {
            const headers = new Headers(init?.headers);
            headers.set("X-Authorization", `Bearer ${accessToken}`);
            // 🔴 User-Agent 必须显式设置：本家 chat 端点对 UA 有指纹要求，
            // 运行时默认 UA（bun 的 `Bun/x.y.z` 等）会被上游判成非法客户端
            // → **405 + 阿里云 WAF HTML 页**（不是 406 空体，也不是 403 pay-view）。
            // 实测（DMIT，同请求只改 UA）：
            //   UA=null（bun 默认）               -> 405 ✗
            //   UA="AutoClaw/1.18.1 (win-arm64)"  -> 200 ✓
            //   UA="AutoClaw/1.18.1"              -> 200 ✓
            // ⚠️ 不设它时 bun 会用自己的默认 UA，Headers 里根本看不到该键，
            //    但线上请求带的是 bun 标识 —— 本插件因此长期稳定 405。
            headers.set("User-Agent", USER_AGENT);
            headers.set("X-Client-Type", "pc");
            headers.set("X-Product", PRODUCT);
            // 🔴 绝不发 X-Harness-Type: zcode —— 上游 2026-09-22 起对本家客户端做指纹
            // 甄别：带 `zcode` 稳定 403 pay-view(810001) 或 406 空体；不带、或换成
            // `autoclaw` 都是 200。实测对照（同账号/同模型/同请求体，只改这一个头）：
            //   zcode    -> 406 空体
            //   不带      -> 200 ✓
            //   autoclaw -> 200 ✓
            // 详见 agent2api `providers/autoclaw/adapter.rs` 模块头「上游 2026-09-22
            // 起的两道闸」第 1 条，以及本仓库诊断报告第三节。
            headers.set("X-Tm", PLATFORM_TM);
            headers.set("X-Version", CLIENT_VERSION);
            headers.set("X-Lang", "zh-CN");
            headers.set("X-Channel", CHANNEL);
            headers.set("x_trace_id", "autoclaw-desktop");
            headers.delete("Authorization");

            let routeModel = "";
            let outInit = init;
            try {
              const raw = JSON.parse(String(init?.body ?? "{}"));
              // 🔴 X-Request-Model 必须发**路由 ID**（带 zaicoding_/zai_ 前缀），
              // 不能直接拿 body.model 发 —— 后者是无前缀的目录名，上游回 400 非法模型。
              routeModel = resolveRouteId(raw.model);
              // 🔴 上游对出站 body 的 max_tokens 有预校验（agent2api #58/#69，本仓库实测复现）：
              // 小正整数（30/256/4096/8192…）一律 406 空体；缺省或 ≥10000 才 200。
              // 绝大多数客户端默认带 4096，必须把「小正整数」抬到安全下限，否则必然 406。
              // 🔴 还要规范化 system 提示词：上游对首条 system 的**首句做逐字指纹**
              // （必须 `You are a personal assistant running inside OpenClaw.` 开头 +
              // 带 `## Tooling` 段，且不得含外来 harness 身份句）。
              // **经 magpie 网关转发时这是唯一的 406 来源** —— 网关会注入它自己的
              // system 提示词，而该提示词不满足白名单；插件直调（无网关注入）则天然
              // 满足，所以「插件自测 200、经网关 406」。
              const changedBody = normalizeMaxTokens(raw) | normalizeSystemPrompt(raw);
              if (changedBody) {
                outInit = { ...init, body: JSON.stringify(raw) };
              }
            } catch { /* 保持空 */ }
            if (routeModel) headers.set("X-Request-Model", routeModel);
            headers.set("X-Request-Id", randomHex(16));

            const tryFetch = (host) =>
              fetch(`${host}${CHAT_PATH}`, { ...outInit, headers, signal: outInit?.signal });

            // 🔴 403 不能一律当「登录失效」：上游的 403 有三种形态，只有第一种才是
            // 真失效，另两种是**业务态**，换 host 重试既无意义、还会把真实原因
            // 伪装成「登录失效」让用户白折腾：
            //   ① 403 + `{"message":"forbidden"}`（1KB 内、约 0.9s）→ 平台绑定
            //      不符（X-Tm 平台/账号绑定不一致）—— 换 host 无用，原样返回。
            //   ② 403 + `{"action":{"kind":"pay-view"},"code":810001,…, image_url}`
            //      → 额度/高峰期提示 —— 业务响应，原样返回给客户端（别吞）。
            //   ③ 403 + `{"code":810002,"message":"请求过于频繁…"}` → 限流，原样返回。
            //   ④ 401 → 才可能是 token 真的失效，值得换 host 再试一次。
            const isAuthFailure = (res) => res.status === 401;

            const res1 = await tryFetch(hosts[0]);
            if (isAuthFailure(res1)) {
              const res2 = await tryFetch(hosts[1]);
              if (isAuthFailure(res2)) {
                try { res2.body?.cancel?.(); } catch {}
                return new Response(JSON.stringify({ error: { message: "AutoClaw 登录已失效（两个 host 均拒绝该 token）", type: "invalid_request_error" } }), {
                  status: 401,
                  headers: { "Content-Type": "application/json", "X-Magpie-Sign-In": "expired" },
                });
              }
              return res2;
            }
            return res1;
          },
        };
      },

      async usage(getAuth) {
        const auth = await getAuth();
        if (auth?.type !== "oauth" || !auth.access) return { error: "未登录", windows: [] };
        const hosts = [GLOBAL_HOST, CN_HOST];
        const token = bareToken(auth.access);
        const cfg = signinConfig(options);
        try {
          const [data, signin] = await Promise.all([
            fetchWallets(token, hosts),
            signinStatus(token, hosts[0]).then((s) => s ?? signinStatus(token, hosts[1] ?? hosts[0])),
          ]);
          // 旧链路自动补签（默认关，需 signinOnUsage=true）：查额度即触发。
          // 放在状态查询之后：未签才补，补完重查一次状态展示。
          if (signin && signin.status !== "completed" && (cfg.signin && cfg.signinOnUsage)) {
            await maybeSignin(token, hosts[0], options, "usage", providerId);
          }
          const signinFinal = signin?.status === "completed"
            ? signin
            : (await signinStatus(token, hosts[0]).then((s) => s ?? signinStatus(token, hosts[1] ?? hosts[0])) ?? signin);
          if (!data) return { error: "积分接口无数据（token 可能不属于该 host）", windows: [] };
          const total = Number(data.total_balance);
          if (!Number.isFinite(total)) return { error: "积分响应异常", windows: [] };

          const rows = Array.isArray(data.wallets) ? data.wallets : [];
          const named = rows
            .filter((r) => r.display !== false && Number(r.balance) > 0)
            .map((r) => ({ name: String(r.display_name ?? r.public_wallet_type ?? "积分"), balance: Number(r.balance) }))
            .filter((w) => Math.round(w.balance) !== Math.round(total))
            .slice(0, 3);

          // 签到窗口行 = 状态展示（开关指示交给 magpie 原生 checkin 的 Settings 开关）
          const signinWindow = signinFinal
            ? [{
                name: "每日签到",
                used: signinFinal.status === "completed" ? 0 : 1,
                display: signinFinal.status === "completed"
                  ? `今日已签 ✓${signinFinal.reward ? ` +${signinFinal.reward}` : ""}`
                  : `今日未签（+${signinFinal.reward || 400}）`,
                aside: true,
              }]
            : [];

          return {
            balance: `${Math.round(total)} 积分`,
            windows: [
              { name: "积分余额", used: 0, display: `${Math.round(total)} 积分`, aside: true },
              ...signinWindow,
              ...named.map((w) => ({ name: w.name, used: 0, display: `${Math.round(w.balance)}`, aside: true })),
            ],
          };
        } catch (e) {
          return { error: `积分查询失败: ${e?.message ?? e}`, windows: [] };
        }
      },

      /**
       * 原生每日签到钩子（magpie ≥ v0.1.1083）。由宿主调度：Settings → Usage → Plugins
       * 的 Daily check-in 开关（默认关）控制；每天每账号一次，结果上 Usage 卡片。
       * 契约：返回 {outcome, credit?, streak?, message?}；throw → failed（30 分钟后重试）。
       */
      async checkin(getAuth) {
        const auth = await getAuth();
        if (auth?.type !== "oauth" || !auth.access) throw new Error("未登录");
        const token = bareToken(auth.access);
        const hosts = [GLOBAL_HOST, CN_HOST];

        // 先查任务状态：区分「无签到活动」（inactive）与「查询失败」（throw → failed 重试）
        let task = null;
        let lastErr = null;
        for (const h of hosts) {
          try {
            const tasks = await taskList(token, h);
            if (tasks) {
              task = tasks.find((x) => x?.task_id === "daily_signin") ?? null;
              break;
            }
          } catch (e) { lastErr = e; }
        }
        if (!task && lastErr) throw lastErr;
        if (!task) return { outcome: "inactive", message: "当前没有签到活动" };
        if (String(task.status ?? "") === "completed") {
          return { outcome: "done", credit: optNumber(task.reward_points) };
        }

        // 补签：主 host 优先，无响应再试备用 host（服务端幂等）
        const r = await dailySignin(token, hosts[0]).catch(() => null)
          ?? await dailySignin(token, hosts[1] ?? hosts[0]).catch(() => null);
        return checkinOutcome(r);
      },
    },

    provider: {
      id: providerId,
      async models(provider) {
        return provider.models;
      },
    },
  });
}

// ---------------------------------------------------------------------------
// 登录方式：国际网页 OAuth（本地完整实现：滑块 + 授权 + 回调捕获）
// ---------------------------------------------------------------------------

const overseaOAuthMethod = {
  type: "oauth",
  label: "AutoClaw 网页登录（Google / z.ai）",
  async authorize(inputs) {
    const vendor = inputs?.vendor === "zai" ? "zai" : "google";
    return await startLocalOAuth(vendor);
  },
  prompts: [
    { type: "select", key: "vendor", message: "登录方式",
      options: [
        { label: "Google 账号", value: "google" },
        { label: "z.ai 账号", value: "zai" },
      ] },
  ],
};

// ---------------------------------------------------------------------------
// 登录方式：授权链接手动粘贴（官方 method:"code" 契约）——不伺服本地引导页，
// 适合 127.0.0.1 打不开的环境（远程/代理/浏览器与 magpie 不同机）。
// navigate_uri 仍须用官方 client 注册过的白名单端口（此处不监听，只与上游对齐）。
// ---------------------------------------------------------------------------

// 旧手动粘贴方式的固定 redirect_uri（保留常量以免外部引用断裂；现行实现已改用本地监听）
const MANUAL_REDIRECT_URI = "http://localhost:18432/auth/callback-";
/** 判断粘贴串是否是 OAuth「错误回调」（Google 拒绝授权等），而非成功回调。 */
function isErrorRedirect(raw, code) {
  if (code) return false;
  if (/[?&#]error=/.test(raw)) return true;
  return /(access_denied|cancel|denied|unauthorized)/i.test(raw);
}

/**
 * 把上游 login 的失败码翻译成可操作提示。
 * 631001 = 上游换 token 失败：最常见原因是「授权绑定的 device_id」与「兑换用的 device_id」不一致
 * （即用户点了方式1 或手工复制了不带 device_id 的旧引导页链接），其次才是 code 过期/已使用。
 */
function loginErrorMessage(res, vendor) {
  const code = res?.code;
  const msg = res?.msg ?? `code ${code}`;
  if (code === 631001) {
    return "登录失败: "
      + "上游拒绝了这次兑换（631001）。最可能的原因：授权用的 device_id 与当前会话不一致 —— "
      + "请从 magpie 面板重新点「AutoClaw 授权链接登录」，用它弹出的那一条链接完成授权（不要用收藏/旧链接或方式1 的页面），"
      + "然后在 10 分钟内粘贴返回地址；若仍失败，换 " + (vendor === "zai" ? "Google" : "z.ai") + " 账号再试。";
  }
  if (code === 630014) return `登录失败: 安全验证未通过（630014）。请回引导页重新完成阿里云滑块后立刻继续授权。`;
  if (code === 400001) return `登录失败: 请求参数不完整（400001）。请确认是全新打开的引导页，并粘贴带 code 的完整回调 URL。`;
  if (code === 500009) return `登录失败: 上游服务异常（500009）。稍后重试即可。`;
  return `登录失败: ${msg}`;
}

const manualOauthMethod = {
  type: "oauth",
  label: "AutoClaw 授权链接登录（本地页打不开时用）",
  async authorize(inputs) {
    const vendor = inputs?.vendor === "zai" ? "zai" : "google";
    // 🔴 先试本地监听：浏览器与 magpie 同机时，授权后自动回跳、自动完成登录，
    //    不需要复制粘贴。端口全被占（远程服务器 / 官方桌面端在跑）才降级为粘贴。
    // `inputs.paste === true` 时跳过监听（测试与「明确想走粘贴」的场景）。
    //
    // 🔴 无头环境（远程服务器 / 容器 / WSL 无 GUI）必须直接走粘贴：
    //    Linux 上没有 DISPLAY / WAYLAND_DISPLAY ⇒ 用户不在本机，
    //    local.url 是服务器自己的 127.0.0.1，客户端浏览器必然打不开。
    //    v0.9.2 只按「端口能不能 listen」判断，导致远程场景返回一个打不开的地
    //    址（方式③主路径失效）—— 这里按宿主机环境判断，不再依赖端口偶然失败。
    //    AUTOCLAW_FORCE_PASTE=1 可强制；=0 可强制回到本地监听（同机调试用）。
    const headless = process.platform === "linux"
      && !process.env.DISPLAY
      && !process.env.WAYLAND_DISPLAY;
    const forcePaste = inputs?.paste === true
      || process.env.AUTOCLAW_FORCE_PASTE === "1"
      || (headless && process.env.AUTOCLAW_FORCE_PASTE !== "0");

    let local = null;
    // 无头环境不再空占 OAuth 白名单端口：跳过监听，端口留给真正需要它的场景
    if (!forcePaste) {
      try {
        local = await startLocalOAuth(vendor);
      } catch { /* 端口全占：走手动粘贴兜底 */ }
    }
    if (local) {
      return {
        // 用 GitHub Pages 那套引导页（设备上外部可达），但回调仍由本地监听自动接收。
        // 这样"127.0.0.1 被代理劫持 / 端口连不上"的场景也能用 Pages 打开页面、再自动回调。
        url: local.url,
        instructions: local.instructions,
        method: "auto",
        callback: local.callback,
      };
    }

    // ---- 降级：手动粘贴 ----
    const deviceId = newDeviceId();
    // 🔴 device_id 必须随引导页传给浏览器侧：引导页拿它向 {vendor}-oauth-url 发起授权，
    // callback() 里又用同一个 deviceId 调 {vendor}-oauth-login 换 token。
    // 两者一旦不同，上游会话对不上，login 必报 631001「登录失败,请重新尝试」。
    const redirectUri = "http://localhost:18432/auth/callback-" + vendor;
    const url = "https://liuxigreen.github.io/magpie-autoclaw-auth/autoclaw-guide.html"
      + "?vendor=" + encodeURIComponent(vendor)
      + "&device_id=" + encodeURIComponent(deviceId)
      + "&redirect_uri=" + encodeURIComponent(redirectUri);
    return {
      url,
      instructions: "在本页完成滑块验证并完成官方 Google / z.ai 登录。登录成功后浏览器会跳到 http://localhost:18432/... 并显示“无法访问”——属正常：把地址栏里的完整 URL 粘贴到下一步输入框。",
      method: "code",
      async callback(pasted) {
        const raw = String(pasted ?? "").trim();
        if (!raw) return { type: "failed", error: "粘贴内容为空" };
        let code = "", state = "";
        try {
          const u = new URL(raw);
          code = u.searchParams.get("code") ?? "";
          state = u.searchParams.get("state") ?? "";
        } catch { /* 非完整 URL，走正则提取 */ }
        if (!code) { const m = raw.match(/[?&]code=([^&#\s]+)/); if (m) code = m[1]; }
        if (!state) { const m = raw.match(/[?&]state=([^&#\s]+)/); if (m) state = m[1]; }
        // 诊断必须早于「裸 code 兜底」：否则整条 URL 会被误当成 code。
        if (isErrorRedirect(raw, code)) {
          return { type: "failed", error:
            "授权被拒绝或链接不完整：粘贴的是错误回调（含 error / 无 code）。请回引导页重新完成授权，"
            + "并粘贴「地址栏里带 code=... 的那条 http://localhost:18432/... 完整 URL」。" };
        }
        if (/^https?:\/\//i.test(raw) && !code) {
          return { type: "failed", error:
            "这条 URL 里没有 code 参数。请确认粘的是授权完成后跳转的那条地址（示例："
            + `http://localhost:18432/auth/callback-${vendor}?code=xxxx&state=yyyy ），而不是引导页或授权页地址。` };
        }
        if (!code) code = raw; // 用户直接粘了裸 code
        try { code = decodeURIComponent(code); } catch { /* 原样 */ }
        try { state = decodeURIComponent(state); } catch { /* 原样 */ }
        if (!/^[\w\-.\/~+=%]{8,}$/.test(code)) {
          return { type: "failed", error:
            `提取到的 code 形态可疑（${code.slice(0, 24)}…）。请粘完整 URL，不要只截取片段。` };
        }
        const res = await callEnvelope(`/userapi/overseasv1/${vendor}-oauth-login`, {
          method: "POST",
          body: JSON.stringify({ source_id: PRODUCT, device_id: deviceId, code, state, navigate_uri: redirectUri }),
          base: GLOBAL_HOST,
        });
        if (res.code !== 0 || !res.data?.access_token) {
          return { type: "failed", error: loginErrorMessage(res, vendor) };
        }
        const t = tokenFields(res.data);
        const profile = await fetchUserProfile(t.access, GLOBAL_HOST);
        const displayName = accountDisplayName(profile, `${vendor} 账号`);
        return {
          type: "success",
          ...t,
          accountId: displayName,
          email: displayName,
          uid: nonEmptyString(res.data.user_id) ?? undefined,
        };
      },
    };
  },
  prompts: [
    { type: "select", key: "vendor", message: "登录方式",
      options: [
        { label: "Google 账号", value: "google" },
        { label: "z.ai 账号", value: "zai" },
      ] },
  ],
};

// ---------------------------------------------------------------------------
// 登录方式：国内手机验证码（无需浏览器 / 无需滑块，可在任意机器上登录）
// ---------------------------------------------------------------------------

/**
 * 国内手机号登录：这是**唯一不需要浏览器**的登录路径 ——
 * 发码、校验全程是普通 POST，服务器上直接 `magpie plugin login` 就能用。
 *
 * 协议（2026-10-17 对照社区版 `@magpie-community/opencode-autoclaw-auth` v0.2.0）：
 *   POST {CN_HOST}/userapi/v1/agent-send-code   {source_id, device_id, phone}
 *   POST {CN_HOST}/userapi/v1/agent-login     {source_id, device_id, phone, code}
 * 信封 `code === 0` 且 `data.access_token` 存在即成功。
 *
 * 🔴 手机号只认国内 host（CN_HOST = 加速域）。拿它去全球 host 调会 401。
 *
 * 宿主契约细节：`type: "oauth"` 的 `authorize()` **失败必须 throw** —— 返回
 * `{type:"failed"}` 会被宿主的 auto 分支当成"无参 callback()"再调一次，行为不可预期。
 * 成功才返回 `{type:"success", ...}`。
 */
const phoneSmsMethod = {
  type: "oauth",
  label: "AutoClaw 手机验证码登录（国内号）",
  async authorize(inputs) {
    const phone = String(inputs?.phone ?? "").trim();
    if (!/^1\d{10}$/.test(phone)) throw new Error("请输入 11 位手机号（不带 +86）");

    const deviceId = newDeviceId();
    const send = await callEnvelope("/userapi/v1/agent-send-code", {
      method: "POST",
      body: JSON.stringify({ source_id: PRODUCT, device_id: deviceId, phone }),
      base: CN_HOST,
    });
    if (send.code !== 0) {
      throw new Error(`发送验证码失败：${send.msg ?? `code ${send.code}`}`);
    }

    return {
      url: "",
      instructions: `验证码已发送到 ${phone.slice(0, 3)}****${phone.slice(-4)}，请输入短信里的验证码。`,
      method: "code",
      async callback(code) {
        const value = String(code?.code ?? code ?? "").trim();
        if (!/^\d{4,8}$/.test(value)) {
          return { type: "failed", error: "验证码应是 4~8 位数字" };
        }
        // 🔴 末尾不能带斜杠：上游 2026-10 起对 "/agent-login/" 回 307
        //    Location: /userapi/v1/agent-login（不带斜杠才是 200）。
        //    宿主不跟随重定向时会拿到空 body，登录直接失败。
        const res = await callEnvelope("/userapi/v1/agent-login", {
          method: "POST",
          body: JSON.stringify({ source_id: PRODUCT, device_id: deviceId, phone, code: value }),
          base: CN_HOST,
        });
        if (res.code !== 0 || !res.data?.access_token) {
          return { type: "failed", error: `登录失败：${res.msg ?? `code ${res.code}`}` };
        }
        const t = tokenFields(res.data);
        // 登录响应里 user_name 常为空 → 会显示成「已登录」，拉 profile 补昵称/手机号
        const profile = await fetchUserProfile(t.access, CN_HOST);
        const displayName = accountDisplayName(profile, phone);
        return {
          type: "success",
          ...t,
          accountId: displayName,
          email: displayName,
          uid: nonEmptyString(res.data.user_id) ?? undefined,
        };
      },
    };
  },
  prompts: [
    {
      type: "text",
      key: "phone",
      message: "手机号（11 位，不带 +86）",
      placeholder: "13800138000",
      validate: (v) => (/^1\d{10}$/.test(String(v ?? "").trim()) ? undefined : "请输入 11 位手机号"),
    },
  ],
};

/**
 * 本地 OAuth 会话上限：callback 的等待是 5 分钟；宿主不调 callback 时兜底释放端口。
 * 必须略大于等待窗口，否则刚收到 code 端口就被自己的定时器关掉。
 */
const OAUTH_SESSION_TIMEOUT_MS = 10 * 60 * 1000;

/**
 * 本地回调是否应收下这个 code（抽成纯函数便于测试）。
 * 等待窗口内任何网页都能导航到本端口 —— code 必须配上 /open-auth 记下的
 * state 才收，否则只回失败页：把别人的 code 塞进来会登录成别人的账号。
 */
function acceptLocalCallback(expectedOauthState, code, cbState) {
  return !!code && expectedOauthState !== null && expectedOauthState !== undefined && cbState === expectedOauthState;
}

/**
 * 启动本地 OAuth：立即返回 {url, method:"auto", callback}。
 * url = 本地引导页（滑块在内完成，之后自动跳授权页）；callback 挂起等 code，
 * 拿到后直连上游换 token。
 */
async function startLocalOAuth(vendor) {
  const deviceId = newDeviceId();
  const state = {
    captchaReceipt: null,
    oauthCode: null,
    oauthState: "",
    // 🔴 /open-auth 从上游授权页地址里读出的 state；回调必须原样带回（防 login CSRF）。
    //    null = 尚未发起授权；任意网页都能导航到本端口，没有它就等于谁来都收。
    expectedOauthState: null,
    error: null,
  };
  const waiters = [];
  const notify = () => { while (waiters.length) waiters.shift()(); };
  const waitFor = (timeoutMs, what) => new Promise((resolve, reject) => {
    const check = () => {
      if (state.error) { cleanup(); reject(new Error(state.error)); return true; }
      if (state.oauthCode) { cleanup(); resolve(state.oauthCode); return true; }
      return false;
    };
    const timer = setTimeout(() => { cleanup(); reject(new Error(`${what} 等待超时（${Math.round(timeoutMs / 60000)} 分钟）— 请重试登录`)); }, timeoutMs);
    const w = () => { check(); };
    const cleanup = () => { clearTimeout(timer); const i = waiters.indexOf(w); if (i >= 0) waiters.splice(i, 1); };
    waiters.push(w);
    check();
  });

  // 官方 TokenServer 端口池（OAuth client 注册的回调白名单端口）。
  // 18432 被占（如官方客户端在跑）时依次尝试其余。
  const FIXED_PORTS = [18432, 19654, 19723, 53699];

  // 先行探测可用端口（listen → 记下 → 关闭，真正 listen 在 callback 里）
  let fixedPort = 0;
  const probe = http.createServer();
  for (const p of FIXED_PORTS) {
    const ok = await new Promise((resolve) => {
      probe.once("error", () => resolve(false));
      probe.listen(p, "127.0.0.1", () => { probe.close(() => resolve(true)); });
    });
    if (ok) { fixedPort = p; break; }
  }
  if (!fixedPort) {
    throw new Error(`本地端口 ${FIXED_PORTS.join("/")} 均被占用——OAuth 回调需要其中之一（官方 client 白名单端口）。请关闭占用进程（可能是 AutoClaw 桌面端或其 TokenServer）后重试。`);
  }

  const server = http.createServer((req, res) => {
    const base = `http://127.0.0.1:${server.address()?.port ?? 0}`;
    let url;
    try { url = new URL(req.url, base); } catch { res.writeHead(400); res.end(); return; }
    const send = (status, type, body, extra = {}) => {
      res.writeHead(status, { "Content-Type": type, "Cache-Control": "no-store", ...extra });
      res.end(body);
    };
    // 写接口仅接受本机来源：浏览器同源 fetch 一定带 Origin（127.0.0.1/localhost）；
    // curl 等非浏览器客户端无 Origin，放行。防其他网页跨源 POST /abort 干扰登录。
    const localOrigin = (req) => {
      const o = req.headers.origin;
      return !o || /^https?:\/\/(127\.0\.0\.1|localhost|\[::1\])(:\d+)?$/i.test(String(o));
    };
    if (["/captcha", "/open-auth", "/abort"].includes(url.pathname) && !localOrigin(req)) {
      send(403, "application/json", JSON.stringify({ error: "forbidden origin" }));
      return;
    }

    if (req.method === "OPTIONS") {
      send(204, "text/plain", "", { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "content-type", "Access-Control-Allow-Methods": "GET,POST,OPTIONS" });
      return;
    }

    if (url.pathname === "/" || url.pathname === "/index.html") {
      send(200, "text/html; charset=utf-8", guidePageHtml(vendor));
      return;
    }

    if (url.pathname === "/captcha-config") {
      callEnvelope("/userapi/overseasv1/oauth-captcha-config", { method: "POST", body: "{}", base: GLOBAL_HOST })
        .then((r) => send(200, "application/json", JSON.stringify(r.data ?? { enabled: false })))
        .catch(() => send(502, "application/json", JSON.stringify({ enabled: false, error: "config fetch failed" })));
      return;
    }

    const readBody = () => new Promise((resolve) => {
      let b = "";
      req.on("data", (c) => { b += c; });
      req.on("end", () => { try { resolve(JSON.parse(b || "{}")); } catch { resolve({}); } });
    });

    if (url.pathname === "/captcha" && req.method === "POST") {
      readBody().then((j) => {
        // 阿里 SDK 把回执作为 captchaVerifyCallback 首参本身（JSON 字符串），
        // 兜底 captchaVerifyParam 字段两种形态。
        const receipt = typeof j.receipt === "string" ? j.receipt
          : typeof j.captchaVerifyParam === "string" ? j.captchaVerifyParam : "";
        state.captchaReceipt = receipt.trim();
        send(200, "application/json", JSON.stringify({ ok: !!state.captchaReceipt }), { "Access-Control-Allow-Origin": "*" });
      });
      return;
    }

    if (url.pathname === "/open-auth" && req.method === "POST") {
      (async () => {
        // ⚠️ redirect_uri 必须是官方 client 注册过的白名单形态：
        // http://localhost:<port>/auth/callback-<vendor>（host=localhost、固定路径、
        // 端口为官方 TokenServer 端口池之一），随机端口/自定路径会被
        // {"detail":"Redirect URI not registered for this client"} 拒绝。
        const redirectUri = `http://localhost:${fixedPort}/auth/callback-${vendor}`;
        const bodyObj = { source_id: PRODUCT, device_id: deviceId, navigate_uri: redirectUri };
        if (state.captchaReceipt) bodyObj.ali_captcha_verify_param = state.captchaReceipt;
        const r = await callEnvelope(`/userapi/overseasv1/${vendor}-oauth-url`, {
          method: "POST", body: JSON.stringify(bodyObj), base: GLOBAL_HOST,
        });
        if (r.code !== 0 || !r.data) {
          send(200, "application/json", JSON.stringify({ error: `获取授权页失败: ${r.msg ?? `code ${r.code}`}` }));
          return;
        }
        const authorizeUrl = String(r.data.oauth_url ?? r.data.url ?? r.data.login_url ?? r.data.auth_url ?? r.data.verify_url ?? "");
        if (!authorizeUrl) {
          send(200, "application/json", JSON.stringify({ error: "上游未返回授权页地址" }));
          return;
        }
        // 记下上游放进授权页的 state：回调必须原样带回，否则拒收（防伪造回调劫持登录）
        let handedOutState = "";
        try { handedOutState = new URL(authorizeUrl).searchParams.get("state") ?? ""; } catch { /* 非法地址按缺 state 处理 */ }
        if (!handedOutState) {
          send(200, "application/json", JSON.stringify({ error: "上游授权页地址缺少 state 参数，已取消登录（回调校验必需）" }));
          return;
        }
        state.expectedOauthState = handedOutState;
        send(200, "application/json", JSON.stringify({ url: authorizeUrl }));
      })().catch((e) => send(200, "application/json", JSON.stringify({ error: `获取授权页失败: ${e?.message ?? e}` })));
      return;
    }

    // 官方注册的回调路径：/auth/callback-<vendor>（另有旧 /callback 兜底）。
    // 等待窗口内任何网页都能导航到本端口 —— code 必须配上 /open-auth 记下的
    // state 才收，否则只回失败页：把别人的 code 塞进来会登录成别人的账号。
    if (url.pathname === `/auth/callback-${vendor}` || url.pathname === "/callback") {
      const code = url.searchParams.get("code");
      const cbState = url.searchParams.get("state") ?? "";
      const accepted = acceptLocalCallback(state.expectedOauthState, code, cbState);
      if (accepted) {
        state.oauthCode = code;
        state.oauthState = cbState;
        notify();
        send(200, "text/html; charset=utf-8", callbackPageHtml(true));
      } else {
        // 拒收但不动会话状态：之后到达的合法回调仍能完成登录
        const note = !code ? undefined
          : state.expectedOauthState === null ? "授权尚未发起或已结束，请回引导页重试。"
          : "回调校验失败（state 不匹配），已拒绝——请回 magpie 重新登录。";
        send(200, "text/html; charset=utf-8", callbackPageHtml(false, note));
      }
      return;
    }

    if (url.pathname === "/abort" && req.method === "POST") {
      readBody().then((j) => {
        state.error = String(j.reason ?? "用户取消");
        notify();
        send(200, "application/json", JSON.stringify({ ok: true }));
      });
      return;
    }

    send(404, "text/plain", "not found");
  });

  const serverReady = new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(fixedPort, "127.0.0.1", () => resolve(fixedPort));
  });

  // 🔴 `authorize()` 一返回端口就被占住，直到 callback 完成或会话超时。
  //   宿主可能永远不调 callback（用户在 magpie 里取消登录），没有这个定时器
  //   端口会一直泄漏，下次登录就全端口占用。
  let sessionDone = false;
  let sessionClosed = false;
  const closeServer = () => {
    if (sessionClosed) return;
    sessionClosed = true;
    clearTimeout(sessionTimer);
    if (!sessionDone) {
      state.error ??= "本地登录已超时，服务器已关闭——请重新发起登录";
      notify();
    }
    try { server.close(); } catch { /* 未 listening / 已关闭 */ }
    server.closeAllConnections?.();
  };
  const sessionTimer = setTimeout(closeServer, OAUTH_SESSION_TIMEOUT_MS);
  sessionTimer.unref?.();

  return {
    url: `http://127.0.0.1:${fixedPort}/`, // 宿主自动打开；未自动打开时按 instructions 手动访问
    instructions: `已打开本地引导页（未自动打开时手动访问 http://127.0.0.1:${fixedPort}/ ）：请完成滑块验证并登录授权，完成后自动返回 magpie。`,
    method: "auto",
    async callback() {
      const port = await serverReady;
      const guide = `http://127.0.0.1:${port}/`;
      const redirectUri = `http://localhost:${port}/auth/callback-${vendor}`;
      try {
        openBrowser(guide);
        const code = await waitFor(5 * 60 * 1000, "浏览器登录");
        const res = await callEnvelope(`/userapi/overseasv1/${vendor}-oauth-login`, {
          method: "POST",
          body: JSON.stringify({ source_id: PRODUCT, device_id: deviceId, code, state: state.oauthState, navigate_uri: redirectUri }),
          base: GLOBAL_HOST,
        });
        if (res.code !== 0 || !res.data?.access_token) {
          return { type: "failed", error: loginErrorMessage(res, vendor) };
        }
        const t = tokenFields(res.data);
        // GUI 显示名：拉 user-profile 取昵称（Google/z.ai 账号通常有昵称或邮箱）
        const profile = await fetchUserProfile(t.access, GLOBAL_HOST);
        const displayName = accountDisplayName(profile, `${vendor} 账号`);
        return {
          type: "success",
          ...t,
          accountId: displayName,
          email: displayName,
          uid: nonEmptyString(res.data.user_id) ?? undefined,
        };
      } finally {
        sessionDone = true;
        closeServer();
      }
    },
  };
}

/** 跨平台打开浏览器（node:child_process，Bun / Node 宿主均可；失败时用户可手动打开 instructions 里的地址）。 */
function openBrowser(urlStr) {
  const cmd = process.platform === "darwin" ? "open" : process.platform === "win32" ? "start" : "xdg-open";
  try {
    // Windows 的 start 是 cmd 内建命令，必须走 shell。
    const child = process.platform === "win32"
      ? spawn(cmd, [urlStr], { shell: true, stdio: "ignore", detached: true })
      : spawn(cmd, [urlStr], { stdio: "ignore", detached: true });
    child.on("error", () => { /* 打开失败静默：instructions 已给出可手动访问的地址 */ });
    child.unref();
  } catch { /* 同上 */ }
}

/** 引导页：滑块（如启用）→ 继续授权 → 自动跳授权页。 */
function guidePageHtml(vendor) {
  const vendorName = vendor === "zai" ? "z.ai" : "Google";
  return `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>AutoClaw ${vendorName} 登录</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
 body{font-family:-apple-system,BlinkMacSystemFont,"PingFang SC",sans-serif;background:#f5f6fa;display:flex;justify-content:center;padding:40px 16px;margin:0}
 .card{background:#fff;border-radius:16px;box-shadow:0 8px 30px rgba(0,0,0,.08);max-width:460px;width:100%;padding:32px}
 h1{font-size:20px;margin:0 0 8px}
 p.sub{color:#666;font-size:14px;margin:0 0 20px}
 .step{font-size:14px;color:#333;margin:10px 0;display:flex;gap:8px;align-items:flex-start}
 .step .n{background:#4f6ef7;color:#fff;border-radius:50%;width:20px;height:20px;display:inline-flex;align-items:center;justify-content:center;font-size:12px;flex:none}
 #captchaBox{margin:16px 0;padding:16px;border:1px dashed #ccc;border-radius:10px;display:none}
 #captchaEle{min-height:44px}
 button.primary{background:#4f6ef7;color:#fff;border:none;border-radius:10px;padding:12px 22px;font-size:15px;cursor:pointer;width:100%;margin-top:16px}
 button.primary:disabled{background:#b9c0f4;cursor:not-allowed}
 .msg{font-size:13px;margin-top:10px;min-height:18px}
 .msg.ok{color:#1a9c5b}.msg.err{color:#d43c3c}.msg.warn{color:#c98a00}
 #done{display:none;text-align:center;padding:20px 0}
 .spin{display:inline-block;width:28px;height:28px;border:3px solid #e3e6f7;border-top-color:#4f6ef7;border-radius:50%;animation:r 0.8s linear infinite;margin-bottom:10px}
 @keyframes r{to{transform:rotate(360deg)}}
</style></head><body>
<div class="card">
 <h1>AutoClaw · ${vendorName} 登录</h1>
 <p class="sub">本页面由 magpie 插件本地生成，关闭本页即取消登录。</p>
 <div id="steps">
  <div class="step"><span class="n">1</span><span id="stepCaptcha">检查安全验证…</span></div>
  <div id="captchaBox"><div id="captchaEle"></div></div>
  <div class="step"><span class="n">2</span><span>跳转 ${vendorName} 授权页完成登录</span></div>
 </div>
 <button class="primary" id="goBtn" disabled>继续授权</button>
 <div class="msg" id="msg"></div>
 <div id="done"><div class="spin"></div><div>已完成授权，正在返回 magpie…</div></div>
</div>
<script>
const HIDDEN_TRIGGER_ID="__acHiddenTrigger";
(function ensureHiddenTrigger(){
  let b=document.getElementById(HIDDEN_TRIGGER_ID);
  if(!b){b=document.createElement("button");b.id=HIDDEN_TRIGGER_ID;b.type="button";b.tabIndex=-1;
    b.setAttribute("aria-hidden","true");b.style.cssText="position:fixed;width:1px;height:1px;opacity:0;pointer-events:none;overflow:hidden";
    document.body.appendChild(b);}
})();
function msg(m,cls){const e=document.getElementById("msg");e.textContent=m;e.className="msg "+(cls||"");}
async function boot(){
  let cfg={enabled:false};
  try{
    const r=await fetch("/captcha-config");cfg=await r.json();
  }catch(e){}
  if(cfg&&cfg.enabled){
    document.getElementById("stepCaptcha").textContent="请点击下方按钮完成安全验证";
    const box=document.getElementById("captchaBox");box.style.display="block";
    window.__acRegion=cfg.region||"ga";window.__acPrefix=cfg.prefix||"sq51tr";
    window.AliyunCaptchaConfig=window.AliyunCaptchaConfig||{region:window.__acRegion,prefix:window.__acPrefix};
    msg("正在加载安全验证组件…","warn");
    await loadCaptchaLib();
    if(!window.initAliyunCaptcha){
      msg("验证组件加载失败（网络/广告拦截），请刷新重试","err");return;
    }
    // ⚠️ 官方流程：init → warmup ≥2.1s → 程序化 click 隐藏按钮 → 组件弹出验证窗。
    // click 太快组件未就绪 → 弹出空白框（实测踩坑）。等待 2.3s。
    window.initAliyunCaptcha({
      SceneId:cfg.scene_id,mode:"popup",element:"#captchaEle",button:"#"+HIDDEN_TRIGGER_ID,
        captchaVerifyCallback:(params)=>{
          const receipt=typeof params==="string"?params:(params&&typeof params.captchaVerifyParam==="string"?params.captchaVerifyParam:JSON.stringify(params||{}));
          fetch("/captcha",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({receipt})})
            .then(()=>{window.__acReceiptSent=true;}).catch(()=>{window.__acReceiptSent=true;});
          return {captchaResult:true};
        },
      onBizResultCallback:()=>{},getInstance:()=>{},
      slideStyle:{width:320,height:40},language:"cn",
      onError:(err)=>{msg("安全验证出错: "+((err&&err.message)||"")+"，请点击重试","err");}
    });
    msg("验证组件已就绪，正在弹出验证窗…","warn");
    setTimeout(()=>{document.getElementById("__acHiddenTrigger").click();},2300);
    // 轮询等回执上报完成（回执 POST /captcha 在 captchaVerifyCallback 里异步发）
    const t0=Date.now();
    await (function pollReceipt(){
      if(window.__acReceiptSent||Date.now()-t0>180000)return;
      return new Promise(r=>setTimeout(r,500)).then(pollReceipt);
    })();
    window.__acReceiptSent=false;
    msg("滑块验证通过 ✓","ok");
  }else{
    document.getElementById("stepCaptcha").textContent="无需安全验证 ✓";
  }
  const btn=document.getElementById("goBtn");btn.disabled=false;btn.textContent="继续授权";
}
function loadCaptchaLib(){
  return new Promise((resolve)=>{
    if(window.initAliyunCaptcha){resolve();return;}
    const s=document.createElement("script");
    s.src="https://o.alicdn.com/captcha-frontend/aliyunCaptcha/AliyunCaptcha.js";
    s.async=true;s.onload=()=>resolve();s.onerror=()=>resolve();
    document.head.appendChild(s);
    setTimeout(()=>resolve(),10000);
  });
}
document.getElementById("goBtn").addEventListener("click",async()=>{
  const btn=document.getElementById("goBtn");btn.disabled=true;btn.textContent="正在获取授权页…";
  try{
    const r=await fetch("/open-auth",{method:"POST"});
    const j=await r.json();
    if(j.error){msg(j.error,"err");btn.disabled=false;btn.textContent="继续授权";return;}
    document.getElementById("steps").style.display="none";btn.style.display="none";
    document.getElementById("done").style.display="block";
    setTimeout(()=>{location.href=j.url;},600);
  }catch(e){msg("网络错误："+e.message,"err");btn.disabled=false;btn.textContent="继续授权";}
});
window.addEventListener("beforeunload",()=>{
  try{navigator.sendBeacon("/abort",new Blob([JSON.stringify({reason:"页面关闭"})],{type:"application/json"}));}catch(_){}
});
boot().catch((e)=>msg("初始化失败："+e.message,"err"));
</script></body></html>`;
}

/** 授权回调落地页。 */
function callbackPageHtml(ok, note) {
  const title = ok ? "✓ 授权成功" : "✗ 授权失败";
  const desc = ok
    ? "正在返回 magpie 完成登录，本页可以关闭。"
    : (note ?? "回调缺少 code，请回 magpie 重试。");
  return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><title>AutoClaw 登录</title>
<style>body{font-family:-apple-system,"PingFang SC",sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#f5f6fa}
.c{background:#fff;border-radius:16px;box-shadow:0 8px 30px rgba(0,0,0,.08);padding:40px 48px;text-align:center;max-width:420px}
h1{font-size:18px;margin:0 0 8px;color:${ok ? "#1a9c5b" : "#d43c3c"}}</style></head>
<body><div class="c"><h1>${title}</h1>
<p style="color:#666;font-size:14px">${desc}</p></div></body></html>`;
}

// ---------------------------------------------------------------------------
// 导出
// ---------------------------------------------------------------------------

/** provider "autoclaw"：国际版（z.ai / Google 网页 OAuth，本地完整实现）。 */
export const AutoclawAuthPlugin = makeAutoclawPlugin({
  providerId: "autoclaw",
  providerName: "AutoClaw (Zhipu)",
  homeHost: GLOBAL_HOST,
  loginMethod: overseaOAuthMethod,
});

/**
 * provider `autoclaw-cn`：国内版（手机验证码账号）。
 *
 * 为什么必须单独注册一个 provider 而不是复用 `autoclaw`：
 * magpie 的账号是由**登录时所处的 provider** 决定的（`logins.json` 里的
 * `agent: "plugin:autoclaw-cn"`）。国内号当初就是用 `autoclaw-cn` 登录的，
 * 如果不注册这个 provider，那个账号在 `magpie providers` / `accounts` 里
 * **根本不会出现**，等于废着用不了。
 *
 * 两个 provider 共用同一套逻辑与凭据存储（`plugin-auth.json` 按 provider id 分区），
 * 只是首选 host 与默认登录方式不同。
 */
export const AutoclawCnAuthPlugin = makeAutoclawPlugin({
  providerId: "autoclaw-cn",
  providerName: "AutoClaw 国内 (Zhipu)",
  homeHost: CN_HOST,
  loginMethod: phoneSmsMethod,
});

/** 测试辅助（magpie/OpenCode 不会把它当插件调用）。 */
export const _internal = {
  md5Hex, jwtClaim, tokenFields, bizHeaders, bareToken, newDeviceId,
  dailySignin, signinStatus, maybeSignin, signinConfig, checkinOutcome, refreshTokens,
    fetchUserProfile, accountDisplayName, normalizeMaxTokens,
    resolveRouteId, stripRoutePrefix, autoclawModels,
    normalizeSystemPrompt, rewriteIdentities, replaceAllIgnoreAsciiCase,
    findIgnoreAsciiCase, prependPrefix, joinPrefix, isSystemRole,
    IDENTITY_LINE, IDENTITY_PREFIX, FOREIGN_IDENTITIES,
  guidePageHtml, callbackPageHtml, remoteGuideHtml,
  manualOauthMethod, overseaOAuthMethod,
  phoneSmsMethod, hostsForAuth, isSmsAccountToken, GLOBAL_HOST,
  CHAT_PATH, CN_HOST, PLATFORM_TM, USER_AGENT,
  acceptLocalCallback, startLocalOAuth, OAUTH_SESSION_TIMEOUT_MS,
};

function remoteGuideHtml(vendor, deviceId) {
  const vendorName = vendor === "zai" ? "z.ai" : "Google";
  const html = `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>AutoClaw ${vendorName} 登录</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
 body{font-family:-apple-system,BlinkMacSystemFont,"PingFang SC",sans-serif;background:#f5f6fa;display:flex;justify-content:center;padding:40px 16px;margin:0}
 .card{background:#fff;border-radius:16px;box-shadow:0 8px 30px rgba(0,0,0,.08);max-width:460px;width:100%;padding:32px}
 h1{font-size:20px;margin:0 0 8px}
 p.sub{color:#666;font-size:14px;margin:0 0 20px}
 .step{font-size:14px;color:#333;margin:10px 0;display:flex;gap:8px;align-items:flex-start}
 .step .n{background:#4f6ef7;color:#fff;border-radius:50%;width:20px;height:20px;display:inline-flex;align-items:center;justify-content:center;font-size:12px;flex:none}
 #captchaBox{margin:16px 0;padding:16px;border:1px dashed #ccc;border-radius:10px;display:none}
 #captchaEle{min-height:44px}
 button.primary{background:#4f6ef7;color:#fff;border:none;border-radius:10px;padding:12px 22px;font-size:15px;cursor:pointer;width:100%;margin-top:16px}
 button.primary:disabled{background:#b9c0f4;cursor:not-allowed}
 .msg{font-size:13px;margin-top:10px;min-height:18px}
 .msg.ok{color:#1a9c5b}.msg.err{color:#d43c3c}.msg.warn{color:#c98a00}
 #done{display:none;text-align:center;padding:20px 0}
 .spin{display:inline-block;width:28px;height:28px;border:3px solid #e3e6f7;border-top-color:#4f6ef7;border-radius:50%;animation:r 0.8s linear infinite;margin-bottom:10px}
 @keyframes r{to{transform:rotate(360deg)}}
</style>
<script src="https://cdn.jsdelivr.net/npm/js-md5@0.8.3/src/md5.js"></script>
</head><body>
<div class="card">
 <h1>AutoClaw · ${vendorName} 登录</h1>
 <p class="sub">全部步骤在本页完成（含阿里云滑块）：完成后浏览器跳到 localhost:18432 并“打不开”属正常，把地址栏完整 URL 粘贴回 magpie 即可。</p>
 <div id="steps">
  <div class="step"><span class="n">1</span><span id="stepCaptcha">检查安全验证…</span></div>
  <div id="captchaBox"><div id="captchaEle"></div></div>
  <div class="step"><span class="n">2</span><span>跳转 ${vendorName} 授权页完成登录</span></div>
 </div>
 <button class="primary" id="goBtn" disabled>继续授权</button>
 <div class="msg" id="msg"></div>
</div>
<script>
const APP_ID="${APP_ID}";
const APP_KEY="${APP_KEY}";
const PRODUCT="${PRODUCT}";
const GLOBAL_HOST="https://autoglm-api.autoglm.ai";
const VENDOR="${vendor}";
const DEVICE_ID="${deviceId}";
const REDIRECT_URI="http://localhost:18432/auth/callback-${vendor}";
function md5Sign(ts){
  try { return (typeof md5==="function") ? md5(APP_ID+"&"+ts+"&"+APP_KEY) : ""; } catch(e){ return ""; }
}
function bizHeaders(){
  const ts=String(Math.floor(Date.now()/1000));
  return {
    "Content-Type":"application/json",
    "Accept":"*/*",
    "User-Agent":"AutoClaw/1.18.1 (mac-arm64)",
    "X-Version":"1.18.1",
    "X-Product":PRODUCT,
    "X-Auth-Appid":APP_ID,
    "X-Auth-TimeStamp":ts,
    "X-Auth-Sign":md5Sign(ts),
    "X-Lang":"zh-CN",
    "X-Channel":"AutoClaw4",
    "Origin":"http://localhost:18432",
    "Referer":"http://localhost:18432/"
  };
}
function msg(m,cls){const e=document.getElementById("msg");e.textContent=m;e.className="msg "+(cls||"");}
let receipt="";
window.__acReceiptSent=false;
async function boot(){
  let cfg={enabled:false};
  try{
    const r=await fetch(GLOBAL_HOST+"/userapi/overseasv1/oauth-captcha-config",{method:"POST",headers:bizHeaders(),body:"{}"});
    cfg=(await r.json())?.data ?? {};
  }catch(e){}
  if(cfg && cfg.enabled){
    document.getElementById("stepCaptcha").textContent="请点击下方按钮完成安全验证";
    const box=document.getElementById("captchaBox"); box.style.display="block";
    msg("正在加载安全验证组件…","warn");
    await new Promise((resolve)=>{ if(window.initAliyunCaptcha){resolve();return;} const s=document.createElement("script"); s.src="https://o.alicdn.com/captcha-frontend/aliyunCaptcha/AliyunCaptcha.js"; s.async=true; s.onload=()=>resolve(); s.onerror=()=>resolve(); document.head.appendChild(s); setTimeout(()=>resolve(),10000); });
    if(!window.initAliyunCaptcha){ msg("验证组件加载失败，请刷新重试","err"); return; }
    window.initAliyunCaptcha({
      SceneId:cfg.scene_id,mode:"popup",element:"#captchaEle",button:"#__acHiddenTrigger",
      captchaVerifyCallback:(params)=>{ receipt = typeof params=="string" ? params : (params&&typeof params.captchaVerifyParam=="string"?params.captchaVerifyParam:JSON.stringify(params||{})); window.__acReceiptSent=true; return {captchaResult:true}; },
      onBizResultCallback:()=>{}, getInstance:()=>{}, slideStyle:{width:320,height:40}, language:"cn",
      onError:(err)=>{msg("安全验证出错: "+((err&&err.message)||""),"err");}
    });
    const t0=Date.now(); await (function poll(){ if(window.__acReceiptSent||Date.now()-t0>180000)return; return new Promise(r=>setTimeout(r,500)).then(poll); })();
    msg("滑块验证通过 ✓","ok");
  } else {
    document.getElementById("stepCaptcha").textContent="无需安全验证 ✓";
  }
  const btn=document.getElementById("goBtn"); btn.disabled=false; btn.textContent="继续授权";
  btn.addEventListener("click", async ()=>{
    btn.disabled=true; btn.textContent="正在获取授权页…";
    try {
      const body={source_id:PRODUCT, device_id:DEVICE_ID, navigate_uri:REDIRECT_URI};
      if(receipt) body.ali_captcha_verify_param=receipt;
      const r=await fetch(GLOBAL_HOST+"/userapi/overseasv1/"+VENDOR+"-oauth-url",{method:"POST",headers:bizHeaders(),body:JSON.stringify(body)});
      const j=await r.json(); const data=j?.data;
      const url=String(data?.oauth_url ?? data?.url ?? data?.login_url ?? data?.auth_url ?? data?.verify_url ?? "");
      if(j?.code !== 0 || !url){ msg("获取授权页失败: "+(j?.msg||j?.code||"无地址"),"err"); btn.disabled=false; btn.textContent="继续授权"; return; }
      window.location.href=url;
    } catch(e){ msg("网络错误: "+e.message,"err"); btn.disabled=false; btn.textContent="继续授权"; }
  });
}
boot().catch(e=>msg("初始化失败: "+e.message,"err"));
</script>
<script>(function(){let b=document.getElementById("__acHiddenTrigger");if(!b){b=document.createElement("button");b.id="__acHiddenTrigger";b.type="button";b.tabIndex=-1;b.setAttribute("aria-hidden","true");b.style.cssText="position:fixed;width:1px;height:1px;opacity:0;pointer-events:none;";document.body.appendChild(b);}})();</script>
</body></html>`;
  return "data:text/html;base64," + Buffer.from(html).toString("base64");
}
