/** 纯函数单测（无网络）：node --test tests/ */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { _internal, AutoclawAuthPlugin, AutoclawCnAuthPlugin } from "../index.mjs";

const {
  md5Hex, jwtClaim, tokenFields, bizHeaders, bareToken,
  newDeviceId, signinConfig, checkinOutcome, accountDisplayName,
  isSmsAccountToken, hostsForAuth, phoneSmsMethod, CN_HOST, GLOBAL_HOST,
} = _internal;

const b64url = (obj) => Buffer.from(JSON.stringify(obj)).toString("base64url");
const jwt = (payload) => `${b64url({ alg: "none" })}.${b64url(payload)}.sig`;

// ---- 基础工具 ---------------------------------------------------------------

test("md5Hex 已知向量", () => {
  assert.equal(md5Hex("abc"), "900150983cd24fb0d6963f7d28e17f72");
});

test("bareToken 剥掉任意层 Bearer 前缀", () => {
  assert.equal(bareToken("Bearer abc"), "abc");
  assert.equal(bareToken("  Bearer  Bearer x "), "x");
  assert.equal(bareToken("plain"), "plain");
  assert.equal(bareToken(null), "");
  assert.equal(bareToken(undefined), "");
});

test("newDeviceId 是 64 位十六进制且每次不同", () => {
  assert.match(newDeviceId(), /^[0-9a-f]{64}$/);
  assert.notEqual(newDeviceId(), newDeviceId());
});

// ---- JWT / token 字段 --------------------------------------------------------

test("jwtClaim 读 base64url payload，坏 token 返回 undefined", () => {
  assert.equal(jwtClaim(jwt({ device_id: "dev123", exp: 2_000_000_000 }), "device_id"), "dev123");
  assert.equal(jwtClaim("garbage", "exp"), undefined);
  assert.equal(jwtClaim("a.b", "exp"), undefined); // payload 非法 base64/JSON
});

test("tokenFields：JWT exp 是事实来源，带 10 分钟提前量", () => {
  const access = jwt({ exp: 2_000_000_000 });
  const t = tokenFields({ access_token: `Bearer ${access}`, refresh_token: "Bearer r1" });
  assert.equal(t.access, access); // Bearer 前缀被剥
  assert.equal(t.refresh, "r1");
  assert.equal(t.expires, 2_000_000_000_000 - 10 * 60 * 1000);
});

test("tokenFields：无 JWT exp 时用 expires_in / 5h 兜底", () => {
  const t = tokenFields({ access_token: "opaque", refresh_token: "r1", expires_in: 3600 });
  const skew = 10 * 60 * 1000;
  assert.ok(Math.abs(t.expires - (Date.now() + 3600_000 - skew)) < 5_000);
  const t2 = tokenFields({ access_token: "opaque", refresh_token: "r1" });
  assert.ok(Math.abs(t2.expires - (Date.now() + 5 * 3600_000 - skew)) < 5_000);
});

test("tokenFields：缺 access / 缺 refresh 抛错", () => {
  assert.throws(() => tokenFields({ refresh_token: "r1" }), /access_token/);
  assert.throws(() => tokenFields({ access_token: "opaque" }), /refresh_token/);
});

// ---- 业务签名头 --------------------------------------------------------------

test("bizHeaders：签名头齐全，Authorization 按需", () => {
  const h = bizHeaders("tok");
  assert.equal(h["X-Auth-Appid"], "100003");
  assert.match(h["X-Auth-Sign"], /^[0-9a-f]{32}$/);
  assert.equal(h.Authorization, "Bearer tok");
  assert.match(h["X-Auth-TimeStamp"], /^\d+$/);
  const bare = bizHeaders();
  assert.ok(!("Authorization" in bare));
  assert.match(bizHeaders()["X-Auth-Sign"], /^[0-9a-f]{32}$/);
});

// ---- 签到配置 ----------------------------------------------------------------

test("signinConfig：无文件无 options → 默认（自动补签关，交给原生 checkin）", () => {
  const tmp = mkdtempSync(join(tmpdir(), "autoclaw-test-"));
  const prev = process.env.XDG_CONFIG_HOME;
  try {
    process.env.XDG_CONFIG_HOME = tmp;
    assert.deepEqual(signinConfig(undefined), { signin: true, signinOnUsage: false, signinHour: null });
    assert.deepEqual(signinConfig({}), { signin: true, signinOnUsage: false, signinHour: null });

    // 配置文件通道（热读取）
    mkdirSync(join(tmp, "magpie"), { recursive: true });
    const file = join(tmp, "magpie", "autoclaw.json");
    writeFileSync(file, JSON.stringify({ signin: false, signinHour: 8 }));
    assert.deepEqual(signinConfig(undefined), { signin: false, signinOnUsage: false, signinHour: 8 });
    writeFileSync(file, JSON.stringify({ signinOnUsage: true }));
    assert.deepEqual(signinConfig(undefined), { signin: true, signinOnUsage: true, signinHour: null });

    // 插件 options 优先于文件（options 未给的字段沿用文件值）
    writeFileSync(file, JSON.stringify({ signin: false, signinHour: 8 }));
    assert.deepEqual(signinConfig({ signin: true, signinOnUsage: true }), { signin: true, signinOnUsage: true, signinHour: 8 });
    assert.deepEqual(signinConfig({ signinHour: null }), { signin: false, signinOnUsage: false, signinHour: null });

    // 非法 signinHour 归 null；解析失败的文件当不存在
    writeFileSync(file, JSON.stringify({ signinHour: "8" }));
    assert.equal(signinConfig(undefined).signinHour, null);
    writeFileSync(file, "{ not json");
    assert.deepEqual(signinConfig(undefined), { signin: true, signinOnUsage: false, signinHour: null });
  } finally {
    if (prev === undefined) delete process.env.XDG_CONFIG_HOME;
    else process.env.XDG_CONFIG_HOME = prev;
    rmSync(tmp, { recursive: true, force: true });
  }
});

// ---- 原生 checkin 结果映射 -----------------------------------------------------

test("checkinOutcome：dailySignin 结果 → magpie checkin 契约", () => {
  assert.deepEqual(
    checkinOutcome({ success: true, reward_points: 400, continuous_days: 7 }),
    { outcome: "claimed", credit: 400, streak: 7, message: "已签到 +400 · 连续 7 天" },
  );
  assert.deepEqual(
    checkinOutcome({ success: true, reward_points: 0 }),
    { outcome: "claimed", credit: undefined, streak: undefined, message: "已签到" },
  );
  assert.deepEqual(
    checkinOutcome({ already_completed: true, reward_points: 200 }),
    { outcome: "done", credit: 200 },
  );
  assert.deepEqual(checkinOutcome(null), { outcome: "failed", message: "签到接口无响应" });
  assert.deepEqual(checkinOutcome({ success: false, message: "风控拦截" }), { outcome: "failed", message: "风控拦截" });
  assert.deepEqual(checkinOutcome({ success: false }), { outcome: "failed", message: "签到失败" });
});

// ---- GUI 显示名 ----------------------------------------------------------------

test("accountDisplayName：昵称 > 手机号 > userId > fallback", () => {
  assert.equal(accountDisplayName(null, "fb"), "fb");
  assert.equal(accountDisplayName({}, "fb"), "fb");
  assert.equal(accountDisplayName({ name: "n", phone: "p", userId: "u" }, "fb"), "n");
  assert.equal(accountDisplayName({ phone: "p", userId: "u" }, "fb"), "p");
  assert.equal(accountDisplayName({ userId: "u" }, "fb"), "u");
});

// ---- 插件工厂（结构冒烟，无网络） ---------------------------------------------

test("插件工厂：config() 注册供应商/模型，auth/provider 钩子齐全", async () => {
  const plugin = await AutoclawAuthPlugin({}, {});
  const cfg = {};
  await plugin.config(cfg);
  assert.equal(cfg.provider.autoclaw.name, "AutoClaw (Zhipu)");
  assert.equal(cfg.provider.autoclaw.api, "https://autoglm-api.autoglm.ai");
  assert.ok(cfg.provider.autoclaw.models.zai_auto);
  assert.equal(plugin.auth.provider, "autoclaw");
  assert.ok(plugin.auth.refresh && plugin.auth.loader && plugin.auth.usage);
  assert.equal(typeof plugin.auth.checkin, "function"); // 原生签到钩子存在
  assert.ok(plugin.auth.methods[0].prompts.length > 0); // OAuth 引导页选项存在
  assert.equal(plugin.auth.methods.length, 3); // 网页登录 + 手机验证码 + 手动粘贴登录
  assert.match(plugin.auth.methods[1].label, /手机验证码/);
  assert.equal(typeof plugin.auth.methods[1].authorize, "function");
  assert.equal(plugin.auth.methods[1].prompts[0].key, "phone");
  assert.match(plugin.auth.methods[2].label, /授权链接/); // v0.9.2：本地监听优先，粘贴只是降级
  assert.equal(typeof plugin.auth.methods[2].authorize, "function");
  assert.equal(plugin.provider.id, "autoclaw");

  // 幂等：config 二次调用不覆盖既有配置
  await plugin.config(cfg);
  assert.equal(cfg.provider.autoclaw.api, "https://autoglm-api.autoglm.ai");
});

// ---- 回归：手动粘贴登录的 device_id 透传（v0.6.3 修复 631001） -------------------
// 症状：方式2 引导页自己随机生成 device_id，插件 callback() 却用另一个 device_id
// 调 oauth-login → 上游会话对不上 → 631001「抱歉,登录失败,请重新尝试」。
// 修复：插件把 device_id（及 redirect_uri）拼进引导页 URL，两边必须一致。

test("manualOauthMethod.authorize：URL 携带 device_id / redirect_uri / vendor", async () => {
  const { manualOauthMethod } = _internal;
  const out = await manualOauthMethod.authorize({ vendor: "google", paste: true });
  assert.equal(out.method, "code");
  const u = new URL(out.url);
  assert.equal(u.host, "liuxigreen.github.io");
  assert.match(u.pathname, /autoclaw-guide\.html$/);
  assert.equal(u.searchParams.get("vendor"), "google");
  const dev = u.searchParams.get("device_id");
  assert.ok(dev && dev.length >= 32, `device_id 必须透传，实得: ${dev}`);
  assert.equal(u.searchParams.get("redirect_uri"), "http://localhost:18432/auth/callback-google");
});

test("manualOauthMethod.authorize：zai 分支同样透传（redirect 后缀随 vendor）", async () => {
  const { manualOauthMethod } = _internal;
  const out = await manualOauthMethod.authorize({ vendor: "zai", paste: true });
  const u = new URL(out.url);
  assert.equal(u.searchParams.get("vendor"), "zai");
  assert.ok(u.searchParams.get("device_id"));
  assert.equal(u.searchParams.get("redirect_uri"), "http://localhost:18432/auth/callback-zai");
});

test("manualOauthMethod.authorize：每次调用 device_id 均不同（会话隔离）", async () => {
  const { manualOauthMethod } = _internal;
  const a = new URL((await manualOauthMethod.authorize({ vendor: "google", paste: true })).url).searchParams.get("device_id");
  const b = new URL((await manualOauthMethod.authorize({ vendor: "google", paste: true })).url).searchParams.get("device_id");
  assert.notEqual(a, b);
});

// ---- 无头环境判定（v0.9.3）-------------------------------------------------
// 远程服务器没有 DISPLAY，local.url 指向服务器自己的 127.0.0.1，客户端打不开。
// 这种情况必须直接给出 GitHub Pages 粘贴链接，而不是先试本地监听。

test("manualOauthMethod.authorize：AUTOCLAW_FORCE_PASTE=1 时强制粘贴（不占端口）", async () => {
  const { manualOauthMethod } = _internal;
  const prev = process.env.AUTOCLAW_FORCE_PASTE;
  process.env.AUTOCLAW_FORCE_PASTE = "1";
  try {
    const out = await manualOauthMethod.authorize({ vendor: "google" });
    assert.equal(out.method, "code", "强制粘贴时必须返回 method=code");
    assert.equal(new URL(out.url).host, "liuxigreen.github.io");
  } finally {
    if (prev === undefined) delete process.env.AUTOCLAW_FORCE_PASTE;
    else process.env.AUTOCLAW_FORCE_PASTE = prev;
  }
});

test("manualOauthMethod.authorize：无 DISPLAY 的 Linux 走粘贴（远程服务器场景）", async () => {
  const { manualOauthMethod } = _internal;
  const prevPlat = Object.getOwnPropertyDescriptor(process, "platform");
  const prevD = process.env.DISPLAY;
  const prevW = process.env.WAYLAND_DISPLAY;
  const prevF = process.env.AUTOCLAW_FORCE_PASTE;
  // 模拟无头 Linux 宿主
  Object.defineProperty(process, "platform", { value: "linux", configurable: true });
  delete process.env.DISPLAY;
  delete process.env.WAYLAND_DISPLAY;
  delete process.env.AUTOCLAW_FORCE_PASTE;
  try {
    const out = await manualOauthMethod.authorize({ vendor: "google" });
    assert.equal(out.method, "code", "无头宿主必须直接粘贴，不能返回 127.0.0.1");
    assert.doesNotMatch(out.url, /127\.0\.0\.1/, "无头宿主不应给出本地回环地址");
    assert.equal(new URL(out.url).host, "liuxigreen.github.io");
  } finally {
    Object.defineProperty(process, "platform", prevPlat);
    if (prevD !== undefined) process.env.DISPLAY = prevD;
    if (prevW !== undefined) process.env.WAYLAND_DISPLAY = prevW;
    if (prevF !== undefined) process.env.AUTOCLAW_FORCE_PASTE = prevF;
  }
});

test("manualOauthMethod.authorize：AUTOCLAW_FORCE_PASTE=0 可在无头宿主强行回到本地监听", async () => {
  const { manualOauthMethod } = _internal;
  const prevPlat = Object.getOwnPropertyDescriptor(process, "platform");
  const prevD = process.env.DISPLAY;
  const prevF = process.env.AUTOCLAW_FORCE_PASTE;
  Object.defineProperty(process, "platform", { value: "linux", configurable: true });
  delete process.env.DISPLAY;
  process.env.AUTOCLAW_FORCE_PASTE = "0";
  let out;
  try {
    out = await manualOauthMethod.authorize({ vendor: "google" });
  } finally {
    Object.defineProperty(process, "platform", prevPlat);
    if (prevD !== undefined) process.env.DISPLAY = prevD;
    if (prevF === undefined) delete process.env.AUTOCLAW_FORCE_PASTE;
    else process.env.AUTOCLAW_FORCE_PASTE = prevF;
  }
  // 端口可能全占（CI/本机）⇒ 仍会退到粘贴；只要不是「无头 + 未强制」的静默失败即可
  assert.ok(["auto", "code"].includes(out.method), `method 异常: ${out.method}`);
});

test("remoteGuideHtml：device_id 内联进页面（自渲染引导页）", () => {
  const { remoteGuideHtml } = _internal;
  const did = "deadbeef".repeat(8);
  const html = remoteGuideHtml("google", did);
  assert.match(html, /^data:text\/html;base64,/);
  const body = Buffer.from(html.split(",")[1], "base64").toString("utf8");
  assert.ok(body.includes(`const DEVICE_ID="${did}"`), "device_id 应内联为指定值，而非随机生成");
});

test("manualOauthMethod.callback：非法/空粘贴内容给出明确失败，不抛异常", async () => {
  const { manualOauthMethod } = _internal;
  const out = await manualOauthMethod.authorize({ vendor: "google", paste: true });
  const r1 = await out.callback("");
  assert.equal(r1.type, "failed");
  assert.match(r1.error, /为空/);
});

// ---- 回归：粘贴内容诊断（把「登录失败」变成可操作提示） ----------------------

test("callback：粘了错误回调（含 error=）给出明确提示，不发请求", async () => {
  const { manualOauthMethod } = _internal;
  const out = await manualOauthMethod.authorize({ vendor: "google", paste: true });
  const r = await out.callback("http://localhost:18432/auth/callback-google?error=access_denied&state=x");
  assert.equal(r.type, "failed");
  assert.match(r.error, /授权被拒绝|错误回调/);
});

test("callback：粘了无 code 的 URL 给出明确提示", async () => {
  const { manualOauthMethod } = _internal;
  const out = await manualOauthMethod.authorize({ vendor: "google", paste: true });
  const r = await out.callback("https://liuxigreen.github.io/magpie-autoclaw-auth/autoclaw-guide.html?vendor=google");
  assert.equal(r.type, "failed");
  assert.match(r.error, /没有 code/);
});

test("callback：裸 code 形态可疑时提前拦住", async () => {
  const { manualOauthMethod } = _internal;
  const out = await manualOauthMethod.authorize({ vendor: "google", paste: true });
  const r = await out.callback("ab");
  assert.equal(r.type, "failed");
  assert.match(r.error, /形态可疑/);
});

// ---- 回归：三个真 bug（2026-10-16「测试模型失败」）----------------------------
// 依据：https://github.com/aimod-cc/agent2api 的 providers/autoclaw/*
// 每条都在 DMIT 上按同法实测复现过（见诊断报告第三节）。

test("CHAT_PATH：不带 /v1（带上会被上游 403 pay-view / 406 空体）", () => {
  const { CHAT_PATH } = _internal;
  assert.equal(CHAT_PATH, "/autoclaw-proxy/proxy/autoclaw/chat/completions");
  assert.ok(!CHAT_PATH.includes("/v1/"), "路径不得含 /v1");
});

test("CN_HOST：国内版用加速域（主站 autoglm-api.zhipuai.cn 一律 401/410000）", () => {
  const { CN_HOST } = _internal;
  assert.equal(CN_HOST, "https://autoglm-acceleration-api.zhipuai.cn");
  assert.ok(!/^https:\/\/autoglm-api\.zhipuai\.cn$/.test(CN_HOST), "不能是主站域");
});

test("normalizeMaxTokens：小正整数抬到 10000（上游对小 max_tokens 一律 406 空体）", () => {
  const { normalizeMaxTokens } = _internal;
  for (const v of [30, 256, 1024, 4096, 8192]) {
    const b = { max_tokens: v };
    assert.equal(normalizeMaxTokens(b), true, `${v} 应被抬升`);
    assert.equal(b.max_tokens, 10000);
  }
});

test("normalizeMaxTokens：缺省 / ≥10000 / 非正整数一律不动", () => {
  const { normalizeMaxTokens } = _internal;
  const untouched = [
    {},                       // 缺省：不凭空注入
    { max_tokens: 10000 },    // 恰好下限
    { max_tokens: 131072 },   // 大值
    { max_tokens: 0 },        // 0：交上游
    { max_tokens: -1 },       // 负数
    { max_tokens: 1.5 },      // 浮点
    { max_tokens: "4096" },   // 字符串
    { max_tokens: null },     // null
  ];
  for (const b of untouched) {
    const before = JSON.stringify(b);
    assert.equal(normalizeMaxTokens(b), false, `${before} 不应被改写`);
    assert.equal(JSON.stringify(b), before);
  }
  // max_completion_tokens 不参与该校验，一字不动
  const b = { max_tokens: 4096, max_completion_tokens: 30 };
  assert.equal(normalizeMaxTokens(b), true);
  assert.equal(b.max_completion_tokens, 30);
});

// ---- 回归：模型路由 ID（X-Request-Model 必须带前缀）--------------------------

test("resolveRouteId：目录名/展示名/路由 ID 三种写法都解析到规范 routeId", () => {
  const { resolveRouteId } = _internal;
  // 目录名
  assert.equal(resolveRouteId("glm-5.3"), "zaicoding_glm-5.3");
  assert.equal(resolveRouteId("glm-5.3-flash"), "zai_glm-5.3-flash");
  // 展示名（含大小写变体）
  assert.equal(resolveRouteId("GLM-5.3"), "zaicoding_glm-5.3");
  assert.equal(resolveRouteId("GLM-5.3-Flash"), "zai_glm-5.3-flash");
  assert.equal(resolveRouteId("Auto Fast"), "zai_auto-fast");
  // 路由 ID 本身
  assert.equal(resolveRouteId("zaicoding_glm-5.3"), "zaicoding_glm-5.3");
  assert.equal(resolveRouteId("zai_auto"), "zai_auto");
});

test("resolveRouteId：绝不给 X-Request-Model 发无前缀名（否则上游 400 非法模型）", () => {
  const { resolveRouteId } = _internal;
  for (const name of ["glm-5.3", "glm-5.3-flash", "auto", "auto-fast", "GLM-5.3"]) {
    const r = resolveRouteId(name);
    assert.match(r, /^(zai|zaicoding)_/, `${name} 应解析为带前缀的路由 ID，实际 ${r}`);
  }
});

test("resolveRouteId：未知名字回落 zai_auto；空值同样", () => {
  const { resolveRouteId } = _internal;
  assert.equal(resolveRouteId(""), "zai_auto");
  assert.equal(resolveRouteId("   "), "zai_auto");
  assert.equal(resolveRouteId("gpt-4o"), "zai_auto");
  assert.equal(resolveRouteId("claude-3-opus"), "zai_auto");
});

test("模型表：只留上游真实目录的 4 个（已下架的 turbo / deepseek 必须移除）", () => {
  const { autoclawModels } = _internal;
  const ids = Object.keys(autoclawModels());
  assert.deepEqual(ids.sort(), ["zai_auto", "zai_auto-fast", "zai_glm-5.3-flash", "zaicoding_glm-5.3"].sort());
  assert.ok(!ids.some((i) => i.includes("turbo")), "turbo 已下架，不应再广告");
  assert.ok(!ids.some((i) => i.startsWith("tdpsk_")), "deepseek 已下架，不应再广告");
});

test("PLATFORM_TM：绝不发 linux（上游只认 win/mac，linux 被拒）", () => {
  const { PLATFORM_TM } = _internal;
  assert.ok(["win", "mac"].includes(PLATFORM_TM), `PLATFORM_TM 只能是 win/mac，实际 ${PLATFORM_TM}`);
  assert.notEqual(PLATFORM_TM, "linux");
});

test("USER_AGENT：必须是 AutoClaw/* 形态（运行时默认 UA 会被上游 405 拒）", () => {
  const { USER_AGENT } = _internal;
  assert.match(USER_AGENT, /^AutoClaw\//, `实际 ${USER_AGENT}`);
  assert.ok(!/bun|node|undici/i.test(USER_AGENT), "不得含运行时名");
});

// ---- system 提示词规范化（第 7 道闸：上游对首条 system 做逐字指纹）-----------

test("IDENTITY_PREFIX：必须含身份句 + `## Tooling` 段（缺一段就 403 pay-view）", () => {
  const { IDENTITY_LINE, IDENTITY_PREFIX } = _internal;
  assert.equal(IDENTITY_LINE, "You are a personal assistant running inside OpenClaw.");
  assert.ok(IDENTITY_PREFIX.startsWith(IDENTITY_LINE), "前缀必须以身份句开头");
  assert.ok(IDENTITY_PREFIX.includes("## Tooling"), "前缀必须含 ## Tooling 段");
  assert.ok(IDENTITY_PREFIX.endsWith("\n"), "前缀应以换行收尾（便于拼原文）");
});

test("normalizeSystemPrompt：首条已经是 system → 前缀拼进它，客户端提示词逐字保留在后", () => {
  const { normalizeSystemPrompt, IDENTITY_PREFIX } = _internal;
  const body = { messages: [{ role: "system", content: "You are magpie gateway." }, { role: "user", content: "hi" }] };
  assert.equal(normalizeSystemPrompt(body), true);
  const sys = body.messages[0];
  assert.equal(sys.role, "system");
  assert.ok(sys.content.startsWith(IDENTITY_PREFIX), "前缀应拼在最前");
  assert.ok(sys.content.endsWith("You are magpie gateway."), "客户端原文应逐字保留在后");
  assert.equal(body.messages[1].content, "hi", "user 消息一字不动");
});

test("normalizeSystemPrompt：首条不是 system → 在最前插一条带前缀的 system（不重排其余）", () => {
  const { normalizeSystemPrompt, IDENTITY_PREFIX, IDENTITY_LINE } = _internal;
  const body = {
    messages: [
      { role: "user", content: "hello" },
      { role: "system", content: "late system" },
    ],
  };
  assert.equal(normalizeSystemPrompt(body), true);
  assert.equal(body.messages.length, 3, "应插入一条，不替换");
  assert.equal(body.messages[0].role, "system");
  assert.ok(body.messages[0].content.startsWith(IDENTITY_LINE));
  // 原本的 system 保持原位（只被改写了身份句，位置不动）
  assert.equal(body.messages[2].role, "system");
  assert.equal(body.messages[1].content, "hello");
});

test("normalizeSystemPrompt：外来身份句被改写成中性说法（ZCode / Claude Code / Codex / DeepSeek Harness）", () => {
  const { normalizeSystemPrompt } = _internal;
  const cases = [
    ["You are ZCode, an interactive coding agent", /You are an interactive coding agent/i],
    ["You are Claude Code, Anthropic's official CLI tool for Claude.", /You are a coding assistant/i],
    ["You are Codex, based on GPT-5.", /You are a coding agent/i],
    ["You are an AI agent powered by DeepSeek Harness.", /a local coding harness/i],
  ];
  for (const [text, want] of cases) {
    const body = { messages: [{ role: "system", content: text }, { role: "user", content: "x" }] };
    normalizeSystemPrompt(body);
    const out = body.messages[0].content;
    assert.match(out, want, `${text} 应被改写`);
    assert.ok(!/ZCode|Claude Code|DeepSeek Harness|You are Codex/i.test(out.split("## Tooling")[1] ?? ""), `${text} 改写后仍含产品名：${out}`);
  }
});

test("normalizeSystemPrompt：改写忽略 ASCII 大小写（闸门自己不敏感）", () => {
  const { normalizeSystemPrompt } = _internal;
  const body = { messages: [{ role: "system", content: "you are ZCODE" }, { role: "user", content: "x" }] };
  normalizeSystemPrompt(body);
  const out = body.messages[0].content;
  assert.ok(!/zcode/i.test(out.split("## Tooling")[1] ?? ""), `大小写变体也应被改写：${out}`);
});

test("normalizeSystemPrompt：长匹配优先（先命中长句，短句不留残渣）", () => {
  const { normalizeSystemPrompt } = _internal;
  const body = { messages: [{ role: "system", content: "You are a coding agent running in the Codex CLI tool" }, { role: "user", content: "x" }] };
  normalizeSystemPrompt(body);
  const out = body.messages[0].content;
  assert.ok(!/Codex/i.test(out), `不应残留 Codex：${out}`);
  assert.ok(/terminal CLI tool/.test(out), `应命中长句（terminal CLI tool）：${out}`);
});

test("normalizeSystemPrompt：幂等（正文已以身份句开头则只改写、不再前缀）", () => {
  const { normalizeSystemPrompt, IDENTITY_LINE, IDENTITY_PREFIX } = _internal;
  const body = { messages: [{ role: "system", content: `${IDENTITY_PREFIX}\nYou are Codex.` }, { role: "user", content: "x" }] };
  normalizeSystemPrompt(body);
  const once = body.messages[0].content;
  assert.equal(once.split(IDENTITY_LINE).length - 1, 1, "身份句只应出现一次");
  const body2 = { messages: [{ role: "system", content: once }, { role: "user", content: "x" }] };
  normalizeSystemPrompt(body2);
  assert.equal(body2.messages[0].content, once, "二次调用应逐字不变");
});

test("normalizeSystemPrompt：只动 system/developer，user/assistant/tool 一律不碰", () => {
  const { normalizeSystemPrompt } = _internal;
  const body = {
    messages: [
      { role: "assistant", content: "You are Claude Code" },
      { role: "user", content: "You are ZCode" },
      { role: "tool", content: "You are Codex" },
      { role: "system", content: "plain" },
    ],
  };
  normalizeSystemPrompt(body);
  // 插入的 system 前缀在 index 0，其余整体后移
  assert.equal(body.messages[1].content, "You are Claude Code");
  assert.equal(body.messages[2].content, "You are ZCode");
  assert.equal(body.messages[3].content, "You are Codex");
});

test("normalizeSystemPrompt：developer 角色同样享受白名单待遇", () => {
  const { normalizeSystemPrompt, IDENTITY_PREFIX } = _internal;
  const body = { messages: [{ role: "developer", content: "You are Codex" }, { role: "user", content: "x" }] };
  normalizeSystemPrompt(body);
  assert.equal(body.messages.length, 2, "developer 已是首条，不该再插");
  assert.ok(body.messages[0].content.startsWith(IDENTITY_PREFIX));
  assert.ok(!/Codex/i.test(body.messages[0].content));
});

test("normalizeSystemPrompt：content 是文本 part 数组 → 前缀拼进第一个文本 part", () => {
  const { normalizeSystemPrompt, IDENTITY_PREFIX } = _internal;
  const body = {
    messages: [
      { role: "system", content: [{ type: "text", text: "sys body" }] },
      { role: "user", content: "x" },
    ],
  };
  normalizeSystemPrompt(body);
  const parts = body.messages[0].content;
  assert.ok(Array.isArray(parts));
  assert.ok(parts[0].text.startsWith(IDENTITY_PREFIX));
  assert.ok(parts[0].text.endsWith("sys body"));
});

test("normalizeSystemPrompt：messages 缺失/非数组 → 不动（交给上游报格式错）", () => {
  const { normalizeSystemPrompt } = _internal;
  assert.equal(normalizeSystemPrompt({}), false);
  assert.equal(normalizeSystemPrompt({ messages: "nope" }), false);
  assert.equal(normalizeSystemPrompt(null), false);
});

test("normalizeSystemPrompt：返回值反映是否真的改写（拼网关注入的 body 必须触发 true）", () => {
  const { normalizeSystemPrompt } = _internal;
  const injected = { model: "auto", messages: [{ role: "system", content: "You are magpie." }, { role: "user", content: "hi" }] };
  assert.equal(normalizeSystemPrompt(injected), true);
  const already = { messages: [{ role: "system", content: _internal.IDENTITY_PREFIX }, { role: "user", content: "hi" }] };
  assert.equal(normalizeSystemPrompt(already), false, "已合规的 body 不应被判为改动");
});

test("findIgnoreAsciiCase / replaceAllIgnoreAsciiCase：字节级大小写折叠 + 全量替换", () => {
  const { findIgnoreAsciiCase, replaceAllIgnoreAsciiCase } = _internal;
  assert.equal(findIgnoreAsciiCase("xxABCDyy", "abcd"), 2);
  assert.equal(findIgnoreAsciiCase("hello", "zzz"), null);
  assert.equal(findIgnoreAsciiCase("中文ABCD", "abcd"), Buffer.byteLength("中文", "utf8"));
  assert.equal(replaceAllIgnoreAsciiCase("aAaA", "aa", "-"), "--");
  assert.equal(replaceAllIgnoreAsciiCase("nope", "aa", "-"), null);
  assert.equal(replaceAllIgnoreAsciiCase("中文ABC中文abc", "abc", "X"), "中文X中文X");
});

// ---- v0.9.0 新增：CN ↔ 全球互备的 host 归属判定 -------------------------------
// 上游账号是分区的：国内短信账号只认 CN 侧，Google/z.ai 账号只认全球侧。
// 判定依据是 refresh token 的 JWT claim source_id（agent* = 国内短信号）。

const mkJwt = (claims) => [
  b64url({ alg: "HS256", typ: "JWT" }),
  b64url(claims),
  "sig",
].join(".");

test("isSmsAccountToken：source_id 以 agent 开头即国内短信号", () => {
  assert.equal(isSmsAccountToken(mkJwt({ source_id: "agent" })), true);
  assert.equal(isSmsAccountToken(mkJwt({ source_id: "agent-cn" })), true);
  assert.equal(isSmsAccountToken(mkJwt({ source_id: "AgentCN" })), true); // 大小写不敏感
  assert.equal(isSmsAccountToken(mkJwt({ source_id: "google" })), false);
  assert.equal(isSmsAccountToken(mkJwt({ source_id: "zai" })), false);
  assert.equal(isSmsAccountToken(mkJwt({})), false);
  assert.equal(isSmsAccountToken(""), false);
  assert.equal(isSmsAccountToken(undefined), false);
});

test("isSmsAccountToken：真实 source_id 形如 agentrefresh_token / autoclawrefresh_token", () => {
  // 2026-10-17 DMIT 实测：上游填的是「token 种类」而非纯账号来源
  assert.equal(isSmsAccountToken(mkJwt({ source_id: "agentrefresh_token" })), true);
  assert.equal(isSmsAccountToken(mkJwt({ source_id: "agentaccess_token" })), true);
  // 🔴 autoclaw 以 a 开头，但绝不能误判成 agent
  assert.equal(isSmsAccountToken(mkJwt({ source_id: "autoclawrefresh_token" })), false);
  assert.equal(isSmsAccountToken(mkJwt({ source_id: "autoclawaccess_token" })), false);
});

test("hostsForAuth：国内短信账号 → CN 优先，国际账号 → 全球优先", () => {
  // 国内短信号：refresh 里的 source_id=agent
  assert.deepEqual(
    hostsForAuth({ refresh: mkJwt({ source_id: "agent" }), access: mkJwt({}) }),
    [CN_HOST, GLOBAL_HOST],
  );
  // Google 号
  assert.deepEqual(
    hostsForAuth({ refresh: mkJwt({ source_id: "google" }), access: mkJwt({}) }),
    [GLOBAL_HOST, CN_HOST],
  );
  // z.ai 号
  assert.deepEqual(
    hostsForAuth({ refresh: mkJwt({ source_id: "zai" }), access: mkJwt({}) }),
    [GLOBAL_HOST, CN_HOST],
  );
});

test("hostsForAuth：没有 refresh 时退回 access，两者都无则默认全球优先", () => {
  assert.deepEqual(
    hostsForAuth({ access: mkJwt({ source_id: "agent" }) }),
    [CN_HOST, GLOBAL_HOST],
  );
  assert.deepEqual(hostsForAuth({}), [GLOBAL_HOST, CN_HOST]);
  assert.deepEqual(hostsForAuth(undefined), [GLOBAL_HOST, CN_HOST]);
});

test("hostsForAuth：两个 host 互不相同且都非空（真互备，不是同一个地址）", () => {
  const h = hostsForAuth({ refresh: mkJwt({ source_id: "google" }) });
  assert.equal(h.length, 2);
  assert.notEqual(h[0], h[1]);
  assert.ok(h[0].startsWith("https://"));
  assert.ok(h[1].startsWith("https://"));
});

// ---- v0.9.0 新增：手机验证码登录 ---------------------------------------------

test("phoneSmsMethod：是 oauth 类型、只有 phone 一个 prompt、authorize 为函数", () => {
  assert.equal(phoneSmsMethod.type, "oauth");
  assert.match(phoneSmsMethod.label, /手机验证码/);
  assert.equal(typeof phoneSmsMethod.authorize, "function");
  assert.equal(phoneSmsMethod.prompts.length, 1);
  assert.equal(phoneSmsMethod.prompts[0].key, "phone");
  assert.equal(phoneSmsMethod.prompts[0].type, "text");
});

test("phoneSmsMethod：手机号校验只收 11 位、不带 +86", () => {
  const v = phoneSmsMethod.prompts[0].validate;
  assert.equal(v("13800138000"), undefined);
  assert.ok(v("1380013800"));      // 10 位
  assert.ok(v("138001380001"));    // 12 位
  assert.ok(v("+8613800138000"));  // 带 +86
  assert.ok(v(""));                // 空
  assert.ok(v(undefined));
});

test("phoneSmsMethod：手机号非法时 throw（宿主契约要求 oauth 失败必须 throw）", async () => {
  await assert.rejects(
    () => phoneSmsMethod.authorize({ phone: "123" }),
    /11 位手机号/,
  );
  await assert.rejects(() => phoneSmsMethod.authorize({}), /11 位手机号/);
});

test("phoneSmsMethod：发码走后端 → 返回 code 模式，callback 校验验证码形态", async () => {
  const realFetch = globalThis.fetch;
  const seen = [];
  globalThis.fetch = async (url, init) => {
    seen.push({ url: String(url), body: init?.body ? JSON.parse(String(init.body)) : undefined });
    return new Response(JSON.stringify({ code: 0, msg: "ok", data: {} }), { status: 200 });
  };
  try {
    const r = await phoneSmsMethod.authorize({ phone: "13800138000" });
    // 发码打到 CN host 的 agent-send-code
    assert.match(seen[0].url, /autoglm-acceleration-api\.zhipuai\.cn\/userapi\/v1\/agent-send-code$/);
    assert.equal(seen[0].body.phone, "13800138000");
    assert.equal(seen[0].body.source_id, "autoclaw");
    assert.ok(seen[0].body.device_id, "必须带 device_id");

    // 返回形态符合宿主 oauth method 契约
    assert.equal(r.method, "code");
    assert.match(r.instructions, /138\*\*\*\*8000/);
    assert.equal(typeof r.callback, "function");

    // 验证码形态非法 → failed（不该发请求）
    const before = seen.length;
    const bad = await r.callback({ code: "abc" });
    assert.equal(bad.type, "failed");
    assert.match(bad.error, /4~8 位数字/);
    assert.equal(seen.length, before, "验证码非法时不应发起登录请求");
  } finally {
    globalThis.fetch = realFetch;
  }
});

test("phoneSmsMethod：发码失败（code !== 0）必须 throw，不能静默继续", async () => {
  const realFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response(
    JSON.stringify({ code: 400001, msg: "手机号未注册" }), { status: 200 });
  try {
    await assert.rejects(
      () => phoneSmsMethod.authorize({ phone: "13800138000" }),
      /手机号未注册/,
    );
  } finally {
    globalThis.fetch = realFetch;
  }
});

// ---- v0.9.0 新增：双 provider 注册（autoclaw / autoclaw-cn） -------------------
// magpie 的账号归属由「登录时的 provider」决定（logins.json 的 agent 字段）。
// 国内号当初是用 autoclaw-cn 登录的 —— 不注册这个 provider，那个账号
// 在 providers/accounts 里根本不会出现，等于废着。
// 宿主源码（strings 提自 binary）：
//   "servers are the plugin functions a module exports: default {id?, server} (v1),
//    else every function it exports, ..."  ⇒ 命名导出全部会被加载。

test("导出形态：两个 provider 工厂都是函数（命名导出即可被宿主加载）", () => {
  assert.equal(typeof AutoclawAuthPlugin, "function");
  assert.equal(typeof AutoclawCnAuthPlugin, "function");
});

test("autoclaw-cn：providerName/首选 host/默认登录方式都指向国内", async () => {
  const p = await AutoclawCnAuthPlugin({}, {});
  const cfg = {};
  await p.config(cfg);
  assert.equal(p.auth.provider, "autoclaw-cn");
  assert.match(cfg.provider["autoclaw-cn"].name, /国内/);
  assert.equal(cfg.provider["autoclaw-cn"].api, CN_HOST);
  // 国内 provider 的首个登录按钮必须是手机验证码（无需浏览器）
  assert.match(p.auth.methods[0].label, /手机验证码/);
});

test("autoclaw：首选 host 是全球，首个登录方式是网页 OAuth", async () => {
  const p = await AutoclawAuthPlugin({}, {});
  const cfg = {};
  await p.config(cfg);
  assert.equal(p.auth.provider, "autoclaw");
  assert.equal(cfg.provider.autoclaw.api, GLOBAL_HOST);
  assert.match(p.auth.methods[0].label, /网页登录/);
});

// ---- v0.9.2：授权链接登录改为「本地监听优先，粘贴兜底」 ----------------------

test("manualOauthMethod：默认走本地监听（method=auto），不再强制粘贴", async () => {
  const { manualOauthMethod } = _internal;
  const out = await manualOauthMethod.authorize({ vendor: "google" });
  try {
    assert.equal(out.method, "auto");
    assert.match(out.url, /^http:\/\/127\.0\.0\.1:\d+\/$/);
    assert.equal(typeof out.callback, "function");
    // 回调地址就是官方白名单形态（host=localhost、固定路径、白名单端口）
    const port = new URL(out.url).port;
    assert.match(out.instructions, new RegExp(`127\\.0\\.0\\.1:${port}`));
  } finally {
    // 别调 callback（会等浏览器 5 分钟）：走 abort 让会话立即结束并释放端口
    const port = new URL(out.url).port;
    await fetch(`http://127.0.0.1:${port}/abort`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ reason: "test" }),
    }).catch(() => {});
    await out.callback().catch(() => {});
  }
});

test("manualOauthMethod：paste:true 强制降级为粘贴（method=code）", async () => {
  const { manualOauthMethod } = _internal;
  const out = await manualOauthMethod.authorize({ vendor: "google", paste: true });
  assert.equal(out.method, "code");
  assert.match(out.url, /^https:\/\/liuxigreen\.github\.io\//);
});

test("本地回调：state 不匹配时拒收，且不污染会话", () => {
  const { acceptLocalCallback } = _internal;
  // 未发起授权时 expectedOauthState === null → 任何 code 都不收
  assert.equal(acceptLocalCallback(null, "abc", "x"), false);
  // 发起后 state 不符 → 拒收
  assert.equal(acceptLocalCallback("S1", "abc", "S2"), false);
  // 完全匹配 → 收
  assert.equal(acceptLocalCallback("S1", "abc", "S1"), true);
  // 缺 code → 拒收
  assert.equal(acceptLocalCallback("S1", null, "S1"), false);
});

test("两个 provider 各自注册、互不覆盖，且模型表一致", async () => {  const cfg = {};
  await (await AutoclawAuthPlugin({}, {})).config(cfg);
  await (await AutoclawCnAuthPlugin({}, {})).config(cfg);
  assert.ok(cfg.provider.autoclaw);
  assert.ok(cfg.provider["autoclaw-cn"]);
  assert.notEqual(cfg.provider.autoclaw.api, cfg.provider["autoclaw-cn"].api);
  assert.deepEqual(
    Object.keys(cfg.provider.autoclaw.models).sort(),
    Object.keys(cfg.provider["autoclaw-cn"].models).sort(),
  );
});

// ---- 灵感中心（daily_inspiration_center）------------------------------------
// 国际账号实测可领 +200；国内手机号账号会「翻成 completed 但 reward=0」，
// 等于白吃当天机会 ⇒ 必须按账号类型跳过。

test("claimInspirationCenter：网络/接口异常一律返回 null，绝不 throw", async () => {
  const { claimInspirationCenter } = _internal;
  // 用一个必然连不上的 host，确保进入 catch
  const r = await claimInspirationCenter("fake-token", "http://127.0.0.1:1");
  assert.equal(r, null);
});

test("checkin 里的账号判定：国内号不领灵感中心", () => {
  const { isSmsAccountToken } = _internal;
  const b64url = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
  const jwt = (p) => `${b64url({ alg: "none" })}.${b64url(p)}.sig`;

  const smsTok = jwt({ source_id: "agentrefresh_token" });
  const globTok = jwt({ source_id: "autoclawrefresh_token" });

  assert.equal(isSmsAccountToken(smsTok), true, "国内号应识别为 SMS 账号");
  assert.equal(isSmsAccountToken(globTok), false, "国际号不应识别为 SMS 账号");
});
