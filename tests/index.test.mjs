/** 纯函数单测（无网络）：node --test tests/ */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { _internal, AutoclawAuthPlugin } from "../index.mjs";

const {
  md5Hex, jwtClaim, tokenFields, bizHeaders, bareToken,
  newDeviceId, signinConfig, checkinOutcome, accountDisplayName,
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
  assert.equal(plugin.auth.methods.length, 2); // 网页登录 + 手动粘贴登录
  assert.match(plugin.auth.methods[1].label, /手动粘贴/);
  assert.equal(typeof plugin.auth.methods[1].authorize, "function");
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
  const out = await manualOauthMethod.authorize({ vendor: "google" });
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
  const out = await manualOauthMethod.authorize({ vendor: "zai" });
  const u = new URL(out.url);
  assert.equal(u.searchParams.get("vendor"), "zai");
  assert.ok(u.searchParams.get("device_id"));
  assert.equal(u.searchParams.get("redirect_uri"), "http://localhost:18432/auth/callback-zai");
});

test("manualOauthMethod.authorize：每次调用 device_id 均不同（会话隔离）", async () => {
  const { manualOauthMethod } = _internal;
  const a = new URL((await manualOauthMethod.authorize({ vendor: "google" })).url).searchParams.get("device_id");
  const b = new URL((await manualOauthMethod.authorize({ vendor: "google" })).url).searchParams.get("device_id");
  assert.notEqual(a, b);
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
  const out = await manualOauthMethod.authorize({ vendor: "google" });
  const r1 = await out.callback("");
  assert.equal(r1.type, "failed");
  assert.match(r1.error, /为空/);
});

// ---- 回归：粘贴内容诊断（把「登录失败」变成可操作提示） ----------------------

test("callback：粘了错误回调（含 error=）给出明确提示，不发请求", async () => {
  const { manualOauthMethod } = _internal;
  const out = await manualOauthMethod.authorize({ vendor: "google" });
  const r = await out.callback("http://localhost:18432/auth/callback-google?error=access_denied&state=x");
  assert.equal(r.type, "failed");
  assert.match(r.error, /授权被拒绝|错误回调/);
});

test("callback：粘了无 code 的 URL 给出明确提示", async () => {
  const { manualOauthMethod } = _internal;
  const out = await manualOauthMethod.authorize({ vendor: "google" });
  const r = await out.callback("https://liuxigreen.github.io/magpie-autoclaw-auth/autoclaw-guide.html?vendor=google");
  assert.equal(r.type, "failed");
  assert.match(r.error, /没有 code/);
});

test("callback：裸 code 形态可疑时提前拦住", async () => {
  const { manualOauthMethod } = _internal;
  const out = await manualOauthMethod.authorize({ vendor: "google" });
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
