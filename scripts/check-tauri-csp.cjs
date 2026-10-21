#!/usr/bin/env node
"use strict";

// Tauri CSP 护栏（零依赖，仅用 Node 标准库）。
//
// ## 为什么需要它
//
// `security.csp` 是**字符串**：写错不会有编译期报错，也不会有测试失败 ——
// 代价在运行时才出现，而且两个方向都很糟：
//
//   · 写成 `null`（本仓历史状态，规格 D6）⇒ 页面没有任何内容安全策略，
//     一次注入即可读走用户的本机账号数据；
//   · 写得太紧 ⇒ 白屏 / IPC 全断，而 `cargo check`、`vite build` 全绿。
//
// 所以这里把「最小必要集合」钉成断言：**Tauri IPC 必须通、本机网关必须通、
// 脚本来源必须只有 'self'**。改 CSP 必须同时改本文件的期望，不能悄悄放宽。
//
// 用法：node scripts/check-tauri-csp.cjs   （npm run check:csp）

const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const CONFIG = path.join(ROOT, "src-tauri", "tauri.conf.json");

const failures = [];
const notes = [];
const fail = (message) => failures.push(message);

function directives(csp) {
  /** @type {Map<string, string[]>} */
  const map = new Map();
  for (const part of csp.split(";")) {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    if (tokens.length === 0) continue;
    map.set(tokens[0], tokens.slice(1));
  }
  return map;
}

function main() {
  let raw;
  try {
    raw = fs.readFileSync(CONFIG, "utf8");
  } catch (error) {
    fail(`读不到 src-tauri/tauri.conf.json：${error.message}`);
    return;
  }

  let config;
  try {
    config = JSON.parse(raw);
  } catch (error) {
    fail(`tauri.conf.json 不是合法 JSON：${error.message}`);
    return;
  }

  const security = config?.app?.security;
  if (!security) {
    fail("tauri.conf.json 缺少 app.security 段");
    return;
  }

  // ① 生产 CSP 必须是字符串，且不能是 null / 空串。
  const csp = security.csp;
  if (typeof csp !== "string" || csp.trim() === "") {
    fail(
      `app.security.csp 必须是字符串（当前 ${JSON.stringify(csp)}）—— null 等于没有 CSP（D6）`,
    );
    return;
  }

  const parsed = directives(csp);
  const require = (name, values) => {
    const actual = parsed.get(name);
    if (!actual) {
      fail(`CSP 缺少 ${name}`);
      return;
    }
    for (const value of values) {
      if (!actual.includes(value)) fail(`CSP 的 ${name} 缺少 ${value}`);
    }
  };

  // ② 默认与脚本来源收紧到 self。
  require("default-src", ["'self'"]);
  require("script-src", ["'self'"]);
  require("object-src", ["'none'"]);
  require("base-uri", ["'self'"]);

  // ③ Tauri IPC 通道：缺这两个，前端所有 invoke 都会在运行期被 CSP 拦掉。
  require("connect-src", ["ipc:", "http://ipc.localhost"]);

  // ④ 本机网关（127.0.0.1 上的 5789x 端口）与开发期 HMR。
  const connect = parsed.get("connect-src") || [];
  if (!connect.some((value) => value.startsWith("http://127.0.0.1"))) {
    fail("CSP 的 connect-src 缺少本机网关 http://127.0.0.1:*");
  }

  // ⑤ 明确禁止的两类放宽：脚本 eval 与脚本通配。
  const scriptSrc = parsed.get("script-src") || [];
  if (scriptSrc.includes("'unsafe-eval'")) {
    fail("生产 CSP 的 script-src 不得包含 'unsafe-eval'");
  }
  if (scriptSrc.includes("*") || scriptSrc.some((value) => value.endsWith("://*"))) {
    fail("生产 CSP 的 script-src 不得使用通配来源");
  }

  // ⑥ 样式必须允许 inline：Tailwind v4 与组件库在运行时注入 <style>，
  //    禁掉它会把整个界面变成无样式的白页。
  const styleSrc = parsed.get("style-src") || [];
  if (!styleSrc.includes("'unsafe-inline'")) {
    fail("CSP 的 style-src 必须包含 'unsafe-inline'（Tailwind/Radix 运行时注入样式）");
  }

  // ⑦ 开发期单独一条：Vite HMR 需要 ws://localhost:*，生产 CSP 不能带它。
  const devCsp = security.devCsp;
  if (typeof devCsp !== "string" || devCsp.trim() === "") {
    fail("app.security.devCsp 必须单独声明（dev 的 HMR 与生产策略不能混用）");
  } else {
    const devConnect = directives(devCsp).get("connect-src") || [];
    const hasHmr = devConnect.some(
      (value) => value.startsWith("ws://localhost") || value.startsWith("ws://127.0.0.1"),
    );
    if (!hasHmr) fail("devCsp 的 connect-src 必须允许 Vite HMR 的 ws://localhost:*");
    if (connect.some((value) => value.startsWith("ws://localhost"))) {
      fail("生产 CSP 的 connect-src 不得包含 ws://localhost（那只是开发期需要）");
    }
  }

  notes.push("csp 非空且 default-src/script-src 收紧到 'self'");
  notes.push("connect-src 覆盖 Tauri IPC 与本机网关");
  notes.push("devCsp 与生产策略分离");
}

main();

if (failures.length > 0) {
  console.error("[check-tauri-csp] 失败：");
  for (const failure of failures) console.error(`  ✗ ${failure}`);
  process.exit(1);
}

console.log("[check-tauri-csp] 通过：");
for (const note of notes) console.log(`  · ${note}`);
