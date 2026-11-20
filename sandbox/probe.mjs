// Isolation probes, run inside the reviewer sandbox by CI (never by the
// gate). `dep-review review --probe` runs this script with exactly the
// container flags, network and proxy of a real review; only the command
// differs. Exit status 0 means every probe passed.
//
// Usage: node probe.mjs --proxy IP:PORT [--deny-tcp HOST:PORT]... [--deny-dns NAME]...
//                       [--deny-http URL]... [--writable DIR]... [--readonly DIR]...
import { execFileSync } from "node:child_process";
import dns from "node:dns/promises";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";

const args = process.argv.slice(2);
const opt = (name) => args.flatMap((a, i) => (a === name ? [args[i + 1]] : []));
const [proxy] = opt("--proxy");
let failed = 0;
const pass = (what) => console.log(`PASS ${what}`);
const fail = (what) => {
  failed++;
  console.log(`FAIL ${what}`);
};
const check = (ok, what) => (ok ? pass(what) : fail(what));

// --- identity and kernel ---------------------------------------------------
check(process.getuid() !== 0 && process.getgid() !== 0, `non-root (uid=${process.getuid()} gid=${process.getgid()})`);
const status = fs.readFileSync("/proc/self/status", "utf8");
check(/^CapEff:\s*0+$/m.test(status), "no effective capabilities");
check(/^NoNewPrivs:\s*1$/m.test(status), "no_new_privs set");
let dmesg = "";
try {
  dmesg = execFileSync("dmesg", { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
} catch (e) {
  dmesg = String(e.stdout || "") + String(e.stderr || "");
}
check(/gVisor/i.test(dmesg), "kernel is gVisor (dmesg)");
console.log(`  /proc/version: ${fs.readFileSync("/proc/version", "utf8").trim()}`);

// --- environment -------------------------------------------------------------
const names = Object.keys(process.env).sort();
console.log(`  env: ${names.join(" ")}`);
const bad = names.filter((n) => /^(GITHUB_|ACTIONS_|RUNNER_)/.test(n) || (/(TOKEN|SECRET|PASSWORD|CREDENTIAL|KEY)/.test(n) && n !== "ANTHROPIC_API_KEY"));
check(bad.length === 0, `no credential-looking or runner variables (${bad.join(" ") || "none"})`);
check(process.env.ANTHROPIC_API_KEY === "dep-review-sandbox-no-credential", "ANTHROPIC_API_KEY is the placeholder");

// --- filesystem ------------------------------------------------------------
function canWrite(dir) {
  const p = `${dir}/.probe-${process.pid}`;
  try {
    fs.writeFileSync(p, "x");
    fs.unlinkSync(p);
    return true;
  } catch {
    return false;
  }
}
for (const d of ["/", "/usr", "/etc", "/work", ...opt("--readonly")]) check(!canWrite(d), `read-only: ${d}`);
for (const d of [os.homedir(), "/tmp", ...opt("--writable")]) check(canWrite(d), `writable tmpfs: ${d}`);
const mounts = fs.readFileSync("/proc/self/mounts", "utf8");
console.log(`  mounts:\n${mounts.trim().replace(/^/gm, "    ")}`);
const rootMount = mounts.split("\n").find((l) => l.split(" ")[1] === "/");
check(rootMount && /\bro\b/.test(rootMount.split(" ")[3]), "root filesystem mounted ro");
check(fs.readdirSync("/work").sort().join(",") === "evidence,repo", "/work holds exactly evidence and repo");

// --- network -----------------------------------------------------------------
const timeout = (ms, p) => Promise.race([p, new Promise((_, rej) => setTimeout(() => rej(new Error("timeout")), ms))]);

function tcp(hostport, ms = 4000) {
  const i = hostport.lastIndexOf(":");
  const host = hostport.slice(0, i).replace(/^\[|\]$/g, "");
  const port = Number(hostport.slice(i + 1));
  return new Promise((resolve) => {
    const s = net.connect({ host, port });
    const done = (r) => {
      s.destroy();
      resolve(r);
    };
    s.setTimeout(ms, () => done("timeout"));
    s.on("connect", () => done("connected"));
    s.on("error", (e) => done(e.code || e.message));
  });
}

async function http(method, url, { body, headers = {}, raw } = {}) {
  // Raw request over TCP so absolute-form and CONNECT targets reach the proxy as written.
  const u = new URL(`http://${proxy}`);
  return new Promise((resolve) => {
    const s = net.connect({ host: u.hostname, port: Number(u.port) });
    let data = "";
    s.setTimeout(10000, () => {
      s.destroy();
      resolve({ status: 0, body: "timeout" });
    });
    s.on("error", (e) => resolve({ status: 0, body: e.code || e.message }));
    s.on("data", (d) => (data += d));
    s.on("end", () => {
      const m = /^HTTP\/1\.\d (\d{3})/.exec(data);
      resolve({ status: m ? Number(m[1]) : 0, body: data.split("\r\n\r\n").slice(1).join("\r\n\r\n") });
    });
    s.on("connect", () => {
      const b = body === undefined ? "" : typeof body === "string" ? body : JSON.stringify(body);
      const h = { Host: proxy, Connection: "close", "Content-Type": "application/json", "Content-Length": Buffer.byteLength(b), ...headers };
      s.write(raw || `${method} ${url} HTTP/1.1\r\n${Object.entries(h).map(([k, v]) => `${k}: ${v}`).join("\r\n")}\r\n\r\n${b}`);
    });
  });
}

for (const name of opt("--deny-dns")) {
  let r;
  try {
    r = await timeout(6000, dns.lookup(name, { all: true }));
  } catch (e) {
    r = e.code || e.message;
  }
  check(!Array.isArray(r), `no DNS: ${name} (${Array.isArray(r) ? JSON.stringify(r) : r})`);
}
{
  const resolver = new dns.Resolver({ timeout: 2000, tries: 1 });
  resolver.setServers(["8.8.8.8", "1.1.1.1"]);
  let r;
  try {
    r = await timeout(6000, resolver.resolve4("github.com"));
  } catch (e) {
    r = e.code || e.message;
  }
  check(!Array.isArray(r), `no DNS via public resolvers (${Array.isArray(r) ? r : r})`);
}
for (const t of opt("--deny-tcp")) {
  const r = await tcp(t);
  check(r !== "connected", `no TCP: ${t} (${r})`);
}
for (const u of opt("--deny-http")) {
  let r;
  try {
    r = await timeout(8000, fetch(u)).then((x) => `HTTP ${x.status}`);
  } catch (e) {
    r = e.cause?.code || e.message;
  }
  check(!String(r).startsWith("HTTP"), `no HTTP(S): ${u} (${r})`);
}

// --- the proxy ---------------------------------------------------------------
{
  const r = await tcp(proxy);
  check(r === "connected", `proxy reachable: ${proxy} (${r})`);
  const model = opt("--model")[0];
  const msg = (extra = {}) => ({ model, max_tokens: 1, messages: [{ role: "user", content: "x" }], ...extra });
  const refused = [
    ["GET", "/v1/models"],
    ["GET", "/v1/messages"],
    ["POST", "/v1/messages/count_tokens", msg()],
    ["POST", "/v1/messages/batches", msg()],
    ["POST", "/v1/files", ""],
    ["POST", "/v1/complete", msg()],
    ["POST", "/v1/oauth/token", { grant_type: "x" }],
    ["POST", "/v1/messages?beta=true&x=1", msg()],
    ["POST", "/v1/messages/../models", msg()],
    ["POST", "/", msg()],
    ["CONNECT", "api.anthropic.com:443"],
    ["POST", "/v1/messages", msg({ model: "claude-haiku-4-5" })],
    ["POST", "/v1/messages", msg({ tools: [{ type: "web_fetch_20250910", name: "web_fetch" }] })],
    ["POST", "/v1/messages", msg({ mcp_servers: [{ type: "url", url: "https://example.com/mcp", name: "x" }] })],
    ["POST", "/v1/messages", msg({ messages: [{ role: "user", content: [{ type: "image", source: { type: "url", url: "https://example.com/x.png" } }] }] })],
    ["POST", "/v1/messages", msg({ messages: [{ role: "user", content: [{ type: "document", source: { type: "file", file_id: "file_x" } }] }] })],
  ];
  for (const [m, p, b] of refused) {
    const r = await http(m, p, { body: b });
    check(r.status === 403, `proxy refuses ${m} ${p}${b && b.model && b.model !== model ? " (other model)" : ""} -> ${r.status}`);
  }
  // Absolute-form target: the proxy must ignore the authority and only
  // ever talk to its upstream. Sent with a disallowed model so nothing is
  // forwarded or counted either way.
  const abs = await http("POST", "http://example.com/v1/models", { body: msg() });
  check(abs.status === 403, `proxy refuses absolute-form http://example.com/v1/models -> ${abs.status}`);
}

console.log(failed ? `${failed} probe(s) FAILED` : "all probes passed");
process.exit(failed ? 1 : 0);
