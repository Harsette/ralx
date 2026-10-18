// Seeds a temporary D1 test identity, never a login bypass in the Worker.
// All raw enrollment/curl output stays in memory. Only status summaries are printed.
import { spawnSync } from "node:child_process";
import { randomBytes, createHash } from "node:crypto";
import { mkdirSync, writeFileSync, unlinkSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
const cwd = fileURLToPath(new URL("..", import.meta.url));
const base = process.env.RALX_PROOF_URL;
const config = process.env.RALX_WRANGLER_CONFIG;
if (!base || !config || process.env.RALX_ALLOW_REMOTE_PROOF !== "yes") throw Error("Set RALX_PROOF_URL, RALX_WRANGLER_CONFIG and RALX_ALLOW_REMOTE_PROOF=yes for an explicitly authorized remote test");
const user = "user_liveproof_" + randomBytes(8).toString("hex");
const code = "en_" + randomBytes(32).toString("hex");
const digest = createHash("sha256").update(code).digest("hex");
const expires = Math.floor(Date.now() / 1000) + 900;
const sqlPath = resolve(cwd, "evidence-private/live-proof.sql");
mkdirSync(resolve(cwd, "evidence-private"), { recursive: true });
function sql(source) {
  writeFileSync(sqlPath, source);
  const r = spawnSync(
    process.execPath,
    [
      resolve(cwd, "node_modules/wrangler/bin/wrangler.js"),
      "d1",
      "execute",
      "DB",
      "--config",
      config,
      "--remote",
      "--file",
      sqlPath,
    ],
    { cwd, encoding: "utf8" },
  );
  if (r.status !== 0) throw Error("D1 proof setup failed");
}
function curl(path, data) {
  const r = spawnSync(
    "curl.exe",
    [
      "--silent",
      "--show-error",
      "--max-time",
      "40",
      "--write-out",
      "\n%{http_code}",
      ...(data === undefined
        ? []
        : [
            "--request",
            "POST",
            "--header",
            "Content-Type: application/json",
            "--data-binary",
            "@-",
          ]),
      base + path,
    ],
    {
      input: data === undefined ? undefined : JSON.stringify(data),
      encoding: "utf8",
    },
  );
  if (r.status !== 0) throw Error("curl failed");
  const split = r.stdout.lastIndexOf("\n");
  return {
    status: Number(r.stdout.slice(split + 1)),
    body: r.stdout.slice(0, split),
  };
}
// Bearer headers go through stdin, never process arguments, disk or stdout.
function authenticated(path, key, data) {
  const args = [
    "--silent",
    "--show-error",
    "--max-time",
    "40",
    "--write-out",
    "\n%{http_code}",
    "--header",
    "@-",
  ];
  if (data !== undefined) {
    args.push(
      "--request",
      "POST",
      "--header",
      "Content-Type: application/json",
      "--data-binary",
      JSON.stringify(data),
    );
  }
  args.push(base + path);
  const r = spawnSync("curl.exe", args, {
    input: `Authorization: Bearer ${key}\n`,
    encoding: "utf8",
  });
  if (r.status !== 0) throw Error("curl failed");
  const split = r.stdout.lastIndexOf("\n");
  return {
    status: Number(r.stdout.slice(split + 1)),
    body: r.stdout.slice(0, split),
  };
}
try {
  sql(
    `INSERT INTO users(id,email,name) VALUES ('${user}','ralx-liveproof@example.invalid','Temporary live proof');INSERT INTO codes(hash,user_id,expires) VALUES ('${digest}','${user}',${expires});`,
  );
  const enrollment = curl("/api/enroll", {
    code,
    name: "Temporary live proof",
    client: "curl",
  });
  console.log("curl POST /api/enroll ->", enrollment.status, "key=[redacted]");
  const key = JSON.parse(enrollment.body).key;
  if (!key) throw Error("Enrollment failed");
  console.log(
    "curl POST /api/enroll reused code ->",
    curl("/api/enroll", { code }).status,
  );
  for (const path of ["/api/v1/whoami", "/api/v1/tools"]) {
    const r = authenticated(path, key);
    console.log("curl GET", path, "->", r.status);
    if (r.status === 200)
      console.log(
        path.endsWith("tools")
          ? "tool count=" + JSON.parse(r.body).tools.length
          : "test owner matched=" +
              String(
                JSON.parse(r.body).owner_email ===
                  "ralx-liveproof@example.invalid",
              ),
      );
  }
  for (const method of ["initialize", "tools/list"]) {
    const r = authenticated("/mcp", key, {
      jsonrpc: "2.0",
      id: 1,
      method,
      params:
        method === "initialize"
          ? {
              protocolVersion: "2025-06-18",
              capabilities: {},
              clientInfo: { name: "curl-proof", version: "1" },
            }
          : {},
    });
    const b = JSON.parse(r.body);
    console.log(
      "curl POST /mcp",
      method,
      "->",
      r.status,
      b.result ? "result present" : "provider setup pending",
    );
  }
  sql(`UPDATE agents SET revoked=1 WHERE user_id='${user}';`);
  console.log(
    "curl GET /api/v1/whoami after D1 revoke ->",
    authenticated("/api/v1/whoami", key).status,
  );
} finally {
  sql(
    `DELETE FROM agents WHERE user_id='${user}';DELETE FROM codes WHERE user_id='${user}';DELETE FROM users WHERE id='${user}';`,
  );
  unlinkSync(sqlPath);
  console.log(
    "Temporary D1 proof identity removed. WorkOS login and real account approval require separate proof.",
  );
}
