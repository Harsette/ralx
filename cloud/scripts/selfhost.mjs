#!/usr/bin/env node
import { spawn, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { chmodSync, existsSync, lstatSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createInterface } from 'node:readline/promises';
import { Writable } from 'node:stream';
import { createServer } from 'node:net';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
process.chdir(root);
const args = new Set(process.argv.slice(2));
const allowed = new Set(['--local', '--check', '--update', '--help']);
for (const arg of args) if (!allowed.has(arg)) throw new Error(`Unknown option: ${arg}`);
if (args.has('--help')) {
  console.log('npm run selfhost [-- --local [--check] | --update]\nLocal never logs in, creates remote resources or deploys. Update uses the existing account and database.');
  process.exit(0);
}
if (args.has('--check') && !args.has('--local')) throw new Error('--check requires --local');
if (args.has('--local') && args.has('--update')) throw new Error('--local and --update cannot be combined');
if (Number(process.versions.node.split('.')[0]) < 22) throw new Error('Node 22 or newer is required');
const wrangler = resolve(root, 'node_modules/wrangler/bin/wrangler.js');
if (!existsSync(wrangler)) throw new Error('Run npm ci in cloud/ first');
const local = args.has('--local');
const configPath = resolve(root, local ? 'wrangler.selfhost.local.json' : 'wrangler.selfhost.json');
const secretsPath = resolve(root, '.selfhost-secrets.json');
const env = { ...process.env, WRANGLER_SEND_METRICS: 'false', CI: 'true' };
if (local) {
  // Do not let ambient Cloudflare credentials participate in local proof.
  for (const key of Object.keys(env)) if (/^(CLOUDFLARE_|CF_)/.test(key)) delete env[key];
}
async function run(argv, input, quiet = false) {
  return new Promise((done, fail) => {
    const p = spawn(process.execPath, [wrangler, ...argv, '--config', configPath], {
      cwd: root, env, stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true,
    });
    let out = '';
    p.stdout.on('data', b => { out += b; if (!quiet) process.stdout.write(b); });
    p.stderr.on('data', b => { if (!quiet) process.stderr.write(b); });
    p.on('error', fail);
    p.on('close', code => code === 0 ? done(out) : fail(new Error(`Wrangler ${argv.slice(0, 3).join(' ')} failed (${code}); retry from your own terminal. Private output withheld.`)));
    p.stdin.end(input);
  });
}
function save(path, data) {
  if (!existsSync(path)) writeFileSync(path, '', { mode: 0o600, flag: 'wx' });
  if (!lstatSync(path).isFile() || lstatSync(path).isSymbolicLink()) throw new Error('Refusing unsafe config or recovery file');
  // Restrict access before writing any secret, on Windows as well as Unix.
  if (process.platform === 'win32') {
    const identity = spawnSync('whoami.exe', ['/user', '/fo', 'csv', '/nh'], { encoding: 'utf8', windowsHide: true });
    const sid = identity.stdout?.match(/S-1-5-[0-9-]+/)?.[0];
    if (identity.status !== 0 || !sid) throw new Error('Could not identify the current Windows user');
    const acl = spawnSync('icacls.exe', [path, '/inheritance:r', '/grant:r', `*${sid}:F`], { stdio: 'ignore', windowsHide: true });
    if (acl.status !== 0) throw new Error('Could not protect config or recovery file');
  } else chmodSync(path, 0o600);
  writeFileSync(path, JSON.stringify(data, null, 2) + '\n');
}
function template() { return JSON.parse(readFileSync(resolve(root, 'wrangler.jsonc'), 'utf8')); }
async function question(label, secret = false) {
  if (!process.stdin.isTTY) throw new Error('Remote setup needs an interactive terminal; no secrets may be passed as command arguments');
  // Muted output avoids echoing secrets, including readline redraws.
  let muted = false;
  const output = new Writable({ write(chunk, encoding, cb) { if (!muted) process.stdout.write(chunk); cb(); } });
  const rl = createInterface({ input: process.stdin, output, terminal: true });
  try {
    if (secret) { process.stdout.write(label + ': '); muted = true; }
    const value = (await rl.question(secret ? '' : label + ': ')).trim();
    if (secret) process.stdout.write('\n');
    if (!value) throw new Error(`${label} is required`);
    return value;
  } finally { rl.close(); }
}
function origin(value) {
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.origin !== value) throw new Error('Use an HTTPS origin without a trailing slash, path, query or credentials');
  return value;
}
function validConfig(c) {
  origin(c.vars.BASE_URL);
  if (!/^[a-f0-9]{32}$/.test(c.account_id || '')) throw new Error('A Cloudflare account ID is required');
  if (!/^[a-f0-9-]{36}$/.test(c.d1_databases?.[0]?.database_id || '')) throw new Error('A real D1 database ID is required');
  if (c.d1_databases[0].database_id === '00000000-0000-0000-0000-000000000000') throw new Error('Local placeholder database cannot be deployed');
}
async function localCheck() {
  if (readdirSync(root).some(name => /^\.dev\.vars(?:\.|$)|^\.env(?:\.|$)/.test(name))) {
    throw new Error('Local synthetic proof needs a clean cloud directory without .dev.vars or .env files. Use a separate checkout.');
  }
  const listener = createServer();
  await new Promise(r => listener.listen(0, '127.0.0.1', r));
  const port = listener.address().port;
  await new Promise(r => listener.close(r));
  const c = template();
  c.vars = { BASE_URL: `http://127.0.0.1:${port}`, WORKOS_CLIENT_ID: '', WORKOS_API_KEY: '', SESSION_SECRET: 'synthetic-local-session', ENCRYPTION_KEY: 'synthetic-local-encryption' };
  save(configPath, c);
  await run(['d1', 'migrations', 'apply', 'DB', '--local']);
  await run(['d1', 'execute', 'DB', '--local', '--command', "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('users','native_accounts','vault_items') ORDER BY name"]);
  console.log('Local D1 migrations applied. No Cloudflare login or remote operation.');
  const p = spawn(process.execPath, [wrangler, 'dev', '--local', '--ip', '127.0.0.1', '--port', String(port), '--config', configPath], { cwd: root, env, stdio: 'ignore', windowsHide: true });
  let failure;
  p.on('error', err => { failure = err; });
  try {
    const base = c.vars.BASE_URL;
    let ready = false;
    for (let i = 0; i < 120; i++) {
      if (failure) throw failure;
      if (p.exitCode !== null) throw new Error('Local Wrangler exited before readiness');
      try { const r = await fetch(base + '/', { signal: AbortSignal.timeout(1000) }); if (r.status === 200) { ready = true; break; } } catch {}
      await new Promise(r => setTimeout(r, 500));
    }
    if (!ready) throw new Error('Local Worker did not start within 60 seconds');
    const unauth = await fetch(base + '/api/v1/whoami');
    if (unauth.status !== 401) throw new Error(`Agent auth expected 401, got ${unauth.status}`);
    const login = await fetch(base + '/login', { redirect: 'manual' });
    if (login.status !== 503) throw new Error(`Unconfigured login expected 503, got ${login.status}`);
    console.log('PASS local Worker: home=200, unauthenticated agent=401, unconfigured login=503.');
    console.log(`Local URL: ${base}`);
    console.log('Local proof uses synthetic settings. Real WorkOS and Google consent require your own apps.');
    if (!args.has('--check')) { console.log('Press Ctrl+C to stop.'); await new Promise(r => process.once('SIGINT', r)); }
  } finally {
    p.kill();
    if (p.exitCode === null) await new Promise(r => p.once('close', r));
  }
}
async function remote() {
  let c;
  if (existsSync(configPath)) c = JSON.parse(readFileSync(configPath, 'utf8'));
  else {
    if (args.has('--update')) throw new Error('Run initial selfhost setup first');
    c = template();
    c.name = await question('Worker name (lowercase letters, numbers and dashes)');
    if (!/^[a-z][a-z0-9-]{0,62}$/.test(c.name)) throw new Error('Invalid Worker name');
    c.account_id = await question('Your Cloudflare account ID');
    if (!/^[a-f0-9]{32}$/.test(c.account_id)) throw new Error('Invalid account ID');
    c.vars = { BASE_URL: origin(await question('Final HTTPS origin, e.g. https://ralx.YOUR-SUBDOMAIN.workers.dev')) };
    c.d1_databases = [];
    save(configPath, c);
  }
  if (!/^[a-f0-9]{32}$/.test(c.account_id || '')) throw new Error('A valid account ID is required');
  env.CLOUDFLARE_ACCOUNT_ID = c.account_id;
  const identity = await run(['whoami'], undefined, true);
  if (!identity.includes('You are logged in with')) throw new Error('Wrangler is not authenticated. Run npx wrangler login first.');
  console.log('Wrangler login checked. Config selects your account.');
  if (!c.d1_databases.length) {
    console.log('Creating D1 in the account you selected. Keep this config to resume after an interrupted setup.');
    if (c.creation_pending) throw new Error('Previous database creation was interrupted. Inspect your account and add its DB binding to this config before retrying.');
    c.creation_pending = true;
    save(configPath, c);
    const output = await run(['d1', 'create', c.name + '-db', '--update-config=false'], undefined, true);
    const id = /[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/i.exec(output)?.[0];
    if (!id) throw new Error('D1 creation returned unexpected output. Inspect your account before retrying to avoid a duplicate database.');
    delete c.creation_pending;
    c.d1_databases = [{ binding: 'DB', database_name: c.name + '-db', database_id: id, migrations_dir: 'migrations' }];
    save(configPath, c);
  }
  validConfig(c);
  if (!args.has('--update')) {
    let secrets = existsSync(secretsPath) ? JSON.parse(readFileSync(secretsPath, 'utf8')) : {};
    for (const key of ['WORKOS_CLIENT_ID', 'WORKOS_API_KEY', 'GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET']) {
      if (!secrets[key]) { secrets[key] = await question(key, true); save(secretsPath, secrets); }
    }
    // Stable across retries. Replacing this key makes existing vault data unreadable.
    for (const key of ['SESSION_SECRET', 'ENCRYPTION_KEY']) if (!secrets[key]) secrets[key] = randomBytes(32).toString('base64url');
    save(secretsPath, secrets);
    console.log('Private recovery file saved with restricted access. Back it up securely.');
    await run(['secret', 'bulk'], JSON.stringify(secrets), true);
    console.log('Required secrets uploaded without printing values.');
  }
  await run(['d1', 'migrations', 'apply', 'DB', '--remote']);
  await run(['deploy']);
  console.log(`RalX URL: ${c.vars.BASE_URL}\nralx setup --mode cloud --url ${c.vars.BASE_URL}`);
  console.log(`Configure WorkOS redirect ${c.vars.BASE_URL}/callback and Google redirect ${c.vars.BASE_URL}/oauth/google/callback before sign-in.`);
}
try { await (local ? localCheck() : remote()); }
catch (err) { console.error('Self-host setup: ' + err.message); process.exitCode = 1; }
