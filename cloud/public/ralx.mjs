#!/usr/bin/env node
import { readFile, writeFile, mkdir, chmod, lstat, rename, unlink } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { createInterface } from 'node:readline';

const self = fileURLToPath(import.meta.url);
const root = dirname(self);
const configPath = join(root, 'connection.json');
let base = process.env.RALX_URL || '';
function checkOrigin() {
  if (!base || new URL(base).protocol !== 'https:' || new URL(base).origin !== base) throw new Error('Use the setup prompt from your own RalX URL.');
}
const fail = message => { throw new Error(message); };
async function privatePath(path, directory = false) {
  const stat = await lstat(path);
  if (stat.isSymbolicLink() || (directory ? !stat.isDirectory() : !stat.isFile())) fail('RalX setup found an unsafe file path.');
  if (process.platform === 'win32') {
    const identity = spawnSync('whoami.exe', ['/user', '/fo', 'csv', '/nh'], { encoding: 'utf8', windowsHide: true });
    const sid = identity.stdout?.match(/S-1-5-[0-9-]+/)?.[0];
    if (identity.status !== 0 || !sid) fail('Could not protect your RalX connection file.');
    const acl = spawnSync('icacls.exe', [path, '/inheritance:r', '/grant:r', `*${sid}:${directory ? '(OI)(CI)' : ''}F`], { windowsHide: true, stdio: 'ignore' });
    if (acl.status !== 0) fail('Could not protect your RalX connection file.');
  } else await chmod(path, directory ? 0o700 : 0o600);
}
async function request(path, data, key) {
  const response = await fetch(base + path, { method: data === undefined ? 'GET' : 'POST', redirect: 'error',
    headers: { 'Content-Type': 'application/json', ...(key ? { Authorization: 'Bearer ' + key } : {}) },
    body: data === undefined ? undefined : JSON.stringify(data), signal: AbortSignal.timeout(60000) });
  const text = await response.text();
  if (text.length > 8 * 1024 * 1024) fail('RalX response too large.');
  let value; try { value = JSON.parse(text); } catch { fail('RalX returned an unreadable response.'); }
  if (!response.ok) fail(value.error || 'RalX request failed.');
  return value;
}
async function connection() {
  await privatePath(root, true);
  await privatePath(configPath);
  const value = JSON.parse(await readFile(configPath, 'utf8'));
  if (!base) base = value.base;
  checkOrigin();
  if (value.base !== base || !/^ralx_[a-f0-9]{64}$/.test(value.key)) fail('Reconnect this agent from RalX.');
  return value;
}
function native(command, args) {
  return spawnSync(command, args, { windowsHide: true, encoding: 'utf8', shell: false });
}
async function enroll(code, client = 'agent', name = client) {
  if (!base) await connection();
  checkOrigin();
  if (!/^en_[a-f0-9]{64}$/.test(code || '')) fail('Use a fresh setup prompt from RalX.');
  await mkdir(root, { recursive: true, mode: 0o700 });
  await privatePath(root, true);
  // Refuse to replace a working agent key. Repeated setup reuses it.
  let existing;
  try { existing = await connection(); } catch (err) { if (err.code !== 'ENOENT') throw err; }
  if (existing) {
    await request('/api/v1/whoami', undefined, existing.key);
  } else {
    const value = await request('/api/enroll', { code, name: String(name).slice(0, 120), client: String(client).slice(0, 120) });
    if (!/^ralx_[a-f0-9]{64}$/.test(value.key)) fail('RalX enrollment failed.');
    const temporary = join(root, 'connection-' + crypto.randomUUID() + '.tmp');
    await writeFile(temporary, JSON.stringify({ base, key: value.key }), { mode: 0o600, flag: 'wx' });
    try { await privatePath(temporary); await rename(temporary, configPath); }
    finally { await unlink(temporary).catch(() => {}); }
  }
  const config = await connection();
  let registered = false;
  if (client === 'codex') {
    const result = native(process.platform === 'win32' ? 'codex.exe' : 'codex', ['mcp', 'add', 'ralx-cloud', '--', process.execPath, self, 'mcp']);
    registered = result.status === 0;
  } else if (client === 'claude') {
    const result = native(process.platform === 'win32' ? 'claude.exe' : 'claude', ['mcp', 'add', '--scope', 'user', 'ralx-cloud', '--', process.execPath, self, 'mcp']);
    registered = result.status === 0;
  }
  const identity = await request('/api/v1/whoami', undefined, config.key);
  console.log(JSON.stringify({ connected: true, client, mcp_registered: registered, accounts: identity.connected,
    ...(registered ? {} : { mcp_command: process.execPath, mcp_args: [self, 'mcp'], note: 'Use this stdio MCP configuration in clients with custom MCP settings. CLI access works immediately.' }) }));
  for (const account of identity.connected) {
    const tool = account.slug === 'gmail' ? 'GMAIL_FETCH_EMAILS' : account.slug === 'googledrive' ? 'GOOGLEDRIVE_LIST_FILES' : null;
    if (!tool) continue;
    try { console.log(JSON.stringify({ account: account.label, service: account.slug,
      result: await request('/api/v1/call', { tool, args: { max_results: 3 }, account: account.account }, config.key) })); }
    catch (err) { console.log(JSON.stringify({ account: account.label, service: account.slug, error: err.message })); }
  }
}
async function mcp() {
  const config = await connection();
  const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
  for await (const line of lines) {
    if (!line.trim()) continue;
    if (line.length > 65536) { console.error('RalX message too large.'); continue; }
    let message;
    try { message = JSON.parse(line); } catch { continue; }
    try {
      const response = await fetch(base + '/mcp', { method: 'POST', redirect: 'error',
        headers: { Authorization: 'Bearer ' + config.key, 'Content-Type': 'application/json' },
        body: JSON.stringify(message), signal: AbortSignal.timeout(60000) });
      if (message.id === undefined) continue;
      const value = await response.json();
      console.log(JSON.stringify(response.ok ? value : { jsonrpc: '2.0', id: message.id, error: { code: -32000, message: value.error || 'RalX request failed.' } }));
    } catch { if (message.id !== undefined) console.log(JSON.stringify({ jsonrpc: '2.0', id: message.id, error: { code: -32000, message: 'RalX is unavailable. Try again.' } })); }
  }
}
try {
  const [command, ...args] = process.argv.slice(2);
  if (command === 'enroll') await enroll(...args);
  else if (command === 'mcp') await mcp();
  else {
    const config = await connection();
    if (command === 'status') console.log(JSON.stringify(await request('/api/v1/whoami', undefined, config.key)));
    else if (command === 'tools') console.log(JSON.stringify(await request('/api/v1/tools', undefined, config.key)));
    else if (command === 'call') console.log(JSON.stringify(await request('/api/v1/call', { tool: args[0], args: JSON.parse(args[1] || '{}'), ...(args[2] ? { account: args[2] } : {}) }, config.key)));
    else fail('Use ralx status, tools, call <tool> <json> [account], or mcp.');
  }
} catch (err) { console.error(err.message); process.exitCode = 1; }
