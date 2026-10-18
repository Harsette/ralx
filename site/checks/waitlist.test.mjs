import { test } from 'node:test';
import assert from 'node:assert/strict';
import { onRequest } from '../functions/api/waitlist.js';
const request = (body, extra = {}) => new Request('http://localhost:7431/api/waitlist', { method: 'POST', headers: { 'Content-Type': 'application/json', ...extra }, body: JSON.stringify(body) });
test('persists normalized email and timestamp, then rate limits', async () => {
  const values = new Map(); const WAITLIST = { get: async key => values.get(key), put: async (key, value) => values.set(key, value) };
  const r = await onRequest({ request: request({ email: '  Person@Example.com  ' }), env: { WAITLIST } });
  assert.equal(r.status, 200); const row = JSON.parse([...values].find(([key]) => key.startsWith('email:'))[1]);
  assert.equal(row.email, 'person@example.com'); assert.ok(Number.isFinite(Date.parse(row.timestamp)));
  const limited = await onRequest({ request: request({ email: 'other@example.com' }), env: { WAITLIST } });
  assert.equal(limited.status, 429); assert.equal(limited.headers.get('Retry-After'), '60');
});
test('refuses bad email and cross-origin; honeypot writes nothing', async () => {
  const env = { WAITLIST: { get: async () => assert.fail('unexpected read'), put: async () => assert.fail('unexpected write') } };
  assert.equal((await onRequest({ request: request({ email: 'bad' }), env })).status, 400);
  assert.equal((await onRequest({ request: request({ email: 'a@b.com' }, { Origin: 'https://elsewhere.test' }), env })).status, 403);
  assert.equal((await onRequest({ request: request({ email: 'a@b.com', website: 'spam' }), env })).status, 200);
});
test('storage failure does not pretend signup saved', async () => {
  assert.equal((await onRequest({ request: request({ email: 'a@b.com' }), env: {} })).status, 503);
  assert.equal((await onRequest({ request: request({ email: 'a@b.com' }), env: { WAITLIST: { get: async () => { throw Error('offline'); }, put() {} } } })).status, 503);
});
