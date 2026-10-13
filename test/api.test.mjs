import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import vm from 'node:vm';
import { buildRiskPayload, handleApi } from '../netlify/lib/api.mts';

function request(path, options = {}) {
  return new Request(`https://scanner.example${path}`, {
    ...options,
    headers: { Origin: 'https://scanner.example', 'Content-Type': 'application/json', ...options.headers },
  });
}

async function member() {
  return { name: 'Test Member', email: 'member@example.com' };
}

test('public health check does not load an account', async () => {
  const response = await handleApi(request('/health'), async () => { throw new Error('Must not authenticate'); });
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { status: 'ok' });
});

test('all protected endpoints reject unauthenticated visitors', async () => {
  for (const path of ['/api/me', '/api/risk', '/api/report']) {
    const response = await handleApi(request(path, { method: path === '/api/me' ? 'GET' : 'POST' }), async () => null);
    assert.equal(response.status, 401);
    assert.equal(response.headers.get('Cache-Control'), 'no-store');
  }
});

test('account response does not expose session details', async () => {
  const response = await handleApi(request('/api/me'), member);
  assert.deepEqual(await response.json(), await member());
});

test('risk profiles preserve the Python simulation scores', async () => {
  for (const [wifiType, score] of [['open', 85], ['weak', 50], ['strong', 15]]) {
    const response = await handleApi(request('/api/risk', { method: 'POST', body: JSON.stringify({ wifiType }) }), member);
    assert.equal(response.status, 200);
    assert.equal((await response.json()).risk, score);
  }
  assert.equal(buildRiskPayload('constructor'), null);
});

test('report is a private downloadable educational text file', async () => {
  const response = await handleApi(request('/api/report', { method: 'POST', body: '{"wifiType":"strong"}' }), member);
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('Content-Disposition'), 'attachment; filename="WiFi_Risk_Report.txt"');
  assert.equal(response.headers.get('Cache-Control'), 'no-store');
  const report = await response.text();
  assert.match(report, /15%/);
  assert.match(report, /not a real network scan/);
});

test('cross-origin and missing-origin posts are blocked', async () => {
  for (const origin of ['https://attacker.example', 'null', '']) {
    const response = await handleApi(request('/api/risk', { method: 'POST', headers: { Origin: origin } }), member);
    assert.equal(response.status, 403);
  }
});

test('unexpected methods and unknown API routes are rejected', async () => {
  const response = await handleApi(request('/api/me', { method: 'POST' }), member);
  assert.equal(response.status, 405);
  assert.equal(response.headers.get('Allow'), 'GET');
  assert.equal((await handleApi(request('/api/unknown'), member)).status, 404);
});

test('invalid input returns structured errors', async () => {
  for (const body of ['{', 'null', '[]', '{}', '{"wifiType":1}', '{"wifiType":"invalid"}']) {
    const response = await handleApi(request('/api/risk', { method: 'POST', body }), member);
    assert.equal(response.status, 400);
    assert.equal((await response.json()).success, false);
  }
});

test('non-JSON and oversized payloads are rejected', async () => {
  const plain = request('/api/risk', { method: 'POST', headers: { 'Content-Type': 'text/plain' }, body: '{}' });
  assert.equal((await handleApi(plain, member)).status, 415);
  const large = request('/api/risk', { method: 'POST', body: JSON.stringify({ wifiType: 'open', extra: 'a'.repeat(16384) }) });
  assert.equal((await handleApi(large, member)).status, 413);
});

test('browser processes email callbacks before checking the session', async () => {
  const source = (await readFile('src/auth.js', 'utf8')).replace(/^import .*;\n/, '');
  const calls = [];
  const context = {
    window: {}, document: { getElementById: () => null },
    login() {}, logout() {}, signup() {},
    async handleAuthCallback() { calls.push('callback'); },
    async getUser() { calls.push('session'); return member(); },
  };
  vm.runInNewContext(source, context);
  const session = await context.window.secureNetAuth.ready;
  assert.deepEqual(calls, ['callback', 'session']);
  assert.equal(session.user.name, 'Test Member');
});

test('invalid email callbacks show an actionable message', async () => {
  const source = (await readFile('src/auth.js', 'utf8')).replace(/^import .*;\n/, '');
  const message = {};
  const context = {
    window: {}, document: { getElementById: () => message },
    login() {}, logout() {}, signup() {},
    async handleAuthCallback() { throw new Error('Invalid callback'); },
    async getUser() { throw new Error('Must not load session'); },
  };
  vm.runInNewContext(source, context);
  assert.equal((await context.window.secureNetAuth.ready).error, true);
  assert.match(message.textContent, /confirmation link could not be verified/);
});

test('every page loads the auth client and inline scripts parse', async () => {
  for (const page of ['index.html', 'login.html', 'register.html']) {
    const html = await readFile(page, 'utf8');
    assert.match(html, /<script src="\/assets\/auth.js"><\/script>/);
    assert.doesNotMatch(html, /Start the server first|fetch\("\/api\/(login|register|logout)"/);
    for (const script of html.matchAll(/<script>([\s\S]*?)<\/script>/g)) new vm.Script(script[1]);
  }
});
