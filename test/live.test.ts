// Live: TLS 1.3 handshake + real HTTP. Needs internet.
// Run: bun scratch/bun-tls/test/live.test.ts
import assert from 'node:assert';
import { request, openConnection, roundtrip, serializeForEarly } from '../src/http/client';
import { Session } from '../src/http/session';
import type { Ticket } from '../src/tls/resumption';
import { fromJa3 } from '../src/fp/ja3';
import { dart } from '../src/fp/fingerprints';
import { clients } from '../src/fp/clients';

// 1) example.com → 200 + body, cert verified (default)
const r = await request({ url: 'https://example.com/', timeoutMs: 15000 });
console.log(`example.com → ${r.status} ${r.statusText}, ${r.body.length}B, alpn=${r.alpn}`);
assert.equal(r.status, 200, 'example.com 200');
assert.ok(r.text().includes('Example Domain'), 'example domain body');

// 2) JA3 + JA4 echo: tls.peet.ws must see exactly what we computed
const e = await request({ url: 'https://tls.peet.ws/api/clean', timeoutMs: 15000 });
assert.equal(e.status, 200, 'peet 200');
const seen = e.json<{ ja3_hash?: string; ja4?: string }>();
console.log('peet ja3_hash =', seen.ja3_hash, '| ja4 =', seen.ja4);
console.log('ours ja3_hash =', e.ja3Hash, '| ja4 =', e.ja4);
assert.equal(seen.ja3_hash, e.ja3Hash, 'JA3 the server sees == what we sent');
// JA4 _b (cipher hash) and _c (ext+sigalg hash) must match peet exactly; the _a
// prefix differs only in peet's non-standard cipher-count zero-pad ("3" vs spec "03").
const [, ourB, ourC] = e.ja4.split('_');
const [, peetB, peetC] = (seen.ja4 ?? '').split('_');
assert.equal(ourB, peetB, 'JA4 cipher hash matches peet');
assert.equal(ourC, peetC, 'JA4 ext+sigalg hash matches peet');

// 3) POST + gzip decode (postman-echo)
const p = await request({
	url: 'https://postman-echo.com/post',
	method: 'POST',
	headers: { 'Content-Type': 'application/json' },
	body: JSON.stringify({ hi: 'bun-tls', n: 7 }),
	timeoutMs: 20000
});
assert.equal(p.status, 200, 'post 200');
const pj = p.json<{ data: { hi: string; n: number } }>();
assert.equal(pj.data.hi, 'bun-tls');
assert.equal(pj.data.n, 7);
console.log('post → 200, echo ok');

// 4) fromJa3: impersonate from a JA3 string (round-trips through the echo)
const ja3 = '771,4865-4866-4867,0-10-11-13-43-45-51,29-23-24,0';
const j = await request({ url: 'https://tls.peet.ws/api/clean', fingerprint: fromJa3(ja3), timeoutMs: 15000 });
assert.equal(j.status, 200, 'fromJa3 200');
console.log('fromJa3 → sent ja3Hash', j.ja3Hash, '(server saw', j.json<{ ja3_hash?: string }>().ja3_hash + ')');
assert.equal(j.json<{ ja3_hash?: string }>().ja3_hash, j.ja3Hash, 'fromJa3 JA3 matches echo');

// 5) Session: cookies persist + redirect followed
const s = new Session();
await s.get('https://postman-echo.com/cookies/set?demo=bun', { timeoutMs: 20000 }); // 302 → /cookies
const c = await s.get('https://postman-echo.com/cookies', { timeoutMs: 20000 });
console.log('session cookies →', c.text().replace(/\s+/g, ' ').slice(0, 80));
assert.equal(c.status, 200, 'session 200');
assert.ok(c.text().includes('"demo": "bun"') || c.text().includes('"demo":"bun"'), 'cookie stored + resent');

// 6) dart preset reproduces dart:io's fingerprint exactly (captured 2026-10-12)
const d = await request({ url: 'https://tls.peet.ws/api/all', fingerprint: dart(), timeoutMs: 20000 });
const dt = d.json<{ tls: { ja3_hash: string; ja4: string } }>().tls;
console.log('dart preset: ja3Hash', dt.ja3_hash, '| ja4', dt.ja4);
assert.equal(dt.ja3_hash, '9225d95490794840d9d5f1f94d339285', 'dart JA3 hash matches dart:io');
const [, db, dc] = dt.ja4.split('_');
assert.equal(db, '5b57614c22b0', 'dart JA4_b matches dart:io');
assert.equal(dc, '78e6aca7449b', 'dart JA4_c matches dart:io');

// 7) client presets: each handshakes and the echo sees exactly our JA3.
//    chrome131 permutes its extensions, so the RAW JA3 varies per connection — we
//    assert on JA3N (extensions sorted), which is stable and matches utls
//    HelloChrome_131's published value. firefox148 has a fixed ext order (no permute).
const ja3nSet = new Set<string>();
const ja3nBy: Record<string, string> = {};
for (const [name, fp] of Object.entries(clients)) {
	const cr = await request({ url: 'https://tls.peet.ws/api/clean', fingerprint: fp(), timeoutMs: 20000 });
	assert.equal(cr.status, 200, `${name} handshake`);
	assert.equal(cr.json<{ ja3_hash?: string }>().ja3_hash, cr.ja3Hash, `${name} echo == ours`);
	ja3nSet.add(cr.ja3nHash);
	ja3nBy[name] = cr.ja3nHash;
	console.log(`client ${name.padEnd(8)} ja3n=${cr.ja3nHash}`);
}
assert.equal(ja3nBy.chrome, 'dee19b855b658c6aa0f575eda2525e19', 'chrome JA3N == utls HelloChrome_131');
assert.equal(ja3nBy.edge, ja3nBy.chrome, 'edge == chrome131 (both Chromium)');
assert.equal(ja3nBy.firefox, '3d7d71e7ee5cc9e08aa503d985e74b27', 'firefox JA3N == utls HelloFirefox_148');
assert.equal(ja3nBy.dart, '47dcc243bfad0cd80a0ec4c402647c28', 'dart JA3N stable');
assert.ok(ja3nSet.size >= 5, 'client fingerprints distinct (edge==chrome collapses 6→5)');

// 8) TLS 1.3 session resumption (+ 0-RTT when the server allows it). cloudflare.com
//    issues tickets and accepts PSK resumption on a fresh connection.
{
	const host = 'www.cloudflare.com';
	const rt = { method: 'GET', host, path: '/', headers: {}, keepAlive: true };
	let ticket: Ticket | null = null;
	const t1 = await openConnection({ host, port: 443, timeoutMs: 15000, onTicket: (t) => { if (!ticket) ticket = t; } });
	await roundtrip(t1, rt);
	t1.close();
	assert.ok(ticket, 'cloudflare issued a session ticket');
	const tk: Ticket = ticket!;
	const t2 = await openConnection({ host, port: 443, timeoutMs: 15000, resume: { ticket: tk, earlyData: tk.maxEarlyData > 0 }, earlyData: serializeForEarly(rt) });
	const r2 = await roundtrip(t2, rt, t2.earlyAccepted);
	console.log(`resumption → resumed=${t2.resumed} earlyAccepted=${t2.earlyAccepted} status=${r2.status} (ticket maxEarlyData=${tk.maxEarlyData})`);
	assert.ok(t2.resumed, 'second connection resumed via pre_shared_key');
	assert.equal(r2.status, 200, 'resumed request got 200');
	t2.close();
}

// 9) HTTP/2: negotiate ALPN h2 and complete a GET (HPACK decode + flow control).
//    modern() advertises only ECDHE groups we implement, so no MLKEM HelloRetryRequest.
{
	const r2 = await request({ url: 'https://nghttp2.org/', http2: true, timeoutMs: 20000 });
	console.log(`http/2 → alpn=${r2.alpn} status=${r2.status} bodyLen=${r2.body.length}`);
	assert.equal(r2.alpn, 'h2', 'negotiated HTTP/2');
	assert.equal(r2.status, 200, 'h2 GET got 200');
	assert.ok(r2.body.length > 0, 'h2 response has a body');
}

console.log('live: OK');
process.exit(0);
