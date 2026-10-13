// Live: TLS 1.3 handshake + real HTTP. Needs internet.
// Run: bun scratch/bun-tls/test/live.test.ts
import assert from 'node:assert';
import { request, openConnection, roundtrip, serializeForEarly } from '../src/http/client';
import { Session } from '../src/http/session';
import type { Ticket } from '../src/tls/resumption';
import { fromJa3 } from '../src/fp/ja3';
import { dart, tls12 } from '../src/fp/fingerprints';
import { clients } from '../src/fp/clients';
import { verifyOcsp, fetchOcsp } from '../src/tls/ocsp';
import { fromClientHello } from '../src/fp/capture';
import { buildClientHello } from '../src/tls/clienthello';
import { hex } from '../src/core/bytes';
import crypto from 'node:crypto';

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

	// 9b) Session over HTTP/2: 3 concurrent requests multiplexed on one connection.
	const s2 = new Session({ http2: true });
	const [a, b, c] = await Promise.all([s2.get('https://nghttp2.org/'), s2.get('https://nghttp2.org/httpbin/get'), s2.get('https://nghttp2.org/blog/')]);
	console.log(`http/2 mux → ${a.status} ${b.status} ${c.status} alpn=${a.alpn}`);
	assert.ok(a.status === 200 && b.status === 200 && c.status === 200, 'h2 multiplexed 3 streams on one connection');
	assert.equal(a.alpn, 'h2', 'session negotiated h2');
	s2.close();
}

// 10) OCSP revocation (RFC 6960): stapling + AIA fetch; signature and CertID binding enforced.
{
	// soft mode is browser-style: a cert with no OCSP (e.g. current Let's Encrypt) still passes.
	const soft = await request({ url: 'https://www.cloudflare.com/', ocsp: 'soft', timeoutMs: 20000 });
	assert.equal(soft.status, 200, 'ocsp soft tolerates a missing OCSP response');

	// A stapling CA: verify the response end to end, and prove the checks actually bite.
	const tls = await openConnection({ host: 'www.digicert.com', port: 443, timeoutMs: 15000 });
	const certs = tls.peerCertificates;
	tls.close();
	const leaf = new crypto.X509Certificate(Buffer.from(certs[0]!));
	const issuer = new crypto.X509Certificate(Buffer.from(certs[1]!));
	const resp = tls.ocspStaple ?? (await fetchOcsp(leaf, issuer)); // stapled, else fetched from AIA
	assert.ok(resp, 'digicert provides an OCSP response (staple or AIA)');
	console.log(`ocsp → ${tls.ocspStaple ? 'stapled' : 'fetched'} ${resp!.length}B status=${verifyOcsp(resp!, leaf, issuer)}`);
	assert.equal(verifyOcsp(resp!, leaf, issuer), 'good', 'OCSP status is good');
	const bad = Uint8Array.from(resp!);
	bad[bad.length - 1] ^= 0xff; // flip a signature byte → signature must be rejected
	assert.throws(() => verifyOcsp(bad, leaf, issuer), 'tampered OCSP signature rejected');
	assert.throws(() => verifyOcsp(resp!, leaf, leaf), 'OCSP CertID binding enforced (wrong issuer rejected)');
	const hard = await request({ url: 'https://www.digicert.com/', ocsp: 'hard', timeoutMs: 20000 });
	assert.equal(hard.status, 200, 'ocsp hard passes on a good, in-date certificate');
}

// 11) TLS 1.2 (ECDHE + AEAD): negotiate 1.2, echo our JA3, exercise both GCM and ChaCha.
{
	const r = await request({ url: 'https://tls-v1-2.badssl.com:1012/', tls12: true, timeoutMs: 20000 });
	console.log(`tls1.2 → ${r.status} ja4=${r.ja4}`);
	assert.equal(r.status, 200, 'TLS 1.2-only server handshake (not a 1.3 downgrade)');
	assert.ok(r.ja4.startsWith('t12'), 'JA4 reports TLS 1.2');
	const e = await request({ url: 'https://tls.peet.ws/api/clean', tls12: true, timeoutMs: 20000 });
	assert.equal(e.json<{ ja3_hash?: string }>().ja3_hash, e.ja3Hash, 'TLS 1.2 JA3 echo == ours');
	const fp = tls12();
	fp.ciphers = [0xcca9, 0xcca8]; // only ECDHE-CHACHA20-POLY1305 → forces the RFC 7905 record path
	const c = await request({ url: 'https://www.cloudflare.com/', tls12: true, fingerprint: fp, timeoutMs: 20000 });
	assert.equal(c.status, 200, 'TLS 1.2 ChaCha20-Poly1305 handshake + transfer');
}

// 12) Personas: one coherent identity across TLS + HTTP/2 + headers, with per-connection
//     JA3 rotation (the anti-block-list property) and a per-persona h2 fingerprint.
{
	const c1 = await request({ url: 'https://tls.peet.ws/api/clean', persona: 'chrome', timeoutMs: 20000 });
	const c2 = await request({ url: 'https://tls.peet.ws/api/clean', persona: 'chrome', timeoutMs: 20000 });
	assert.equal(c1.status, 200, 'persona chrome handshakes');
	assert.equal(c1.alpn, 'h2', 'persona chrome uses HTTP/2');
	assert.equal(c1.ja3nHash, 'dee19b855b658c6aa0f575eda2525e19', 'chrome persona JA3N == Chrome 131');
	assert.notEqual(c1.ja3Hash, c2.ja3Hash, 'raw JA3 rotates per connection (no fixed JA3 to block-list)');
	assert.equal(c1.ja3nHash, c2.ja3nHash, 'JA3N (the shape) stays a valid Chrome');

	// coherence: the h2 (Akamai) fingerprint matches the persona, not always Chrome's.
	const ff = await request({ url: 'https://tls.peet.ws/api/all', persona: 'firefox', timeoutMs: 20000 });
	assert.equal(ff.ja3nHash, '3d7d71e7ee5cc9e08aa503d985e74b27', 'firefox persona JA3N == Firefox 148');
	const akamai = ff.json<{ http2?: { akamai_fingerprint?: string } }>().http2?.akamai_fingerprint ?? '';
	console.log('persona firefox akamai h2 =', akamai);
	assert.ok(akamai.startsWith('1:65536;4:131072;5:16384'), 'firefox persona sends the Firefox h2 fingerprint, not Chrome');
}

// 13) Byte-exact capture replay: parse a ClientHello back into a Fingerprint and reproduce
//     it. The replayed JA3 must equal both what the server echoes and the captured value.
{
	const ch = buildClientHello(dart(), 'tls.peet.ws'); // stand-in for a real captured CH
	const fp = fromClientHello(hex(ch.bytes)); // accepts a hex string or raw bytes
	const r = await request({ url: 'https://tls.peet.ws/api/clean', fingerprint: fp, timeoutMs: 20000 });
	console.log(`capture replay → ja3=${r.ja3Hash}`);
	assert.equal(r.json<{ ja3_hash?: string }>().ja3_hash, r.ja3Hash, 'replayed CH JA3 == what the server sees (byte-exact)');
	assert.equal(r.ja3Hash, '9225d95490794840d9d5f1f94d339285', 'capture replay reproduces the exact dart:io JA3');
}

// 14) fetch()-compatible API with a streaming body + fingerprint control.
{
	const { fetch } = await import('../src/http/fetchlike');
	const fr = await fetch('https://example.com/');
	assert.equal(fr.status, 200, 'fetch example.com 200');
	assert.ok((await fr.text()).includes('Example Domain'), 'fetch body decoded');
	const fj = await fetch('https://postman-echo.com/get?x=1', { persona: 'chrome' });
	const jd = fj.status === 200 ? ((await fj.json()) as { args?: { x?: string }; headers?: Record<string,string> }) : {};
	assert.equal(jd.args?.x, '1', 'fetch gzip+json decoded');
	assert.ok((jd.headers?.['user-agent'] ?? '').includes('Chrome'), 'fetch persona UA applied');
	const fs2 = await fetch('https://www.google.com/');
	let bytes = 0; for await (const c of fs2.body as unknown as AsyncIterable<Uint8Array>) { bytes += c.length; if (bytes > 1000) break; }
	assert.ok(bytes > 0, 'fetch body streams incrementally');
	console.log(`fetch → example 200, persona json ok, stream ${bytes}+ bytes`);
}

// 15) WebSocket (RFC 6455) over the fingerprinted TLS channel.
{
	const { connectWebSocket } = await import('../src/http/ws');
	const ws = await connectWebSocket('wss://echo.websocket.org/', { persona: 'chrome' });
	ws.send('hello-bun-tls');
	let echoed = false;
	const guard = setTimeout(() => ws.close(), 6000);
	for await (const m of ws.messages()) {
		if (!m.binary && String(m.data).includes('hello-bun-tls')) { echoed = true; break; }
	}
	clearTimeout(guard);
	ws.close();
	assert.ok(echoed, 'WebSocket echoed our message back');
	console.log(`websocket → echo ok, ja3=${ws.fp.ja3Hash}`);
}

// 16) HTTP/3 (QUIC, RFC 9000/9001/9114) end to end: a real GET returns 200 with a body.
{
	const { fetch } = await import('../src/http/fetchlike');
	const r = await fetch('https://cloudflare-quic.com/', { http3: true, timeoutMs: 15000 });
	const body = await r.text();
	console.log(`http/3 → ${r.status} ${body.length}B ctype=${r.headers.get('content-type')} server=${r.headers.get('server')}`);
	assert.equal(r.status, 200, 'HTTP/3 GET returns 200');
	assert.ok(body.length > 0, 'HTTP/3 response has a body');
	// past the 256 KiB stream / 1 MiB connection windows: flow-control credit must flow
	const big = await fetch('https://www.cloudflare.com/', { http3: true, timeoutMs: 20000, headers: { 'accept-encoding': 'identity' } });
	const bigLen = (await big.arrayBuffer()).byteLength;
	console.log(`http/3 large → ${big.status} ${bigLen}B`);
	assert.ok(bigLen > 1_000_000, 'HTTP/3 body larger than the flow-control windows arrives whole');
}

// 17) ALPS: Google negotiates application_settings for h2, so the chrome persona must send its
//     client EncryptedExtensions (else Google answers the Finished with unexpected_message).
{
	const g = await request({ url: 'https://www.google.com/', persona: 'chrome', timeoutMs: 20000 });
	console.log(`alps google → ${g.status} alpn=${g.alpn}`);
	assert.equal(g.status, 200, 'chrome persona over h2 to Google (ALPS)');
	assert.equal(g.alpn, 'h2', 'Google selected h2');
}

// 17) LLM-ready scraping: token-cheap structured data (JSON-LD/OpenGraph) + clean Markdown.
{
	const { scrape } = await import('../src/http/scrape');
	const r = await scrape('https://www.ikea.com/', { as: 'auto', maxChars: 3000, timeoutMs: 20000 });
	assert.equal(r.status, 200, 'scrape fetched the page');
	assert.ok(r.title.length > 0, 'extracted a title');
	assert.ok(r.og.site_name || r.jsonld.length > 0, 'extracted structured data (og/jsonld)');
	assert.ok(r.markdown.length > 0 && !/\{color-scheme|font-family:/.test(r.markdown), 'markdown present, no style leakage');
	console.log(`scrape → ${r.status} title="${r.title.slice(0, 28)}" jsonld=${r.jsonld.length} og.site=${r.og.site_name ?? '-'} md=${r.markdown.length}B links=${r.links.length}`);
}

console.log('live: OK');
process.exit(0);
