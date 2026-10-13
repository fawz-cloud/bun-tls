// fetch() contract over local raw HTTPS servers: AbortSignal (already aborted, during the
// dial, during the body), timeoutMs as one total budget, redirects (follow by default, manual,
// error, 303/301→GET, 307 keeps the body, credentials dropped across origins, loop limit),
// interim 1xx responses, and truncated bodies surfacing as errors. Uses bench/{key,cert}.pem
// (gitignored) and skips cleanly without them. Run: bun test/fetch.test.ts
import assert from 'node:assert';
import { existsSync, readFileSync } from 'node:fs';
import tls from 'node:tls';
import zlib from 'node:zlib';
import { fetch } from '../src/index';

const dir = new URL('../bench', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');
if (!existsSync(`${dir}/cert.pem`) || !existsSync(`${dir}/key.pem`)) {
	console.log('fetch: SKIP (no bench/cert.pem — generate it to run this test)');
	process.exit(0);
}
const key = readFileSync(`${dir}/key.pem`);
const cert = readFileSync(`${dir}/cert.pem`);

interface Req {
	method: string;
	path: string;
	headers: Record<string, string>;
	body: Buffer;
}
type Handler = (req: Req, sock: tls.TLSSocket) => void;

/** A raw HTTPS/1.1 server: one request per connection, the handler writes bytes itself. */
async function rawServer(handler: Handler): Promise<{ port: number; conns: () => number; close: () => void }> {
	let conns = 0;
	const srv = tls.createServer({ key, cert }, (sock) => {
		conns++;
		let buf = Buffer.alloc(0);
		sock.on('error', () => {});
		sock.on('data', (d: Buffer) => {
			buf = Buffer.concat([buf, d]);
			const end = buf.indexOf('\r\n\r\n');
			if (end < 0) return;
			const [line, ...lines] = buf.subarray(0, end).toString('latin1').split('\r\n');
			const headers: Record<string, string> = {};
			for (const l of lines) {
				const i = l.indexOf(':');
				headers[l.slice(0, i).trim().toLowerCase()] = l.slice(i + 1).trim();
			}
			const len = Number(headers['content-length'] ?? 0);
			if (buf.length < end + 4 + len) return;
			const [method, path] = line!.split(' ');
			sock.removeAllListeners('data');
			handler({ method: method!, path: path!, headers, body: buf.subarray(end + 4, end + 4 + len) }, sock);
		});
	});
	await new Promise<void>((r) => srv.listen(0, r));
	return { port: (srv.address() as { port: number }).port, conns: () => conns, close: () => srv.close() };
}

const send = (sock: tls.TLSSocket, status: string, headers: Record<string, string>, body: string | Buffer = '') => {
	const b = typeof body === 'string' ? Buffer.from(body) : body;
	const h = Object.entries({ 'Content-Length': String(b.length), Connection: 'close', ...headers })
		.map(([k, v]) => `${k}: ${v}\r\n`)
		.join('');
	sock.end(Buffer.concat([Buffer.from(`HTTP/1.1 ${status}\r\n${h}\r\n`), b]));
};

// Origin B echoes what it received (for the cross-origin credential check).
const B = await rawServer((req, sock) => send(sock, '200 OK', { 'Content-Type': 'application/json' }, JSON.stringify({ method: req.method, headers: req.headers, body: req.body.toString() })));

const A = await rawServer((req, sock) => {
	const p = req.path;
	if (p === '/final') return send(sock, '200 OK', {}, 'final');
	if (p === '/r301') return send(sock, '301 Moved Permanently', { Location: '/final' });
	if (p.startsWith('/loop')) return send(sock, '302 Found', { Location: `/loop${Number(p.slice(5) || 0) + 1}` });
	if (p === '/r303') return send(sock, '303 See Other', { Location: '/echo' });
	if (p === '/r307') return send(sock, '307 Temporary Redirect', { Location: '/echo' });
	if (p === '/echo') return send(sock, '200 OK', {}, JSON.stringify({ method: req.method, headers: req.headers, body: req.body.toString() }));
	if (p === '/same') return send(sock, '302 Found', { Location: '/echo' });
	if (p === '/cross') return send(sock, '302 Found', { Location: `https://localhost:${B.port}/echo` });
	if (p === '/early') {
		sock.write('HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\n');
		return send(sock, '200 OK', {}, 'after-hints');
	}
	if (p === '/gzip') return send(sock, '200 OK', { 'Content-Encoding': 'gzip' }, zlib.gzipSync('compressed body'));
	if (p === '/short-cl') return void sock.end('HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\nonly ten b'); // 10 of 100
	if (p === '/short-chunked') return void sock.end('HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n'); // no 0-chunk
	if (p === '/stall-body') return void sock.write('HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\npartial'); // then nothing
	if (p === '/stall-head') return; // never answers
	send(sock, '404 Not Found', {}, 'nope');
});
const a = (p: string) => `https://localhost:${A.port}${p}`;
const o = { verify: false } as const;

// ── AbortSignal ──
{
	const before = A.conns();
	const ac = new AbortController();
	ac.abort();
	await assert.rejects(fetch(a('/final'), { ...o, signal: ac.signal }), (e: Error) => e.name === 'AbortError', 'already-aborted signal rejects with AbortError');
	await Bun.sleep(50);
	assert.equal(A.conns(), before, 'already-aborted: no connection is even opened');

	const custom = new AbortController();
	custom.abort(new Error('my reason'));
	await assert.rejects(fetch(a('/final'), { ...o, signal: custom.signal }), /my reason/, 'rejects with the signal reason');

	const ac2 = new AbortController();
	setTimeout(() => ac2.abort(), 150);
	const t0 = Date.now();
	await assert.rejects(fetch(a('/stall-head'), { ...o, signal: ac2.signal }), (e: Error) => e.name === 'AbortError', 'abort while waiting for the head');
	assert.ok(Date.now() - t0 < 1500, 'abort while waiting for the head is prompt');

	const ac3 = new AbortController();
	const res = await fetch(a('/stall-body'), { ...o, signal: ac3.signal });
	assert.equal(res.status, 200);
	setTimeout(() => ac3.abort(), 150);
	await assert.rejects(res.text(), (e: Error) => e.name === 'AbortError', 'abort during the body errors the body');
}

// ── timeoutMs: one total budget (head AND body) ──
{
	const t0 = Date.now();
	await assert.rejects(fetch(a('/stall-head'), { ...o, timeoutMs: 300 }), (e: Error) => e.name === 'TimeoutError', 'timeout waiting for the head');
	assert.ok(Date.now() - t0 < 1500, 'head timeout is prompt');
	const res = await fetch(a('/stall-body'), { ...o, timeoutMs: 300 });
	const t1 = Date.now();
	await assert.rejects(res.text(), (e: Error) => e.name === 'TimeoutError', 'timeout while the body stalls');
	assert.ok(Date.now() - t1 < 1500, 'body timeout is prompt');
	// a completed response leaves no live timer behind
	assert.equal(await (await fetch(a('/final'), { ...o, timeoutMs: 200 })).text(), 'final');
	await Bun.sleep(300);
}

// ── redirects ──
{
	const r = await fetch(a('/r301'), o);
	assert.equal(r.status, 200, 'redirect followed by default');
	assert.equal(await r.text(), 'final');
	assert.equal(r.redirected, true, 'redirected flag');
	assert.equal(r.url, a('/final'), 'final url');

	const m = await fetch(a('/r301'), { ...o, redirect: 'manual' });
	assert.equal(m.status, 301, 'manual returns the 3xx');
	assert.equal(m.headers.get('location'), '/final');
	await assert.rejects(fetch(a('/r301'), { ...o, redirect: 'error' }), TypeError, 'redirect: error rejects');
	await assert.rejects(fetch(a('/loop0'), o), /too many redirects/, 'redirect loop stops at 20');

	const g = await (await fetch(a('/r303'), { ...o, method: 'POST', body: 'payload', headers: { 'Content-Type': 'text/plain' } })).json() as Req;
	assert.equal(g.method, 'GET', '303 turns POST into GET');
	assert.equal(g.body, '', '303 drops the body');
	assert.equal(g.headers['content-type'], undefined, '303 drops content headers');
	const p = await (await fetch(a('/r307'), { ...o, method: 'POST', body: 'payload' })).json() as Req;
	assert.equal(p.method, 'POST', '307 keeps the method');
	assert.equal(p.body, 'payload', '307 keeps the body');

	const same = await (await fetch(a('/same'), { ...o, headers: { Authorization: 'Bearer s3cret' } })).json() as Req;
	assert.equal(same.headers['authorization'], 'Bearer s3cret', 'same-origin redirect keeps Authorization');
	const cross = await (await fetch(a('/cross'), { ...o, headers: { Authorization: 'Bearer s3cret', Cookie: 'sid=1' } })).json() as Req;
	assert.equal(cross.headers['authorization'], undefined, 'cross-origin redirect drops Authorization');
	assert.equal(cross.headers['cookie'], undefined, 'cross-origin redirect drops Cookie');
}

// ── framing ──
{
	const e = await fetch(a('/early'), o);
	assert.equal(e.status, 200, 'interim 103 skipped');
	assert.equal(await e.text(), 'after-hints');
	assert.equal(await (await fetch(a('/gzip'), o)).text(), 'compressed body', 'gzip body decoded');
	await assert.rejects((await fetch(a('/short-cl'), o)).text(), /truncated \(10 of 100 bytes\)/, 'short Content-Length body is an error');
	await assert.rejects((await fetch(a('/short-chunked'), o)).text(), /truncated/, 'chunked body without its last chunk is an error');
}

A.close();
B.close();
console.log('fetch: OK');
