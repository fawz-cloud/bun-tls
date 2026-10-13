// timeoutMs bounds EVERY phase of a request — DNS/TCP, a proxy that never answers (HTTP
// CONNECT and SOCKS5), the TLS handshake, the wait for a free HTTP/2 stream slot, and the
// response — for request(), openConnection() and Session. Local servers only.
// Uses bench/{key,cert}.pem when present (gitignored) for the TLS cases; skips them otherwise.
// Run: bun test/timeouts.test.ts
import assert from 'node:assert';
import { existsSync, readFileSync } from 'node:fs';
import http2 from 'node:http2';
import tls from 'node:tls';
import { request, Session } from '../src/index';
import { openConnection } from '../src/http/client';

/** Resolve with the elapsed ms when `p` rejects with a timeout; fail if it resolves. */
async function rejectsWithin(p: Promise<unknown>, maxMs: number, what: string, re = /timed out/): Promise<number> {
	const t0 = Date.now();
	try {
		await p;
	} catch (e) {
		const ms = Date.now() - t0;
		assert.match((e as Error).message, re, `${what}: error message`);
		assert.ok(ms < maxMs, `${what}: rejected after ${ms} ms (limit ${maxMs})`);
		return ms;
	}
	assert.fail(`${what}: resolved instead of timing out`);
}

// A TCP peer that accepts and never says a word: a stuck proxy (HTTP CONNECT or SOCKS5), or a
// "TLS server" that never answers the ClientHello.
const silent = Bun.listen({ hostname: '127.0.0.1', port: 0, socket: { data() {} } });
const SILENT = `127.0.0.1:${silent.port}`;

{
	const ms = await rejectsWithin(openConnection({ host: 'example.com', port: 443, proxy: `http://${SILENT}`, timeoutMs: 300 }), 1500, 'HTTP CONNECT proxy that never answers');
	console.log(`  stuck CONNECT proxy → rejected in ${ms} ms`);
}
{
	const ms = await rejectsWithin(openConnection({ host: 'example.com', port: 443, proxy: `socks5://${SILENT}`, timeoutMs: 300 }), 1500, 'SOCKS5 proxy that never answers');
	console.log(`  stuck SOCKS5 proxy → rejected in ${ms} ms`);
}
{
	const ms = await rejectsWithin(request({ url: `https://${SILENT}/`, verify: false, timeoutMs: 300 }), 1500, 'server that never answers the ClientHello');
	console.log(`  silent TLS server → rejected in ${ms} ms`);
}
{
	// an AbortSignal cancels a dial that is stuck on the proxy, with the signal's own reason
	const ac = new AbortController();
	setTimeout(() => ac.abort(new Error('caller gave up')), 200);
	await rejectsWithin(openConnection({ host: 'example.com', port: 443, proxy: `http://${SILENT}`, signal: ac.signal }), 1500, 'abort during proxy negotiation', /caller gave up/);
}
silent.stop(true);

const dir = new URL('../bench', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');
if (!existsSync(`${dir}/cert.pem`) || !existsSync(`${dir}/key.pem`)) {
	console.log('timeouts: OK (TLS cases SKIPPED — no bench/cert.pem)');
	process.exit(0);
}
const key = readFileSync(`${dir}/key.pem`);
const cert = readFileSync(`${dir}/cert.pem`);

// TLS server that completes the handshake, then never answers the HTTP request.
const mute = tls.createServer({ key, cert }, () => {});
await new Promise<void>((r) => mute.listen(0, r)); // all interfaces: "localhost" may resolve to ::1
const MUTE = `https://localhost:${(mute.address() as { port: number }).port}/`;
{
	const ms = await rejectsWithin(request({ url: MUTE, verify: false, timeoutMs: 400 }), 1500, 'one-shot request, silent after the handshake');
	console.log(`  request() total budget → rejected in ${ms} ms`);
	const s = new Session({ verify: false, timeoutMs: 400 });
	await rejectsWithin(s.get(MUTE), 1500, 'Session h1, silent after the handshake');
	s.close();
}
mute.close();

// HTTP/2 server allowing ONE concurrent stream: /slow holds it for 3 s.
const h2 = http2.createSecureServer({ key, cert, settings: { maxConcurrentStreams: 1 } }, (req, res) => {
	if (req.url === '/slow') setTimeout(() => res.end('slow'), 3000);
	else res.end('fast');
});
await new Promise<void>((r) => h2.listen(0, r));
const H2 = `https://localhost:${(h2.address() as { port: number }).port}`;
{
	const s = new Session({ http2: true, verify: false });
	assert.equal((await s.get(`${H2}/fast`)).text(), 'fast', 'h2 warm-up');
	const slow = s.get(`${H2}/slow`, { timeoutMs: 6000 }); // occupies the only slot
	await Bun.sleep(100);
	const ms = await rejectsWithin(s.get(`${H2}/fast`, { timeoutMs: 400 }), 1500, 'h2 request queued behind MAX_CONCURRENT_STREAMS');
	console.log(`  queued h2 request → rejected in ${ms} ms (the slot was busy for 3 s)`);
	assert.equal((await slow).text(), 'slow', 'the long request still completes');
	assert.equal((await s.get(`${H2}/fast`, { timeoutMs: 2000 })).text(), 'fast', 'connection still usable after a queue timeout');
	s.close();
}
h2.close();

console.log('timeouts: OK');
