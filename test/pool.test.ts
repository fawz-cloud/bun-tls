// SessionPool functional check over a local TLS server. Uses bench/{key,cert}.pem when present
// (gitignored), and skips cleanly otherwise so the offline suite still runs anywhere.
// Run: bun test/pool.test.ts
import assert from 'node:assert';
import { existsSync, readFileSync } from 'node:fs';
import { SessionPool } from '../src/index';

const dir = new URL('../bench', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');
if (!existsSync(`${dir}/cert.pem`) || !existsSync(`${dir}/key.pem`)) {
	console.log('pool: SKIP (no bench/cert.pem — generate it to run this test)');
	process.exit(0);
}

const SIZE = 2 << 20;
const big = new Uint8Array(SIZE).fill(88);
const server = Bun.serve({
	port: 0,
	tls: { key: readFileSync(`${dir}/key.pem`), cert: readFileSync(`${dir}/cert.pem`) },
	async fetch(req) {
		if (req.method === 'POST') return new Response(String((await req.arrayBuffer()).byteLength));
		if (new URL(req.url).pathname === '/big') return new Response(big);
		return new Response('ok-' + new URL(req.url).pathname);
	}
});
const base = `https://localhost:${server.port}`;

// 1) concurrent GETs across 2 workers, bodies correct, fingerprint echoed.
{
	const pool = new SessionPool({ workers: 2, persona: 'chrome', http2: false, verify: false });
	const rs = await Promise.all(Array.from({ length: 10 }, (_, i) => pool.get(`${base}/p${i}`)));
	rs.forEach((r, i) => {
		assert.equal(r.status, 200, `req ${i} status`);
		assert.equal(r.text(), `ok-/p${i}`, `req ${i} body`);
		assert.ok(r.ja4.startsWith('t13d'), `req ${i} ja4 present`);
	});
	// a large transferred body survives intact
	const b = await pool.get(`${base}/big`);
	assert.equal(b.body.length, SIZE, 'big body length');
	assert.ok(b.body.every((x) => x === 88), 'big body intact');
	// POST body round-trips
	const p = await pool.post(`${base}/echo`, { body: new Uint8Array(1234) });
	assert.equal(p.text(), '1234', 'POST echoed byte count');
	pool.close();
}

// 2) a Fingerprint object is rejected up front (can't cross a worker boundary).
assert.throws(() => new SessionPool({ workers: 1, fingerprint: {} } as never), /Fingerprint/, 'fingerprint object rejected');

// 3) close() rejects a pending request and later requests.
{
	const pool = new SessionPool({ workers: 2, persona: 'chrome', http2: false, verify: false });
	const fut = pool.get(`${base}/big`);
	pool.close();
	await assert.rejects(fut, /closed|crashed/, 'pending request rejected on close');
	await assert.rejects(pool.get(`${base}/x`), /closed/, 'request after close rejected');
}

server.stop(true);
console.log('pool: OK');
process.exit(0);
