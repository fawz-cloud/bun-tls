// bun-tls side of the benchmark. Start `bun bench/server.ts` first.
// The server cert is self-signed, so certificate verification is OFF for both clients.
// Every figure is a median over N runs after a warmup.
import { request, Session } from '../src';

const B = 'https://localhost:48443';
const median = (a: number[]) => a.sort((x, y) => x - y)[Math.floor(a.length / 2)]!;

async function timed(fn: () => Promise<unknown>, n: number, warmup: number): Promise<number> {
	const t: number[] = [];
	for (let i = 0; i < n + warmup; i++) {
		const a = performance.now();
		await fn();
		if (i >= warmup) t.push(performance.now() - a);
	}
	return median(t);
}

// 1) Latency, new connection per request (TCP + TLS handshake every time).
const fresh = await timed(() => request({ url: `${B}/`, verify: false }), 200, 10);

// 2) Latency, one reused connection (Session keep-alive).
const s = new Session({ verify: false });
const reuse = await timed(() => s.get(`${B}/`), 200, 10);
s.close();

// 3) Throughput: 1000 requests at concurrency C through one Session (pool grows to C).
async function throughput(C: number): Promise<number> {
	const sess = new Session({ verify: false });
	let next = 0;
	const t0 = performance.now();
	await Promise.all(
		Array.from({ length: C }, async () => {
			while (next < 1000) {
				next++;
				await sess.get(`${B}/`);
			}
		})
	);
	sess.close();
	return 1000 / ((performance.now() - t0) / 1000);
}

// 4) Upload: POST n bytes over one reused connection.
async function upload(bytes: number, n: number): Promise<number> {
	const body = new Uint8Array(bytes).fill(65);
	const sess = new Session({ verify: false });
	const ms = await timed(() => sess.post(`${B}/echo`, { body }), n, 3);
	sess.close();
	return bytes / 1e6 / (ms / 1000);
}

await throughput(10); // warm the JIT
console.log(`latency  fresh connection   ${fresh.toFixed(2)} ms`);
console.log(`latency  reused connection  ${reuse.toFixed(3)} ms`);
for (const C of [1, 10, 50]) console.log(`throughput C=${String(C).padEnd(2)}            ${(await throughput(C)).toFixed(0)} req/s`);
console.log(`upload   1 MB               ${(await upload(1 << 20, 40)).toFixed(0)} MB/s`);
console.log(`upload   10 MB              ${(await upload(10 << 20, 15)).toFixed(0)} MB/s`);
