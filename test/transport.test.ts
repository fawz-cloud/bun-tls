// Guard test: does Bun hand socket data() a buffer it later reuses? transport.ts copies every
// chunk ("Bun reuses the buffer → copy"); if that is false we can drop the copy. A loopback
// server streams a position-dependent pattern; the client KEEPS each chunk without copying,
// snapshots its hash, and busy-waits on some callbacks so the kernel queue fills and Bun does
// back-to-back full-size reads (where reuse would show). After close, every kept chunk must
// still hash the same and still match the pattern. Run: bun test/transport.test.ts
import assert from 'node:assert';
import { createHash } from 'node:crypto';

const SIZE = 48 << 20; // 48 MiB
const pat = (i: number) => (i * 2654435761) & 0xff; // position-dependent byte
const hash = (b: Uint8Array) => createHash('sha1').update(b).digest('hex');

const kept: { buf: Uint8Array; sha: string; start: number }[] = [];
const buffers = new Set<ArrayBufferLike>();
let got = 0;
let cb = 0;
let maxSlack = 0;
const pumps = new WeakMap<object, () => void>();

await new Promise<void>((resolve, reject) => {
	const server = Bun.listen({
		hostname: '127.0.0.1',
		port: 0,
		socket: {
			open(s) {
				const CH = 1 << 20;
				const block = new Uint8Array(SIZE);
				for (let i = 0; i < SIZE; i++) block[i] = pat(i);
				let off = 0;
				const pump = () => {
					while (off < SIZE) {
						const n = s.write(block.subarray(off, Math.min(SIZE, off + CH)));
						if (n <= 0) return;
						off += n;
					}
					s.flush();
					s.end();
				};
				pumps.set(s, pump);
				pump();
			},
			drain(s) {
				pumps.get(s)?.();
			},
			error(_s, e) {
				reject(e);
			}
		}
	});
	Bun.connect({
		hostname: '127.0.0.1',
		port: server.port,
		socket: {
			binaryType: 'uint8array',
			data(_s, d: Uint8Array) {
				kept.push({ buf: d, sha: hash(d), start: got }); // keep WITHOUT copying
				buffers.add(d.buffer);
				maxSlack = Math.max(maxSlack, d.buffer.byteLength - d.length);
				got += d.length;
				if (cb++ % 4 === 0) {
					const until = performance.now() + 3; // stall so reads queue up
					while (performance.now() < until);
				}
			},
			close() {
				server.stop();
				resolve();
			},
			error(_s, e) {
				reject(e);
			}
		}
	});
});

assert.equal(got, SIZE, `received all ${SIZE} bytes`);
let reused = 0;
for (const k of kept) {
	if (hash(k.buf) !== k.sha) reused++;
}
// Spot-check content against the pattern too (independent of the hash).
for (const k of kept) {
	for (let i = 0; i < k.buf.length; i += 997) assert.equal(k.buf[i], pat(k.start + i), `byte ${k.start + i} matches pattern`);
}

console.log(`transport: ${kept.length} chunks, ${buffers.size} distinct backing buffers, max slack ${(maxSlack / 1024).toFixed(0)} KiB, reused=${reused}`);
assert.equal(reused, 0, 'Bun did NOT reuse any delivered buffer (if this fails, the transport copy is required)');
console.log('transport: OK (data() buffers are stable → the per-chunk copy can be dropped)');
