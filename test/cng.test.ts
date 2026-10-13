// Windows CNG AEADs (src/core/cng.ts) against their oracles: node:crypto AES-GCM and the pure-TS
// ChaCha20-Poly1305 — every record size up to 16384, AAD lengths around the 64-byte scratch, the
// in-place paths, tamper rejection, bounds checks, key destruction, and no native leak over
// many keys. Run: bun test/cng.test.ts (skips off Windows or with BUN_TLS_CRYPTO=node).
import assert from 'node:assert';
import nodeCrypto from 'node:crypto';
import { cngAesGcm, cngChaCha20Poly1305 } from '../src/core/cng';
import { pureSeal, pureOpen } from '../src/core/chacha';
import type { Aead } from '../src/core/crypto';

const gcm = cngAesGcm();
const chacha = cngChaCha20Poly1305();
if (!gcm) {
	console.log('cng: SKIP (no Windows CNG here, or BUN_TLS_CRYPTO=node)');
	process.exit(0);
}

const rnd = (n: number) => new Uint8Array(nodeCrypto.randomBytes(n));
const nodeGcmSeal = (key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, pt: Uint8Array) => {
	const c = nodeCrypto.createCipheriv(key.length === 16 ? 'aes-128-gcm' : 'aes-256-gcm', key, nonce, { authTagLength: 16 });
	c.setAAD(aad);
	return new Uint8Array(Buffer.concat([c.update(pt), c.final(), c.getAuthTag()]));
};

const SIZES = [0, 1, 2, 15, 16, 17, 31, 32, 33, 63, 64, 65, 255, 256, 1000, 4095, 4096, 16383, 16384];
const AADS = [0, 1, 5, 13, 63, 64, 65, 200]; // ≤64 → copied into the scratch, longer → pointed at
let checks = 0;

function exercise(name: string, mk: (k: Uint8Array) => Aead, keyLen: number, oracleSeal: (key: Uint8Array, n: Uint8Array, a: Uint8Array, p: Uint8Array) => Uint8Array) {
	const key = rnd(keyLen);
	const a = mk(key);
	for (const n of SIZES)
		for (const al of AADS) {
			const nonce = rnd(12);
			const aad = rnd(al);
			const pt = rnd(n);
			const want = oracleSeal(key, nonce, aad, pt);
			// seal (allocating) == oracle; open (copying) leaves its input untouched
			assert.deepEqual(a.seal(nonce, aad, pt), want, `${name} seal n=${n} aad=${al}`);
			const keep = want.slice();
			assert.deepEqual(a.open(nonce, aad, want), pt, `${name} open n=${n} aad=${al}`);
			assert.deepEqual(want, keep, `${name} open must not touch its input`);
			// sealInPlace at an offset inside a bigger buffer: bytes around the record untouched
			const buf = rnd(n + 16 + 40);
			const before = buf.slice();
			buf.set(pt, 20);
			a.sealInPlace!(nonce, aad, buf, 20, n);
			assert.deepEqual(buf.subarray(20, 20 + n + 16), want, `${name} sealInPlace n=${n} aad=${al}`);
			assert.deepEqual(buf.subarray(0, 20), before.subarray(0, 20), `${name} sealInPlace prefix intact`);
			assert.deepEqual(buf.subarray(20 + n + 16), before.subarray(20 + n + 16), `${name} sealInPlace suffix intact`);
			// openInPlace on a view → plaintext view over the same memory
			const view = buf.subarray(20, 20 + n + 16);
			const got = a.openInPlace!(nonce, aad, view);
			assert.deepEqual(got, pt, `${name} openInPlace n=${n} aad=${al}`);
			assert.equal(got.buffer, buf.buffer, `${name} openInPlace returns a view, not a copy`);
			// tamper: tag, ciphertext, AAD, nonce — each must throw
			const flip = (u: Uint8Array, i: number) => {
				const c = u.slice();
				c[i]! ^= 0x01;
				return c;
			};
			assert.throws(() => a.open(nonce, aad, flip(want, want.length - 1)), `${name} tag tamper n=${n}`);
			if (n) assert.throws(() => a.open(nonce, aad, flip(want, 0)), `${name} ct tamper n=${n}`);
			if (al) assert.throws(() => a.open(nonce, flip(aad, 0), want), `${name} aad tamper n=${n}`);
			assert.throws(() => a.open(flip(nonce, 11), aad, want), `${name} nonce tamper n=${n}`);
			checks += 8;
		}
	// bounds: nothing reaches CNG with lengths that overrun the buffer
	assert.throws(() => a.sealInPlace!(rnd(12), rnd(5), new Uint8Array(20), 5, 0), RangeError, `${name} tag would overrun`);
	assert.throws(() => a.sealInPlace!(rnd(12), rnd(5), new Uint8Array(40), -1, 4), RangeError, `${name} negative offset`);
	assert.throws(() => a.sealInPlace!(rnd(12), rnd(5), new Uint8Array(40), 0.5, 4), RangeError, `${name} fractional offset`);
	assert.throws(() => a.openInPlace!(rnd(12), rnd(5), new Uint8Array(15)), `${name} ct shorter than tag`);
	assert.throws(() => a.seal(rnd(8), rnd(5), rnd(4)), `${name} short nonce`);
	// destroy: idempotent, then every call fails closed
	a.destroy!();
	a.destroy!();
	assert.throws(() => a.seal(rnd(12), rnd(5), rnd(4)), /destroyed/, `${name} use after destroy`);
}

for (const kl of [16, 32]) exercise(`aes-${kl * 8}-gcm`, gcm, kl, nodeGcmSeal);
if (chacha) exercise('chacha20-poly1305', chacha, 32, (k, n, a, p) => pureSeal(k)(n, a, p));
else console.log('cng: ChaCha20-Poly1305 not in this Windows build (pure-TS path stays)');
// the pure-TS open accepts what CNG ChaCha seals (and vice versa, via the oracle above)
if (chacha) {
	const k = rnd(32), n = rnd(12), ad = rnd(5), p = rnd(777);
	assert.deepEqual(pureOpen(k)(n, ad, chacha(k).seal(n, ad, p)), p, 'pure-TS opens CNG ChaCha');
}

// Native leak smoke: 20k key handles created and destroyed must not grow the process.
{
	const k = rnd(16);
	const rss0 = process.memoryUsage().rss;
	for (let i = 0; i < 20000; i++) gcm(k).destroy!();
	const grew = (process.memoryUsage().rss - rss0) / 1048576;
	assert.ok(grew < 24, `20k create/destroy grew RSS by ${grew.toFixed(1)} MiB`);
}

console.log(`cng: OK (${checks} checks; aes-gcm${chacha ? ' + chacha20-poly1305' : ''})`);
