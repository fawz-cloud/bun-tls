// ChaCha20-Poly1305 vs RFC 8439 §2.8.2. Run: bun scratch/bun-tls/test/chacha.test.ts
import assert from 'node:assert';
import { fromHex, hex } from '../src/core/bytes';
import { chacha20Poly1305, chacha20, pureSeal, pureOpen } from '../src/core/chacha';

// §2.4.2 ChaCha20 keystream/encrypt
const key = fromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
const nonce244 = fromHex('000000000000004a00000000');
const pt244 = Buffer.from("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.");
const ct244 = chacha20(key, 1, nonce244, new Uint8Array(pt244));
assert.equal(hex(ct244).slice(0, 32), '6e2e359a2568f98041ba0728dd0d6981', 'chacha20 keystream start matches RFC');

// §2.8.2 AEAD seal
const aeadKey = fromHex('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f');
const nonce = fromHex('070000004041424344454647');
const aad = fromHex('50515253c0c1c2c3c4c5c6c7');
const pt = Buffer.from("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.");
// Both the pure-TS AEAD and the factory's (Windows CNG when present) must hit the RFC vector.
const aead = chacha20Poly1305(aeadKey);
const pure = { seal: pureSeal(aeadKey), open: pureOpen(aeadKey) };
for (const [name, a] of [['pure-TS', pure], ['factory', aead]] as const) {
	const sealed = a.seal(nonce, aad, new Uint8Array(pt));
	assert.equal(hex(sealed.subarray(sealed.length - 16)), '1ae10b594f09e26a7e902ecbd0600691', `${name}: poly1305 tag matches RFC`);
	assert.equal(hex(sealed.subarray(0, 16)), 'd31a8d34648e60db7b86afbc53ef7ec2', `${name}: ciphertext start matches RFC`);
	const tampered = Uint8Array.of(...sealed.subarray(0, sealed.length - 1), sealed[sealed.length - 1]! ^ 1);
	assert.equal(Buffer.from(a.open(nonce, aad, sealed)).toString(), pt.toString(), `${name}: open returns plaintext`);
	assert.throws(() => a.open(nonce, aad, tampered), `${name}: tampered tag rejected`);
}

// The native WebCrypto bulk path, the pure-TS seal/open and the factory's sync path must be
// byte-identical and interoperate every way — the record layer uses one to produce what another
// consumes. WebCrypto is the reference oracle for the pure-TS ChaCha core + donna-16 Poly1305,
// across block-boundary sizes and AAD lengths 0..33 (Poly1305's leftover/padTo16/finish paths).
await (async () => {
	assert.ok(aead.sealAsync && aead.openAsync, 'native ChaCha path present on this runtime');
	const sizes = [0, 1, 15, 16, 17, 31, 63, 64, 65, 127, 128, 129, 1000, 4096, 16383, 16384, 65536];
	for (const n of sizes) {
		const p = crypto.getRandomValues(new Uint8Array(n));
		const nn = crypto.getRandomValues(new Uint8Array(12));
		for (const al of [0, 1, 5, 15, 16, 17, 33]) {
			const ad = crypto.getRandomValues(new Uint8Array(al));
			const natCt = new Uint8Array(await aead.sealAsync!(nn, ad, p));
			assert.deepEqual(pure.seal(nn, ad, p), natCt, `pure seal == webcrypto (n=${n} aad=${al})`);
			assert.deepEqual(aead.seal(nn, ad, p), natCt, `factory seal == webcrypto (n=${n} aad=${al})`);
			assert.deepEqual(pure.open(nn, ad, natCt), p, `pure open(native ct) (n=${n} aad=${al})`);
			assert.deepEqual(aead.open(nn, ad, natCt), p, `factory open(native ct) (n=${n} aad=${al})`);
			assert.deepEqual(new Uint8Array(await aead.openAsync!(nn, ad, pure.seal(nn, ad, p))), p, `native open(pure ct) (n=${n} aad=${al})`);
		}
	}
})();

console.log('chacha: OK');
