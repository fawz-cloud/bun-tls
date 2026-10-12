// ChaCha20-Poly1305 vs RFC 8439 §2.8.2. Run: bun scratch/bun-tls/test/chacha.test.ts
import assert from 'node:assert';
import { fromHex, hex } from '../src/core/bytes';
import { chacha20Poly1305, chacha20 } from '../src/core/chacha';

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
const aead = chacha20Poly1305(aeadKey);
const sealed = aead.seal(nonce, aad, new Uint8Array(pt));
const tag = sealed.subarray(sealed.length - 16);
assert.equal(hex(tag), '1ae10b594f09e26a7e902ecbd0600691', 'poly1305 tag matches RFC');
assert.equal(hex(sealed.subarray(0, 16)), 'd31a8d34648e60db7b86afbc53ef7ec2', 'ciphertext start matches RFC');
// round-trip open
assert.equal(Buffer.from(aead.open(nonce, aad, sealed)).toString(), pt.toString(), 'open returns plaintext');
assert.throws(
	() => aead.open(nonce, aad, Uint8Array.of(...sealed.subarray(0, sealed.length - 1), sealed[sealed.length - 1]! ^ 1)),
	'tampered tag rejected'
);

console.log('chacha: OK');
