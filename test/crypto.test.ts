// TLS 1.3 primitives vs RFC 8448 vectors (Simple 1-RTT Handshake).
// Run: bun scratch/bun-tls/test/crypto.test.ts
import assert from 'node:assert';
import crypto from 'node:crypto';
import { fromHex, hex } from '../src/core/bytes';
import { aeadNonce, aesGcm, deriveSecret, expandLabel, hkdfExtract, sha, x25519Keypair, x25519Shared } from '../src/core/crypto';

// ── x25519: node derives the RFC 8448 public key from its private key
//    (proves the impl + our raw-key extraction) ──
const clientPrivRaw = fromHex('49af42ba7f7994852d713ef2784bcbcaa7911de26adc5642cb634540e7ea5005');
const pkcs8 = Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'), Buffer.from(clientPrivRaw)]);
const privObj = crypto.createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
const derivedPub = (crypto.createPublicKey(privObj).export({ type: 'spki', format: 'der' }) as Buffer).subarray(-32);
assert.equal(hex(new Uint8Array(derivedPub)), '99381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c', 'x25519 pub RFC 8448');
// x25519Shared is symmetric (A·b == B·a) → ECDHE always agrees on both ends.
const A = x25519Keypair();
const B = x25519Keypair();
assert.equal(hex(x25519Shared(A.priv, B.pub)), hex(x25519Shared(B.priv, A.pub)), 'x25519 shared symmetric');

// ── Key schedule RFC 8448: uses the RFC ECDHE (IKM) = 8bd4054f ──
const H = 'sha256' as const;
const zero = new Uint8Array(32);
const ecdhe = fromHex('8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d');
const early = hkdfExtract(H, zero, zero);
assert.equal(hex(early), '33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a', 'early secret');

const derived = deriveSecret(H, early, 'derived', new Uint8Array(0));
assert.equal(hex(derived), '6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba', 'derived');

const handshake = hkdfExtract(H, derived, ecdhe);
assert.equal(hex(handshake), '1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac', 'handshake secret');

const derived2 = deriveSecret(H, handshake, 'derived', new Uint8Array(0));
const master = hkdfExtract(H, derived2, zero);
assert.equal(hex(master), '18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919', 'master secret');

// ── expandLabel known-answer: Derive-Secret(early,"derived","") uses Hash("") ──
const emptyHash = sha(H, new Uint8Array(0));
assert.equal(hex(expandLabel(H, early, 'derived', emptyHash, 32)), hex(derived), 'expandLabel == deriveSecret');

// ── AES-128-GCM round-trip + 16-byte tag ──
const gcm = aesGcm(16)(fromHex('00112233445566778899aabbccddeeff'));
const iv = fromHex('000000000000000000000000');
const aad = fromHex('170303001a');
const pt = Buffer.from('hello tls 1.3');
const ct = gcm.seal(aeadNonce(iv, 5n), aad, pt);
assert.equal(ct.length, pt.length + 16, 'ciphertext = pt + tag16');
assert.equal(Buffer.from(gcm.open(aeadNonce(iv, 5n), aad, ct)).toString(), 'hello tls 1.3', 'gcm round-trip');
assert.throws(() => gcm.open(aeadNonce(iv, 6n), aad, ct), 'wrong seq → tag fails');

// ── aeadNonce: iv XOR seq in the last 8 bytes ──
assert.equal(hex(aeadNonce(fromHex('0102030405060708090a0b0c'), 0n)), '0102030405060708090a0b0c');
assert.equal(hex(aeadNonce(fromHex('000000000000000000000000'), 0x0102n)), '000000000000000000000102');

console.log('crypto: OK');
