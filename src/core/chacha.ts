// ChaCha20-Poly1305 (IETF, RFC 8439), pure TS — Bun's node:crypto lacks this
// cipher. Used when the server picks TLS_CHACHA20_POLY1305_SHA256. Validated
// against the RFC 8439 §2.8.2 vector in test/chacha.test.ts.
import type { Aead } from './crypto';

const rotl = (x: number, n: number): number => ((x << n) | (x >>> (32 - n))) >>> 0;

function chachaBlock(key: Uint32Array, counter: number, nonce: Uint32Array): Uint8Array {
	const s = new Uint32Array(16);
	s[0] = 0x61707865; s[1] = 0x3320646e; s[2] = 0x79622d32; s[3] = 0x6b206574;
	s.set(key, 4);
	s[12] = counter >>> 0;
	s[13] = nonce[0]!; s[14] = nonce[1]!; s[15] = nonce[2]!;
	const x = s.slice(); // direct typed-array copy (faster than Uint32Array.from's iterator)
	const QR = (a: number, b: number, c: number, d: number) => {
		x[a] = (x[a]! + x[b]!) >>> 0; x[d] = rotl(x[d]! ^ x[a]!, 16);
		x[c] = (x[c]! + x[d]!) >>> 0; x[b] = rotl(x[b]! ^ x[c]!, 12);
		x[a] = (x[a]! + x[b]!) >>> 0; x[d] = rotl(x[d]! ^ x[a]!, 8);
		x[c] = (x[c]! + x[d]!) >>> 0; x[b] = rotl(x[b]! ^ x[c]!, 7);
	};
	for (let i = 0; i < 10; i++) {
		QR(0, 4, 8, 12); QR(1, 5, 9, 13); QR(2, 6, 10, 14); QR(3, 7, 11, 15);
		QR(0, 5, 10, 15); QR(1, 6, 11, 12); QR(2, 7, 8, 13); QR(3, 4, 9, 14);
	}
	const out = new Uint8Array(64);
	const dv = new DataView(out.buffer);
	for (let i = 0; i < 16; i++) dv.setUint32(i * 4, (x[i]! + s[i]!) >>> 0, true);
	return out;
}

function chacha20(key: Uint8Array, counter: number, nonce: Uint8Array, data: Uint8Array): Uint8Array {
	const k = new Uint32Array(8);
	const kdv = new DataView(key.buffer, key.byteOffset, 32);
	for (let i = 0; i < 8; i++) k[i] = kdv.getUint32(i * 4, true);
	const n = new Uint32Array(3);
	const ndv = new DataView(nonce.buffer, nonce.byteOffset, 12);
	for (let i = 0; i < 3; i++) n[i] = ndv.getUint32(i * 4, true);
	const out = new Uint8Array(data.length);
	let blk = counter;
	for (let off = 0; off < data.length; off += 64) {
		const ks = chachaBlock(k, blk++, n); // block counter; chachaBlock masks with >>>0
		const end = Math.min(64, data.length - off);
		for (let i = 0; i < end; i++) out[off + i] = data[off + i]! ^ ks[i]!;
	}
	return out;
}

const P = (1n << 130n) - 5n;
function poly1305(key: Uint8Array, msg: Uint8Array): Uint8Array {
	let r = bytesToLE(key.subarray(0, 16));
	r &= 0x0ffffffc0ffffffc0ffffffc0fffffffn;
	const s = bytesToLE(key.subarray(16, 32));
	let acc = 0n;
	for (let i = 0; i < msg.length; i += 16) {
		const block = msg.subarray(i, i + 16);
		const n = bytesToLE(block) + (1n << BigInt(8 * block.length));
		acc = ((acc + n) * r) % P;
	}
	acc = (acc + s) & ((1n << 128n) - 1n);
	return leToBytes(acc, 16);
}
const bytesToLE = (b: Uint8Array): bigint => {
	let v = 0n;
	for (let i = b.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(b[i]!);
	return v;
};
const leToBytes = (v: bigint, n: number): Uint8Array => {
	const out = new Uint8Array(n);
	for (let i = 0; i < n; i++) { out[i] = Number(v & 0xffn); v >>= 8n; }
	return out;
};

const pad16 = (len: number): number => (16 - (len % 16)) % 16;

/** Poly1305 tag is ALWAYS computed over the CIPHERTEXT (not plaintext). */
function tagOf(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, ciphertext: Uint8Array): Uint8Array {
	const polyKey = chacha20(key, 0, nonce, new Uint8Array(32));
	const mac = new Uint8Array(aad.length + pad16(aad.length) + ciphertext.length + pad16(ciphertext.length) + 16);
	let o = 0;
	mac.set(aad, o); o += aad.length + pad16(aad.length);
	mac.set(ciphertext, o); o += ciphertext.length + pad16(ciphertext.length);
	new DataView(mac.buffer).setBigUint64(o, BigInt(aad.length), true);
	new DataView(mac.buffer).setBigUint64(o + 8, BigInt(ciphertext.length), true);
	return poly1305(polyKey, mac);
}

// Bun's WebCrypto has a NATIVE ChaCha20-Poly1305 (node:crypto does not); it is async-only.
// Importing once per traffic key, it seals/opens one record at ~550 MB/s and, called in
// parallel with Promise.all, at ~1 GB/s — vs ~6 MB/s for the pure-TS code above. We detect
// it once; if absent (older runtime), the async methods stay undefined and callers fall back
// to the sync pure-TS path. Output layout (ciphertext||tag) is identical either way.
const NATIVE_CHACHA = typeof crypto !== 'undefined' && !!crypto.subtle;
const ALG = 'ChaCha20-Poly1305';

/** AEAD factory for ChaCha20-Poly1305 (keyLen 32). seal/open are the pure-TS path (used for
 *  the small handshake records); sealAsync/openAsync use native WebCrypto for bulk data. */
export function chacha20Poly1305(key: Uint8Array): Aead {
	const sealSync = (nonce: Uint8Array, aad: Uint8Array, pt: Uint8Array): Uint8Array => {
		const ct = chacha20(key, 1, nonce, pt);
		const tag = tagOf(key, nonce, aad, ct);
		const r = new Uint8Array(ct.length + 16);
		r.set(ct); r.set(tag, ct.length);
		return r;
	};
	const openSync = (nonce: Uint8Array, aad: Uint8Array, sealed: Uint8Array): Uint8Array => {
		const body = sealed.subarray(0, sealed.length - 16);
		const tag = sealed.subarray(sealed.length - 16);
		const want = tagOf(key, nonce, aad, body);
		let diff = 0;
		for (let i = 0; i < 16; i++) diff |= tag[i]! ^ want[i]!;
		if (diff !== 0) throw new Error('chacha20-poly1305 tag mismatch');
		return chacha20(key, 1, nonce, body);
	};
	const aead: Aead = { keyLen: 32, seal: sealSync, open: openSync };
	if (NATIVE_CHACHA) {
		// TS 6 splits Uint8Array<ArrayBuffer|ArrayBufferLike>; WebCrypto wants a plain BufferSource.
		const bs = (u: Uint8Array) => u as unknown as Uint8Array<ArrayBuffer>;
		// Import the key once (lazily, on first bulk use) and reuse the CryptoKey per record.
		let ck: Promise<CryptoKey> | null = null;
		const getKey = () => (ck ??= crypto.subtle.importKey('raw-secret' as 'raw', bs(key), ALG, false, ['encrypt', 'decrypt']));
		aead.sealAsync = async (nonce, aad, pt) => {
			const k = await getKey();
			return new Uint8Array(await crypto.subtle.encrypt({ name: ALG, iv: bs(nonce), additionalData: bs(aad) }, k, bs(pt)));
		};
		aead.openAsync = async (nonce, aad, ct) => {
			const k = await getKey();
			return new Uint8Array(await crypto.subtle.decrypt({ name: ALG, iv: bs(nonce), additionalData: bs(aad) }, k, bs(ct)));
		};
	}
	return aead;
}

export { chacha20 };
