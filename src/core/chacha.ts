// ChaCha20-Poly1305 (IETF, RFC 8439), pure TS — Bun's node:crypto lacks this
// cipher. Used when the server picks TLS_CHACHA20_POLY1305_SHA256. Validated
// against the RFC 8439 §2.8.2 vector in test/chacha.test.ts.
import type { Aead } from './crypto';
import { cngChaCha20Poly1305 } from './cng';

const rotl = (x: number, n: number): number => ((x << n) | (x >>> (32 - n))) >>> 0;

// ChaCha20 block into a reused 16-word scratch (no per-block allocation). `s` is the input
// state; results land in `x` which the caller XORs into the output.
function chachaCore(s: Int32Array, x: Int32Array): void {
	for (let i = 0; i < 16; i++) x[i] = s[i]!;
	for (let i = 0; i < 10; i++) {
		qr(x, 0, 4, 8, 12); qr(x, 1, 5, 9, 13); qr(x, 2, 6, 10, 14); qr(x, 3, 7, 11, 15);
		qr(x, 0, 5, 10, 15); qr(x, 1, 6, 11, 12); qr(x, 2, 7, 8, 13); qr(x, 3, 4, 9, 14);
	}
	for (let i = 0; i < 16; i++) x[i] = (x[i]! + s[i]!) | 0;
}
function qr(x: Int32Array, a: number, b: number, c: number, d: number): void {
	x[a] = (x[a]! + x[b]!) | 0; x[d] = rotl(x[d]! ^ x[a]!, 16);
	x[c] = (x[c]! + x[d]!) | 0; x[b] = rotl(x[b]! ^ x[c]!, 12);
	x[a] = (x[a]! + x[b]!) | 0; x[d] = rotl(x[d]! ^ x[a]!, 8);
	x[c] = (x[c]! + x[d]!) | 0; x[b] = rotl(x[b]! ^ x[c]!, 7);
}

function chacha20(key: Uint8Array, counter: number, nonce: Uint8Array, data: Uint8Array): Uint8Array {
	const kdv = new DataView(key.buffer, key.byteOffset, 32);
	const ndv = new DataView(nonce.buffer, nonce.byteOffset, 12);
	const s = new Int32Array(16);
	s[0] = 0x61707865; s[1] = 0x3320646e; s[2] = 0x79622d32; s[3] = 0x6b206574;
	for (let i = 0; i < 8; i++) s[4 + i] = kdv.getInt32(i * 4, true);
	s[13] = ndv.getInt32(0, true); s[14] = ndv.getInt32(4, true); s[15] = ndv.getInt32(8, true);
	const x = new Int32Array(16); // one keystream scratch, reused for every block (no per-block alloc)
	const out = new Uint8Array(data.length);
	let blk = counter;
	for (let off = 0; off < data.length; off += 64) {
		s[12] = blk++ | 0; // block counter (wraps at 2^32 like the old >>> 0)
		chachaCore(s, x);
		const end = Math.min(64, data.length - off);
		for (let i = 0; i < end; i++) out[off + i] = data[off + i]! ^ ((x[i >> 2]! >>> ((i & 3) << 3)) & 0xff); // LE byte of x[i>>2]
	}
	return out;
}

// ── Poly1305 (poly1305-donna-16), ported from TweetNaCl.js (public domain). 10 limbs of 13
// bits; every partial product fits in a double. Byte-identical to the previous BigInt version
// (checked against it and the RFC 8439 vectors in test/chacha.test.ts). Streams AAD, padding,
// ciphertext and the length block so the whole MAC input is never assembled in one buffer. ──
class Poly1305 {
	private h = new Float64Array(10);
	private r = new Float64Array(10);
	private pad = new Float64Array(8);
	private buffer = new Uint8Array(16);
	private leftover = 0;
	private fin = 0;

	constructor(key: Uint8Array) {
		const t = (i: number) => (key[i]! & 0xff) | ((key[i + 1]! & 0xff) << 8);
		const t0 = t(0), t1 = t(2), t2 = t(4), t3 = t(6), t4 = t(8), t5 = t(10), t6 = t(12), t7 = t(14);
		this.r[0] = t0 & 0x1fff;
		this.r[1] = ((t0 >>> 13) | (t1 << 3)) & 0x1fff;
		this.r[2] = ((t1 >>> 10) | (t2 << 6)) & 0x1f03;
		this.r[3] = ((t2 >>> 7) | (t3 << 9)) & 0x1fff;
		this.r[4] = ((t3 >>> 4) | (t4 << 12)) & 0x00ff;
		this.r[5] = (t4 >>> 1) & 0x1ffe;
		this.r[6] = ((t4 >>> 14) | (t5 << 2)) & 0x1fff;
		this.r[7] = ((t5 >>> 11) | (t6 << 5)) & 0x1f81;
		this.r[8] = ((t6 >>> 8) | (t7 << 8)) & 0x1fff;
		this.r[9] = (t7 >>> 5) & 0x007f;
		for (let i = 0; i < 8; i++) this.pad[i] = t(16 + i * 2);
	}

	private blocks(m: Uint8Array, mpos: number, bytes: number): void {
		const hibit = this.fin ? 0 : 1 << 11;
		const h = this.h, r = this.r;
		let h0 = h[0]!, h1 = h[1]!, h2 = h[2]!, h3 = h[3]!, h4 = h[4]!, h5 = h[5]!, h6 = h[6]!, h7 = h[7]!, h8 = h[8]!, h9 = h[9]!;
		const r0 = r[0]!, r1 = r[1]!, r2 = r[2]!, r3 = r[3]!, r4 = r[4]!, r5 = r[5]!, r6 = r[6]!, r7 = r[7]!, r8 = r[8]!, r9 = r[9]!;
		while (bytes >= 16) {
			const t = (i: number) => (m[mpos + i]! & 0xff) | ((m[mpos + i + 1]! & 0xff) << 8);
			const t0 = t(0), t1 = t(2), t2 = t(4), t3 = t(6), t4 = t(8), t5 = t(10), t6 = t(12), t7 = t(14);
			h0 += t0 & 0x1fff;
			h1 += ((t0 >>> 13) | (t1 << 3)) & 0x1fff;
			h2 += ((t1 >>> 10) | (t2 << 6)) & 0x1fff;
			h3 += ((t2 >>> 7) | (t3 << 9)) & 0x1fff;
			h4 += ((t3 >>> 4) | (t4 << 12)) & 0x1fff;
			h5 += (t4 >>> 1) & 0x1fff;
			h6 += ((t4 >>> 14) | (t5 << 2)) & 0x1fff;
			h7 += ((t5 >>> 11) | (t6 << 5)) & 0x1fff;
			h8 += ((t6 >>> 8) | (t7 << 8)) & 0x1fff;
			h9 += (t7 >>> 5) | hibit;

			// Multiply (h += block) by r mod 2^130-5. Each d is summed in two groups of five
			// so every intermediate stays < 2^32, where `>>> 13` and `& 0x1fff` are exact.
			let c = 0;
			let d0 = c + h0 * r0 + h1 * (5 * r9) + h2 * (5 * r8) + h3 * (5 * r7) + h4 * (5 * r6); c = (d0 / 0x2000) | 0; d0 &= 0x1fff;
			d0 += h5 * (5 * r5) + h6 * (5 * r4) + h7 * (5 * r3) + h8 * (5 * r2) + h9 * (5 * r1); c += (d0 / 0x2000) | 0; d0 &= 0x1fff;
			let d1 = c + h0 * r1 + h1 * r0 + h2 * (5 * r9) + h3 * (5 * r8) + h4 * (5 * r7); c = (d1 / 0x2000) | 0; d1 &= 0x1fff;
			d1 += h5 * (5 * r6) + h6 * (5 * r5) + h7 * (5 * r4) + h8 * (5 * r3) + h9 * (5 * r2); c += (d1 / 0x2000) | 0; d1 &= 0x1fff;
			let d2 = c + h0 * r2 + h1 * r1 + h2 * r0 + h3 * (5 * r9) + h4 * (5 * r8); c = (d2 / 0x2000) | 0; d2 &= 0x1fff;
			d2 += h5 * (5 * r7) + h6 * (5 * r6) + h7 * (5 * r5) + h8 * (5 * r4) + h9 * (5 * r3); c += (d2 / 0x2000) | 0; d2 &= 0x1fff;
			let d3 = c + h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * (5 * r9); c = (d3 / 0x2000) | 0; d3 &= 0x1fff;
			d3 += h5 * (5 * r8) + h6 * (5 * r7) + h7 * (5 * r6) + h8 * (5 * r5) + h9 * (5 * r4); c += (d3 / 0x2000) | 0; d3 &= 0x1fff;
			let d4 = c + h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0; c = (d4 / 0x2000) | 0; d4 &= 0x1fff;
			d4 += h5 * (5 * r9) + h6 * (5 * r8) + h7 * (5 * r7) + h8 * (5 * r6) + h9 * (5 * r5); c += (d4 / 0x2000) | 0; d4 &= 0x1fff;
			let d5 = c + h0 * r5 + h1 * r4 + h2 * r3 + h3 * r2 + h4 * r1; c = (d5 / 0x2000) | 0; d5 &= 0x1fff;
			d5 += h5 * r0 + h6 * (5 * r9) + h7 * (5 * r8) + h8 * (5 * r7) + h9 * (5 * r6); c += (d5 / 0x2000) | 0; d5 &= 0x1fff;
			let d6 = c + h0 * r6 + h1 * r5 + h2 * r4 + h3 * r3 + h4 * r2; c = (d6 / 0x2000) | 0; d6 &= 0x1fff;
			d6 += h5 * r1 + h6 * r0 + h7 * (5 * r9) + h8 * (5 * r8) + h9 * (5 * r7); c += (d6 / 0x2000) | 0; d6 &= 0x1fff;
			let d7 = c + h0 * r7 + h1 * r6 + h2 * r5 + h3 * r4 + h4 * r3; c = (d7 / 0x2000) | 0; d7 &= 0x1fff;
			d7 += h5 * r2 + h6 * r1 + h7 * r0 + h8 * (5 * r9) + h9 * (5 * r8); c += (d7 / 0x2000) | 0; d7 &= 0x1fff;
			let d8 = c + h0 * r8 + h1 * r7 + h2 * r6 + h3 * r5 + h4 * r4; c = (d8 / 0x2000) | 0; d8 &= 0x1fff;
			d8 += h5 * r3 + h6 * r2 + h7 * r1 + h8 * r0 + h9 * (5 * r9); c += (d8 / 0x2000) | 0; d8 &= 0x1fff;
			let d9 = c + h0 * r9 + h1 * r8 + h2 * r7 + h3 * r6 + h4 * r5; c = (d9 / 0x2000) | 0; d9 &= 0x1fff;
			d9 += h5 * r4 + h6 * r3 + h7 * r2 + h8 * r1 + h9 * r0; c += (d9 / 0x2000) | 0; d9 &= 0x1fff;

			c = ((c << 2) + c) | 0; // c *= 5 (fold the overflow of 2^130 back as 5)
			c = (c + d0) | 0; d0 = c & 0x1fff; c = c >>> 13;
			d1 += c;

			h0 = d0; h1 = d1; h2 = d2; h3 = d3; h4 = d4; h5 = d5; h6 = d6; h7 = d7; h8 = d8; h9 = d9;
			mpos += 16;
			bytes -= 16;
		}
		h[0] = h0; h[1] = h1; h[2] = h2; h[3] = h3; h[4] = h4; h[5] = h5; h[6] = h6; h[7] = h7; h[8] = h8; h[9] = h9;
	}

	update(m: Uint8Array, mpos = 0, bytes = m.length - mpos): void {
		if (this.leftover) {
			let want = 16 - this.leftover;
			if (want > bytes) want = bytes;
			for (let i = 0; i < want; i++) this.buffer[this.leftover + i] = m[mpos + i]!;
			bytes -= want;
			mpos += want;
			this.leftover += want;
			if (this.leftover < 16) return;
			this.blocks(this.buffer, 0, 16);
			this.leftover = 0;
		}
		if (bytes >= 16) {
			const want = bytes - (bytes % 16);
			this.blocks(m, mpos, want);
			mpos += want;
			bytes -= want;
		}
		if (bytes) {
			for (let i = 0; i < bytes; i++) this.buffer[this.leftover + i] = m[mpos + i]!;
			this.leftover += bytes;
		}
	}

	/** Zero-pad the current position up to a 16-byte boundary (RFC 8439 pad16 between fields). */
	padTo16(): void {
		if (this.leftover) {
			for (let i = this.leftover; i < 16; i++) this.buffer[i] = 0;
			this.blocks(this.buffer, 0, 16);
			this.leftover = 0;
		}
	}

	finish(): Uint8Array {
		const h = this.h, pad = this.pad;
		if (this.leftover) {
			let i = this.leftover;
			this.buffer[i++] = 1;
			for (; i < 16; i++) this.buffer[i] = 0;
			this.fin = 1;
			this.blocks(this.buffer, 0, 16);
		}
		let c = h[1]! >>> 13;
		h[1]! &= 0x1fff;
		for (let i = 2; i < 10; i++) {
			h[i] = h[i]! + c;
			c = h[i]! >>> 13;
			h[i]! &= 0x1fff;
		}
		h[0] = h[0]! + c * 5; c = h[0]! >>> 13; h[0]! &= 0x1fff;
		h[1] = h[1]! + c; c = h[1]! >>> 13; h[1]! &= 0x1fff;
		h[2] = h[2]! + c;

		const g = new Float64Array(10);
		g[0] = h[0]! + 5; c = g[0]! >>> 13; g[0]! &= 0x1fff;
		for (let i = 1; i < 10; i++) {
			g[i] = h[i]! + c;
			c = g[i]! >>> 13;
			g[i]! &= 0x1fff;
		}
		g[9]! -= 1 << 13;

		let mask = (c ^ 1) - 1;
		mask &= 0xffffffff;
		for (let i = 0; i < 10; i++) g[i]! &= mask;
		mask = ~mask & 0xffffffff;
		for (let i = 0; i < 10; i++) h[i] = (h[i]! & mask) | g[i]!;

		h[0] = (h[0]! | (h[1]! << 13)) & 0xffff;
		h[1] = ((h[1]! >>> 3) | (h[2]! << 10)) & 0xffff;
		h[2] = ((h[2]! >>> 6) | (h[3]! << 7)) & 0xffff;
		h[3] = ((h[3]! >>> 9) | (h[4]! << 4)) & 0xffff;
		h[4] = ((h[4]! >>> 12) | (h[5]! << 1) | (h[6]! << 14)) & 0xffff;
		h[5] = ((h[6]! >>> 2) | (h[7]! << 11)) & 0xffff;
		h[6] = ((h[7]! >>> 5) | (h[8]! << 8)) & 0xffff;
		h[7] = ((h[8]! >>> 8) | (h[9]! << 5)) & 0xffff;

		let f = h[0]! + pad[0]!; h[0] = f & 0xffff;
		for (let i = 1; i < 8; i++) {
			f = (((h[i]! + pad[i]!) | 0) + (f / 0x10000)) | 0;
			h[i] = f & 0xffff;
		}
		const out = new Uint8Array(16);
		for (let i = 0; i < 8; i++) {
			out[i * 2] = h[i]! & 0xff;
			out[i * 2 + 1] = (h[i]! >>> 8) & 0xff;
		}
		return out;
	}
}

const pad16 = (len: number): number => (16 - (len % 16)) % 16;
const LENBLOCK = new Uint8Array(16);

/** Poly1305 tag is ALWAYS computed over the CIPHERTEXT (not plaintext). Streams the fields so
 *  the whole AAD||pad||ct||pad||lengths input is never assembled in one buffer. */
function tagOf(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, ciphertext: Uint8Array): Uint8Array {
	const polyKey = chacha20(key, 0, nonce, new Uint8Array(32));
	const p = new Poly1305(polyKey);
	p.update(aad);
	p.padTo16();
	p.update(ciphertext);
	p.padTo16();
	const dv = new DataView(LENBLOCK.buffer);
	dv.setUint32(0, aad.length >>> 0, true);
	dv.setUint32(4, Math.floor(aad.length / 0x100000000) >>> 0, true);
	dv.setUint32(8, ciphertext.length >>> 0, true);
	dv.setUint32(12, Math.floor(ciphertext.length / 0x100000000) >>> 0, true);
	p.update(LENBLOCK);
	return p.finish();
}

// Bun's WebCrypto has a NATIVE ChaCha20-Poly1305 (node:crypto does not); it is async-only.
// Importing once per traffic key, it seals/opens one record at ~550 MB/s and, called in
// parallel with Promise.all, at ~1 GB/s — vs ~6 MB/s for the pure-TS code above. We detect
// it once; if absent (older runtime), the async methods stay undefined and callers fall back
// to the sync pure-TS path. Output layout (ciphertext||tag) is identical either way.
const NATIVE_CHACHA = typeof crypto !== 'undefined' && !!crypto.subtle;
const ALG = 'ChaCha20-Poly1305';

/** AEAD factory for ChaCha20-Poly1305 (keyLen 32). The synchronous paths (handshake records,
 *  small writes) use Windows CNG in place when available (~5× the pure-TS speed), else the
 *  pure-TS code; sealAsync/openAsync use native WebCrypto for bulk data (parallel batches). */
export function chacha20Poly1305(key: Uint8Array): Aead {
	const native = cngChaCha20Poly1305();
	const aead: Aead = native ? native(key) : { keyLen: 32, seal: pureSeal(key), open: pureOpen(key) };
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

/** Pure-TS seal (ciphertext || tag). */
function pureSeal(key: Uint8Array) {
	return (nonce: Uint8Array, aad: Uint8Array, pt: Uint8Array): Uint8Array => {
		const ct = chacha20(key, 1, nonce, pt);
		const tag = tagOf(key, nonce, aad, ct);
		const r = new Uint8Array(ct.length + 16);
		r.set(ct); r.set(tag, ct.length);
		return r;
	};
}

/** Pure-TS open: verify the tag (constant-time compare) before decrypting. */
function pureOpen(key: Uint8Array) {
	return (nonce: Uint8Array, aad: Uint8Array, sealed: Uint8Array): Uint8Array => {
		const body = sealed.subarray(0, sealed.length - 16);
		const tag = sealed.subarray(sealed.length - 16);
		const want = tagOf(key, nonce, aad, body);
		let diff = 0;
		for (let i = 0; i < 16; i++) diff |= tag[i]! ^ want[i]!;
		if (diff !== 0) throw new Error('chacha20-poly1305 tag mismatch');
		return chacha20(key, 1, nonce, body);
	};
}

export { chacha20, pureSeal, pureOpen };
