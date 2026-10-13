// TLS 1.3 record layer. Plaintext (ClientHello) + AEAD (after keys exist). The
// TLS1.3 inner plaintext = content || real_type(1) || padding(0). AAD = 5-byte header.
import { Aead, seqNonce } from '../core/crypto';
import { ContentType, TLS12 } from '../core/consts';
import { concat } from '../core/bytes';

// One cached 1-byte Uint8Array per content type (read-only, appended as the TLS 1.3 inner type).
const TYPE_BYTE: Uint8Array[] = [];
const typeByte = (t: number): Uint8Array => (TYPE_BYTE[t] ??= Uint8Array.of(t));

interface Record {
	type: number; // header ContentType (23 for ciphertext)
	fragment: Uint8Array;
}

/** Buffer incoming bytes → emit complete records one at a time. Holds a queue of chunks and
 *  reads across them, so a large socket chunk (Bun hands us ~400-512 KiB) is never copied: a
 *  record wholly inside one chunk is a view; only a record that straddles two chunks is copied,
 *  into a fresh exact-size buffer (never reused, so views handed out stay valid). */
export class RecordReader {
	private q: Uint8Array[] = []; // pending chunks; q[0] is read from `off`
	private off = 0; // read position within q[0]
	private n = 0; // total unread bytes across the queue

	feed(b: Uint8Array): void {
		if (b.length) {
			this.q.push(b);
			this.n += b.length;
		}
	}

	/** null = not enough bytes yet for a full record (nothing is consumed in that case). */
	next(): Record | null {
		if (this.n < 5) return null;
		const len = (this.peek(3) << 8) | this.peek(4);
		if (this.n < 5 + len) return null;
		const type = this.peek(0);
		this.drop(5);
		return { type, fragment: this.take(len) };
	}

	/** Byte at offset `i` from the current read position, fast path when it is inside q[0]. */
	private peek(i: number): number {
		const c0 = this.q[0]!;
		const p = this.off + i;
		if (p < c0.length) return c0[p]!;
		let rem = p - c0.length;
		for (let k = 1; k < this.q.length; k++) {
			const c = this.q[k]!;
			if (rem < c.length) return c[rem]!;
			rem -= c.length;
		}
		throw new Error('record peek past end'); // unreachable: callers check n first
	}

	/** Advance the read position by `len`, dropping fully-read chunks. */
	private drop(len: number): void {
		this.n -= len;
		let need = len;
		while (need > 0) {
			const avail = this.q[0]!.length - this.off;
			if (need < avail) {
				this.off += need;
				return;
			}
			need -= avail;
			this.q.shift();
			this.off = 0;
		}
	}

	/** Take the next `len` bytes: a view when they sit inside q[0], else a fresh joined copy. */
	private take(len: number): Uint8Array {
		if (len === 0) return new Uint8Array(0); // empty record (e.g. a 0-length app-data record)
		const c0 = this.q[0]!;
		if (this.off + len <= c0.length) {
			const v = c0.subarray(this.off, this.off + len);
			this.drop(len);
			return v;
		}
		const out = new Uint8Array(len);
		let w = 0;
		while (w < len) {
			const c = this.q[0]!;
			const take = Math.min(len - w, c.length - this.off);
			out.set(c.subarray(this.off, this.off + take), w);
			w += take;
			this.drop(take);
		}
		return out;
	}
}

/** One AEAD direction (key+iv+seq). write = client→server, read = server→client. */
export class AeadDir {
	private seq = 0; // Number, not BigInt: exact and nonce-safe for seq < 2^53 (see nextNonce)
	constructor(
		private aead: Aead,
		private iv: Uint8Array
	) {}

	/** Nonce for the current record, then advance seq. A fresh buffer every call (async ChaCha
	 *  reads it after an await). Past 2^53 seq++ would stall and reuse a nonce — fail closed. */
	private nextNonce(): Uint8Array {
		if (this.seq >= Number.MAX_SAFE_INTEGER) throw new Error('AEAD sequence number exhausted');
		return seqNonce(this.iv, this.seq++);
	}

	/** Wrap `plaintext` as a TLSCiphertext (app_data 0x17). innerType = the real
	 *  ContentType (handshake/app/alert), appended to the plaintext. */
	encrypt(innerType: number, plaintext: Uint8Array): Uint8Array {
		const out = new Uint8Array(5 + plaintext.length + 1 + 16);
		this.sealRecord(innerType, plaintext, out, 0);
		return out;
	}

	/** Fragment `data` into ≤maxFrag-byte records and encrypt them all into ONE buffer:
	 *  one allocation, headers written in place, one socket write for the caller. */
	encryptMany(innerType: number, data: Uint8Array, maxFrag: number): Uint8Array {
		const n = Math.ceil(data.length / maxFrag);
		const out = new Uint8Array(data.length + n * (5 + 1 + 16)); // header + type byte + tag
		let off = 0;
		for (let p = 0; p < data.length; p += maxFrag) off = this.sealRecord(innerType, data.subarray(p, p + maxFrag), out, off);
		return out;
	}

	/** Write one record (header, then frag||innerType sealed, then tag) into `out` at `off`;
	 *  returns the offset after it. In-place AEAD (CNG): one copy of the plaintext into `out`,
	 *  sealed where it lies. sealParts (node): one copy of the cipher output into `out`. */
	private sealRecord(innerType: number, frag: Uint8Array, out: Uint8Array, off: number): number {
		const len = frag.length + 1 + 16;
		out[off] = ContentType.applicationData;
		out[off + 1] = TLS12 >> 8;
		out[off + 2] = TLS12 & 0xff;
		out[off + 3] = (len >> 8) & 0xff;
		out[off + 4] = len & 0xff;
		const header = out.subarray(off, off + 5);
		const nonce = this.nextNonce();
		if (this.aead.sealInPlace) {
			out.set(frag, off + 5);
			out[off + 5 + frag.length] = innerType;
			this.aead.sealInPlace(nonce, header, out, off + 5, frag.length + 1);
		} else if (this.aead.sealParts) {
			this.aead.sealParts(nonce, header, [frag, typeByte(innerType)], out, off + 5);
		} else {
			out.set(this.aead.seal(nonce, header, concat(frag, typeByte(innerType))), off + 5);
		}
		return off + 5 + len;
	}

	/** True when the cipher has a native async path (ChaCha20 on Bun). The bulk record paths
	 *  (writeAppStream upload, readApp download) switch to the *Async methods then. */
	get hasAsync(): boolean {
		return !!this.aead.sealAsync;
	}

	/** Async form of encryptMany: fragment `data`, derive each record's nonce+header in order,
	 *  then seal every fragment in PARALLEL via the native AEAD and assemble one buffer. One
	 *  socket write for the caller, and the native crypto runs off-thread at ~1 GB/s. */
	async encryptManyAsync(innerType: number, data: Uint8Array, maxFrag: number): Promise<Uint8Array> {
		if (!this.aead.sealAsync) return this.encryptMany(innerType, data, maxFrag);
		const type = typeByte(innerType);
		const jobs: Promise<Uint8Array>[] = [];
		const headers: Uint8Array[] = [];
		for (let p = 0; p < data.length; p += maxFrag) {
			const frag = data.subarray(p, p + maxFrag);
			const len = frag.length + 1 + 16; // + type byte + tag
			const header = Uint8Array.of(ContentType.applicationData, TLS12 >> 8, TLS12 & 0xff, (len >> 8) & 0xff, len & 0xff);
			headers.push(header);
			jobs.push(this.aead.sealAsync(this.nextNonce(), header, concat(frag, type)));
		}
		const cts = await Promise.all(jobs);
		let total = 0;
		for (const ct of cts) total += 5 + ct.length;
		const out = new Uint8Array(total);
		let off = 0;
		for (let i = 0; i < cts.length; i++) {
			out.set(headers[i]!, off);
			out.set(cts[i]!, off + 5);
			off += 5 + cts[i]!.length;
		}
		return out;
	}

	/** Open a TLSCiphertext → { innerType, content } (trailing zero padding removed). With an
	 *  in-place AEAD the plaintext overwrites the ciphertext inside rec.fragment: records come
	 *  from RecordReader (views of socket chunks Bun never reuses, or fresh copies), are opened
	 *  exactly once, in order, and a failure ends the connection — so the buffer is ours. */
	decrypt(rec: Record): { innerType: number; content: Uint8Array } {
		const nonce = this.nextNonce();
		const aad = this.aad(rec);
		return unpad(this.aead.openInPlace ? this.aead.openInPlace(nonce, aad, rec.fragment) : this.aead.open(nonce, aad, rec.fragment));
	}

	/** Release the key's native resources (CNG handle) once this direction is done. */
	destroy(): void {
		this.aead.destroy?.();
	}

	/** Async form of decrypt (native AEAD). The nonce and seq++ happen BEFORE the await, so
	 *  several decryptAsync can be dispatched back to back in wire order (P6 download queue). */
	async decryptAsync(rec: Record): Promise<{ innerType: number; content: Uint8Array }> {
		if (!this.aead.openAsync) return this.decrypt(rec);
		const inner = await this.aead.openAsync(this.nextNonce(), this.aad(rec), rec.fragment);
		return unpad(inner);
	}

	private aad(rec: Record): Uint8Array {
		const len = rec.fragment.length;
		return Uint8Array.of(rec.type, TLS12 >> 8, TLS12 & 0xff, (len >> 8) & 0xff, len & 0xff);
	}
}

function unpad(inner: Uint8Array): { innerType: number; content: Uint8Array } {
	let end = inner.length - 1;
	while (end >= 0 && inner[end] === 0) end--; // strip zero padding
	if (end < 0) throw new Error('empty record after unpadding');
	return { innerType: inner[end]!, content: inner.subarray(0, end) };
}

/** TLSPlaintext (for ClientHello, before keys exist). */
export function plaintextRecord(type: number, fragment: Uint8Array): Uint8Array {
	const len = fragment.length;
	return concat(Uint8Array.of(type, TLS12 >> 8, TLS12 & 0xff, (len >> 8) & 0xff, len & 0xff), fragment);
}
