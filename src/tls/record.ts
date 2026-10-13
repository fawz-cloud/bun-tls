// TLS 1.3 record layer. Plaintext (ClientHello) + AEAD (after keys exist). The
// TLS1.3 inner plaintext = content || real_type(1) || padding(0). AAD = 5-byte header.
import { Aead, aeadNonce } from '../core/crypto';
import { ContentType, TLS12 } from '../core/consts';
import { concat } from '../core/bytes';

interface Record {
	type: number; // header ContentType (23 for ciphertext)
	fragment: Uint8Array;
}

/** Buffer incoming bytes → emit complete records one at a time. */
export class RecordReader {
	private buf: Uint8Array = new Uint8Array(0);
	feed(b: Uint8Array): void {
		this.buf = this.buf.length ? concat(this.buf, b) : b;
	}
	/** null = not enough bytes yet for a full record. */
	next(): Record | null {
		if (this.buf.length < 5) return null;
		const len = (this.buf[3]! << 8) | this.buf[4]!;
		if (this.buf.length < 5 + len) return null;
		const type = this.buf[0]!;
		const fragment = this.buf.subarray(5, 5 + len);
		this.buf = this.buf.subarray(5 + len);
		return { type, fragment };
	}
}

/** One AEAD direction (key+iv+seq). write = client→server, read = server→client. */
export class AeadDir {
	private seq = 0n;
	constructor(
		private aead: Aead,
		private iv: Uint8Array
	) {}

	/** Wrap `plaintext` as a TLSCiphertext (app_data 0x17). innerType = the real
	 *  ContentType (handshake/app/alert), appended to the plaintext. */
	encrypt(innerType: number, plaintext: Uint8Array): Uint8Array {
		const inner = concat(plaintext, Uint8Array.of(innerType));
		const len = inner.length + 16; // + tag
		const header = Uint8Array.of(ContentType.applicationData, TLS12 >> 8, TLS12 & 0xff, (len >> 8) & 0xff, len & 0xff);
		const ct = this.aead.seal(aeadNonce(this.iv, this.seq), header, inner);
		this.seq++;
		return concat(header, ct);
	}

	/** Fragment `data` into ≤maxFrag-byte records and encrypt them all into ONE buffer:
	 *  one allocation, headers written in place, one socket write for the caller. With
	 *  a sealParts-capable AEAD each record costs a single copy (cipher output → out). */
	encryptMany(innerType: number, data: Uint8Array, maxFrag: number): Uint8Array {
		const n = Math.ceil(data.length / maxFrag);
		const out = new Uint8Array(data.length + n * (5 + 1 + 16)); // header + type byte + tag
		const type = Uint8Array.of(innerType);
		let off = 0;
		for (let p = 0; p < data.length; p += maxFrag) {
			const frag = data.subarray(p, p + maxFrag);
			const len = frag.length + 1 + 16;
			out[off] = ContentType.applicationData;
			out[off + 1] = TLS12 >> 8;
			out[off + 2] = TLS12 & 0xff;
			out[off + 3] = (len >> 8) & 0xff;
			out[off + 4] = len & 0xff;
			const header = out.subarray(off, off + 5);
			const nonce = aeadNonce(this.iv, this.seq++);
			if (this.aead.sealParts) {
				off = this.aead.sealParts(nonce, header, [frag, type], out, off + 5);
			} else {
				const ct = this.aead.seal(nonce, header, concat(frag, type));
				out.set(ct, off + 5);
				off += 5 + ct.length;
			}
		}
		return out;
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
		const type = Uint8Array.of(innerType);
		const jobs: Promise<Uint8Array>[] = [];
		const headers: Uint8Array[] = [];
		for (let p = 0; p < data.length; p += maxFrag) {
			const frag = data.subarray(p, p + maxFrag);
			const len = frag.length + 1 + 16; // + type byte + tag
			const header = Uint8Array.of(ContentType.applicationData, TLS12 >> 8, TLS12 & 0xff, (len >> 8) & 0xff, len & 0xff);
			headers.push(header);
			jobs.push(this.aead.sealAsync(aeadNonce(this.iv, this.seq++), header, concat(frag, type)));
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

	/** Open a TLSCiphertext → { innerType, content } (trailing zero padding removed). */
	decrypt(rec: Record): { innerType: number; content: Uint8Array } {
		const inner = this.aead.open(aeadNonce(this.iv, this.seq), this.aad(rec), rec.fragment);
		this.seq++;
		return unpad(inner);
	}

	/** Async form of decrypt (native AEAD). Used on the download hot path in readApp. */
	async decryptAsync(rec: Record): Promise<{ innerType: number; content: Uint8Array }> {
		if (!this.aead.openAsync) return this.decrypt(rec);
		const inner = await this.aead.openAsync(aeadNonce(this.iv, this.seq), this.aad(rec), rec.fragment);
		this.seq++;
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
