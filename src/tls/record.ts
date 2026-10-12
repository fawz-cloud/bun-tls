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

	/** Open a TLSCiphertext → { innerType, content } (trailing zero padding removed). */
	decrypt(rec: Record): { innerType: number; content: Uint8Array } {
		const len = rec.fragment.length;
		const header = Uint8Array.of(rec.type, TLS12 >> 8, TLS12 & 0xff, (len >> 8) & 0xff, len & 0xff);
		const inner = this.aead.open(aeadNonce(this.iv, this.seq), header, rec.fragment);
		this.seq++;
		let end = inner.length - 1;
		while (end >= 0 && inner[end] === 0) end--; // strip zero padding
		if (end < 0) throw new Error('empty record after unpadding');
		return { innerType: inner[end]!, content: inner.subarray(0, end) };
	}
}

/** TLSPlaintext (for ClientHello, before keys exist). */
export function plaintextRecord(type: number, fragment: Uint8Array): Uint8Array {
	const len = fragment.length;
	return concat(Uint8Array.of(type, TLS12 >> 8, TLS12 & 0xff, (len >> 8) & 0xff, len & 0xff), fragment);
}
