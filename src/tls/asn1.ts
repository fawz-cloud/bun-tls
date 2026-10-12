// Minimal DER (ASN.1) reader + encoder — just enough for OCSP (RFC 6960) and the
// certificate fields OCSP needs (issuer name/key, serial, AIA, EKU). Not a general
// ASN.1 library: definite-length only (DER has no indefinite form), and `oid()`
// assumes sub-identifiers fit in 31 bits (true for every OID used here).

export interface Der {
	tag: number;
	content: Uint8Array; // value bytes (inside tag+length)
	raw: Uint8Array; // whole element incl. tag+length — the bytes a signature covers
	end: number; // offset just past this element in the parent buffer
}

/** Read one TLV element starting at `off`. */
export function der(buf: Uint8Array, off = 0): Der {
	const tag = buf[off]!;
	let i = off + 1;
	let len = buf[i++]!;
	if (len & 0x80) {
		const n = len & 0x7f;
		len = 0;
		for (let k = 0; k < n; k++) len = len * 256 + buf[i++]!;
	}
	return { tag, content: buf.subarray(i, i + len), raw: buf.subarray(off, i + len), end: i + len };
}

/** Split a SEQUENCE/SET content buffer into its child elements, in order. */
export function children(content: Uint8Array): Der[] {
	const out: Der[] = [];
	for (let off = 0; off < content.length; ) {
		const e = der(content, off);
		out.push(e);
		off = e.end;
	}
	return out;
}

/** Decode an OBJECT IDENTIFIER value to dotted form. */
export function oid(content: Uint8Array): string {
	const parts: number[] = [];
	let v = 0;
	for (const b of content) {
		v = v * 128 + (b & 0x7f);
		if (!(b & 0x80)) {
			parts.push(v);
			v = 0;
		}
	}
	const first = parts.shift() ?? 0;
	return [Math.floor(first / 40), first % 40, ...parts].join('.');
}

/** GeneralizedTime (YYYYMMDDHHMMSSZ) or UTCTime (YYMMDDHHMMSSZ) → epoch ms (UTC). */
export function derTime(content: Uint8Array): number {
	const s = Buffer.from(content).toString('latin1');
	let y: number, rest: string;
	if (s.length >= 15) {
		y = +s.slice(0, 4);
		rest = s.slice(4);
	} else {
		const yy = +s.slice(0, 2);
		y = yy < 50 ? 2000 + yy : 1900 + yy; // RFC 5280 UTCTime window
		rest = s.slice(2);
	}
	return Date.UTC(y, +rest.slice(0, 2) - 1, +rest.slice(2, 4), +rest.slice(4, 6), +rest.slice(6, 8), +rest.slice(8, 10));
}

// --- tiny encoder (OCSPRequest only) ---

function encLen(n: number): number[] {
	if (n < 0x80) return [n];
	const b: number[] = [];
	for (let x = n; x > 0; x >>= 8) b.unshift(x & 0xff);
	return [0x80 | b.length, ...b];
}

/** Tag-length-value: wrap `content` in `tag` + DER length. */
export function tlv(tag: number, content: Uint8Array): Uint8Array {
	const len = encLen(content.length);
	const out = new Uint8Array(1 + len.length + content.length);
	out[0] = tag;
	out.set(len, 1);
	out.set(content, 1 + len.length);
	return out;
}

/** SEQUENCE of the given (already-encoded) elements. */
export function seq(...parts: Uint8Array[]): Uint8Array {
	let total = 0;
	for (const p of parts) total += p.length;
	const content = new Uint8Array(total);
	let o = 0;
	for (const p of parts) {
		content.set(p, o);
		o += p.length;
	}
	return tlv(0x30, content);
}

/** OCTET STRING. */
export const octet = (content: Uint8Array): Uint8Array => tlv(0x04, content);
