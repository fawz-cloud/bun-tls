// QUIC variable-length integers (RFC 9000 §16): the 2 MSBs of the first byte give the
// length (1/2/4/8 bytes), the remaining 62 bits are the value.
export function readVarint(b: Uint8Array, off: number): { value: number; len: number } {
	const first = b[off]!;
	const len = 1 << (first >> 6); // 00→1, 01→2, 10→4, 11→8
	let v = first & 0x3f;
	for (let i = 1; i < len; i++) v = v * 256 + b[off + i]!;
	return { value: v, len };
}

export function writeVarint(v: number): Uint8Array {
	if (v < 0x40) return Uint8Array.of(v);
	if (v < 0x4000) return Uint8Array.of(0x40 | (v >> 8), v & 0xff);
	if (v < 0x40000000) return Uint8Array.of(0x80 | (v >>> 24), (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff);
	// 8-byte form (value fits in JS safe integer range for our use)
	const hi = Math.floor(v / 0x100000000);
	const lo = v >>> 0;
	return Uint8Array.of(0xc0 | ((hi >> 24) & 0x3f), (hi >> 16) & 0xff, (hi >> 8) & 0xff, hi & 0xff, (lo >>> 24) & 0xff, (lo >>> 16) & 0xff, (lo >>> 8) & 0xff, lo & 0xff);
}

if (import.meta.main) {
	const cases: [number, string][] = [
		[0, '00'], [37, '25'], [15293, '7bbd'], [494878333, '9d7f3e7d']
	];
	for (const [v, hex] of cases) {
		const enc = Buffer.from(writeVarint(v)).toString('hex');
		if (enc !== hex) throw new Error(`varint ${v}: got ${enc} want ${hex}`);
		const dec = readVarint(writeVarint(v), 0);
		if (dec.value !== v) throw new Error(`varint roundtrip ${v}: got ${dec.value}`);
	}
	console.log('quic varint ok');
}
