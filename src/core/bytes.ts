// Big-endian read/write for TLS records & handshake. Length prefixes are
// 8/16/24-bit (TLS uses u24 for handshake length and some lists).

export class Writer {
	private chunks: Uint8Array[] = [];
	u8(v: number): this {
		this.chunks.push(Uint8Array.of(v & 0xff));
		return this;
	}
	u16(v: number): this {
		this.chunks.push(Uint8Array.of((v >>> 8) & 0xff, v & 0xff));
		return this;
	}
	u24(v: number): this {
		this.chunks.push(Uint8Array.of((v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff));
		return this;
	}
	u32(v: number): this {
		this.chunks.push(Uint8Array.of((v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff));
		return this;
	}
	bytes(b: Uint8Array): this {
		this.chunks.push(b);
		return this;
	}
	/** Write a sub-block, prefixed by its length in `n` bytes (1/2/3). */
	block(n: 1 | 2 | 3, fn: (w: Writer) => void): this {
		const inner = new Writer();
		fn(inner);
		const body = inner.build();
		if (n === 1) this.u8(body.length);
		else if (n === 2) this.u16(body.length);
		else this.u24(body.length);
		this.chunks.push(body);
		return this;
	}
	build(): Uint8Array {
		return concat(...this.chunks);
	}
}

export class Reader {
	off = 0;
	constructor(public buf: Uint8Array) {}
	get rem(): number {
		return this.buf.length - this.off;
	}
	u8(): number {
		return this.buf[this.off++]!;
	}
	u16(): number {
		const v = (this.buf[this.off]! << 8) | this.buf[this.off + 1]!;
		this.off += 2;
		return v;
	}
	u24(): number {
		const v = (this.buf[this.off]! << 16) | (this.buf[this.off + 1]! << 8) | this.buf[this.off + 2]!;
		this.off += 3;
		return v;
	}
	u32(): number {
		const v = this.buf[this.off]! * 0x1000000 + ((this.buf[this.off + 1]! << 16) | (this.buf[this.off + 2]! << 8) | this.buf[this.off + 3]!);
		this.off += 4;
		return v; // unsigned
	}
	bytes(n: number): Uint8Array {
		const v = this.buf.subarray(this.off, this.off + n);
		this.off += n;
		return v;
	}
	/** Read a sub-block whose length is prefixed by `n` bytes. */
	block(n: 1 | 2 | 3): Reader {
		const len = n === 1 ? this.u8() : n === 2 ? this.u16() : this.u24();
		return new Reader(this.bytes(len));
	}
}

export function concat(...arrs: Uint8Array[]): Uint8Array {
	let len = 0;
	for (const a of arrs) len += a.length;
	const out = new Uint8Array(len);
	let o = 0;
	for (const a of arrs) {
		out.set(a, o);
		o += a.length;
	}
	return out;
}

export const hex = (b: Uint8Array): string => Buffer.from(b).toString('hex');
export const fromHex = (s: string): Uint8Array => new Uint8Array(Buffer.from(s.replace(/\s+/g, ''), 'hex'));
