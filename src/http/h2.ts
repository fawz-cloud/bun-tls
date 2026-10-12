// Minimal HTTP/2 client (RFC 9113 + HPACK RFC 7541) over an established TLS channel
// (ALPN "h2"). One request/response per connection (a single stream): preface,
// SETTINGS, HEADERS (+ DATA for a body), then read frames until the stream ends.
// HPACK: full decode (static + dynamic table + Huffman); encode is literal-without-
// indexing, no Huffman (valid, simplest). Enough to GET/POST over h2 and read the
// real h2 ALPN; not a multiplexing pool.
import type { TlsConn } from '../tls/handshake';
import type { HttpResponse } from './http1';
import { concat } from '../core/bytes';
import zlib from 'node:zlib';

// ── HPACK static table (RFC 7541 Appendix A), index 1..61 ──────────────────────
const STATIC: [string, string][] = [
	['', ''], [':authority', ''], [':method', 'GET'], [':method', 'POST'], [':path', '/'],
	[':path', '/index.html'], [':scheme', 'http'], [':scheme', 'https'], [':status', '200'],
	[':status', '204'], [':status', '206'], [':status', '304'], [':status', '400'], [':status', '404'],
	[':status', '500'], ['accept-charset', ''], ['accept-encoding', 'gzip, deflate'], ['accept-language', ''],
	['accept-ranges', ''], ['accept', ''], ['access-control-allow-origin', ''], ['age', ''], ['allow', ''],
	['authorization', ''], ['cache-control', ''], ['content-disposition', ''], ['content-encoding', ''],
	['content-language', ''], ['content-length', ''], ['content-location', ''], ['content-range', ''],
	['content-type', ''], ['cookie', ''], ['date', ''], ['etag', ''], ['expect', ''], ['expires', ''],
	['from', ''], ['host', ''], ['if-match', ''], ['if-modified-since', ''], ['if-none-match', ''],
	['if-range', ''], ['if-unmodified-since', ''], ['last-modified', ''], ['link', ''], ['location', ''],
	['max-forwards', ''], ['proxy-authenticate', ''], ['proxy-authorization', ''], ['range', ''],
	['referer', ''], ['refresh', ''], ['retry-after', ''], ['server', ''], ['set-cookie', ''],
	['strict-transport-security', ''], ['transfer-encoding', ''], ['user-agent', ''], ['vary', ''],
	['via', ''], ['www-authenticate', '']
];

// ── HPACK Huffman decode table (RFC 7541 Appendix B) ───────────────────────────
// "sym hex bits" for sym 0..256 (256 = EOS). Built into a per-length code→sym map.
const HUFF =
	'1ff8:13 7fffd8:23 fffffe2:28 fffffe3:28 fffffe4:28 fffffe5:28 fffffe6:28 fffffe7:28 fffffe8:28 ffffea:24 3ffffffc:30 fffffe9:28 fffffea:28 3ffffffd:30 fffffeb:28 fffffec:28 fffffed:28 fffffee:28 fffffef:28 ffffff0:28 ffffff1:28 ffffff2:28 3ffffffe:30 ffffff3:28 ffffff4:28 ffffff5:28 ffffff6:28 ffffff7:28 ffffff8:28 ffffff9:28 ffffffa:28 ffffffb:28 14:6 3f8:10 3f9:10 ffa:12 1ff9:13 15:6 f8:8 7fa:11 3fa:10 3fb:10 f9:8 7fb:11 fa:8 16:6 17:6 18:6 0:5 1:5 2:5 19:6 1a:6 1b:6 1c:6 1d:6 1e:6 1f:6 5c:7 fb:8 7ffc:15 20:6 ffb:12 3fc:10 1ffa:13 21:6 5d:7 5e:7 5f:7 60:7 61:7 62:7 63:7 64:7 65:7 66:7 67:7 68:7 69:7 6a:7 6b:7 6c:7 6d:7 6e:7 6f:7 70:7 71:7 72:7 fc:8 73:7 fd:8 1ffb:13 7fff0:19 1ffc:13 3ffc:14 22:6 7ffd:15 3:5 23:6 4:5 24:6 5:5 25:6 26:6 27:6 6:5 74:7 75:7 28:6 29:6 2a:6 7:5 2b:6 76:7 2c:6 8:5 9:5 2d:6 77:7 78:7 79:7 7a:7 7b:7 7ffe:15 7fc:11 3ffd:14 1ffd:13 ffffffc:28 fffe6:20 3fffd2:22 fffe7:20 fffe8:20 3fffd3:22 3fffd4:22 3fffd5:22 7fffd9:23 3fffd6:22 7fffda:23 7fffdb:23 7fffdc:23 7fffdd:23 7fffde:23 ffffeb:24 7fffdf:23 ffffec:24 ffffed:24 3fffd7:22 7fffe0:23 ffffee:24 7fffe1:23 7fffe2:23 7fffe3:23 7fffe4:23 1fffdc:21 3fffd8:22 7fffe5:23 3fffd9:22 7fffe6:23 7fffe7:23 ffffef:24 3fffda:22 1fffdd:21 fffe9:20 3fffdb:22 3fffdc:22 7fffe8:23 7fffe9:23 1fffde:21 7fffea:23 3fffdd:22 3fffde:22 fffff0:24 1fffdf:21 3fffdf:22 7fffeb:23 7fffec:23 1fffe0:21 1fffe1:21 3fffe0:22 1fffe2:21 7fffed:23 3fffe1:22 7fffee:23 7fffef:23 fffea:20 3fffe2:22 3fffe3:22 3fffe4:22 7ffff0:23 3fffe5:22 3fffe6:22 7ffff1:23 3ffffe0:26 3ffffe1:26 fffeb:20 7fff1:19 3fffe7:22 7ffff2:23 3fffe8:22 1ffffec:25 3ffffe2:26 3ffffe3:26 3ffffe4:26 7ffffde:27 7ffffdf:27 3ffffe5:26 fffff1:24 1ffffed:25 7fff2:19 1fffe3:21 3ffffe6:26 7ffffe0:27 7ffffe1:27 3ffffe7:26 7ffffe2:27 fffff2:24 1fffe4:21 1fffe5:21 3ffffe8:26 3ffffe9:26 ffffffd:28 7ffffe3:27 7ffffe4:27 7ffffe5:27 fffec:20 fffff3:24 fffed:20 1fffe6:21 3fffe9:22 1fffe7:21 1fffe8:21 7ffff3:23 3fffea:22 3fffeb:22 1ffffee:25 1ffffef:25 fffff4:24 fffff5:24 3ffffea:26 7ffff4:23 3ffffeb:26 7ffffe6:27 3ffffec:26 3ffffed:26 7ffffe7:27 7ffffe8:27 7ffffe9:27 7ffffea:27 7ffffeb:27 ffffffe:28 7ffffec:27 7ffffed:27 7ffffee:27 7ffffef:27 7fffff0:27 3ffffee:26 3fffffff:30';

const huffByLen = new Map<number, Map<number, number>>();
HUFF.split(' ').forEach((tok, sym) => {
	if (sym > 255) return; // 256 = EOS, only appears as padding
	const [hex, bits] = tok.split(':');
	const len = Number(bits);
	let m = huffByLen.get(len);
	if (!m) huffByLen.set(len, (m = new Map()));
	m.set(parseInt(hex!, 16), sym);
});

function huffmanDecode(b: Uint8Array): string {
	// Accumulate the whole bitstream (header strings are short) then decode MSB-first.
	let acc = 0n;
	let n = 0n;
	for (const byte of b) {
		acc = (acc << 8n) | BigInt(byte);
		n += 8n;
	}
	const out: number[] = [];
	while (n > 0n) {
		// Final ≤7 all-ones bits are EOS padding (RFC 7541 §5.2) — stop, don't decode them.
		if (n <= 7n && acc === (1n << n) - 1n) break;
		let matched = false;
		for (let len = 5; len <= 30 && BigInt(len) <= n; len++) {
			const code = Number((acc >> (n - BigInt(len))) & ((1n << BigInt(len)) - 1n));
			const sym = huffByLen.get(len)?.get(code);
			if (sym !== undefined) {
				out.push(sym);
				n -= BigInt(len);
				acc &= (1n << n) - 1n;
				matched = true;
				break;
			}
		}
		if (!matched) break; // leftover that is neither a code nor valid padding
	}
	return Buffer.from(out).toString('latin1');
}

// ── HPACK decoder (with dynamic table) ─────────────────────────────────────────
class Hpack {
	private dyn: [string, string][] = [];
	private size = 0;
	private maxSize = 4096;

	private get(index: number): [string, string] {
		if (index >= 1 && index <= 61) return STATIC[index]!;
		const d = this.dyn[index - 62];
		if (!d) throw new Error('hpack: bad index ' + index);
		return d;
	}
	private add(name: string, value: string): void {
		this.dyn.unshift([name, value]);
		this.size += name.length + value.length + 32;
		while (this.size > this.maxSize && this.dyn.length) {
			const [n, v] = this.dyn.pop()!;
			this.size -= n.length + v.length + 32;
		}
	}

	decode(buf: Uint8Array): [string, string][] {
		const out: [string, string][] = [];
		let p = 0;
		const int = (prefix: number): number => {
			const mask = (1 << prefix) - 1;
			let v = buf[p]! & mask;
			p++;
			if (v < mask) return v;
			let m = 0;
			let b: number;
			do {
				b = buf[p++]!;
				v += (b & 0x7f) * 2 ** m;
				m += 7;
			} while (b & 0x80);
			return v;
		};
		const str = (): string => {
			const huff = (buf[p]! & 0x80) !== 0;
			const len = int(7);
			const raw = buf.subarray(p, p + len);
			p += len;
			return huff ? huffmanDecode(raw) : Buffer.from(raw).toString('latin1');
		};
		while (p < buf.length) {
			const b = buf[p]!;
			if (b & 0x80) {
				// 6.1 indexed header field
				out.push(this.get(int(7)));
			} else if (b & 0x40) {
				// 6.2.1 literal with incremental indexing
				const idx = int(6);
				const name = idx === 0 ? str() : this.get(idx)[0];
				const value = str();
				this.add(name, value);
				out.push([name, value]);
			} else if (b & 0x20) {
				// 6.3 dynamic table size update
				this.maxSize = int(5);
				while (this.size > this.maxSize && this.dyn.length) {
					const [n, v] = this.dyn.pop()!;
					this.size -= n.length + v.length + 32;
				}
			} else {
				// 6.2.2 / 6.2.3 literal without indexing (or never-indexed)
				const idx = int(4);
				const name = idx === 0 ? str() : this.get(idx)[0];
				out.push([name, str()]);
			}
		}
		return out;
	}
}

// ── HPACK encode: literal without indexing, no Huffman (RFC 7541 §6.2.2) ────────
function encStr(s: string): Uint8Array {
	const bytes = Buffer.from(s, 'latin1');
	const head = encInt(bytes.length, 7, 0); // H=0
	return concat(head, new Uint8Array(bytes));
}
function encInt(value: number, prefix: number, highBits: number): Uint8Array {
	const mask = (1 << prefix) - 1;
	if (value < mask) return Uint8Array.of(highBits | value);
	const out = [highBits | mask];
	value -= mask;
	while (value >= 128) {
		out.push((value & 0x7f) | 0x80);
		value >>= 7;
	}
	out.push(value);
	return Uint8Array.of(...out);
}
function encodeHeaders(headers: [string, string][]): Uint8Array {
	const parts: Uint8Array[] = [];
	for (const [name, value] of headers) {
		parts.push(Uint8Array.of(0x00)); // literal, no indexing, new name
		parts.push(encStr(name.toLowerCase()));
		parts.push(encStr(value));
	}
	return concat(...parts);
}

// ── Frame layer ────────────────────────────────────────────────────────────────
const FRAME = { DATA: 0, HEADERS: 1, RST_STREAM: 3, SETTINGS: 4, PING: 6, GOAWAY: 7, WINDOW_UPDATE: 8, CONTINUATION: 9 } as const;
const F_END_STREAM = 0x1;
const F_END_HEADERS = 0x4;
const F_ACK = 0x1;

function frame(type: number, flags: number, streamId: number, payload: Uint8Array): Uint8Array {
	const h = new Uint8Array(9);
	const len = payload.length;
	h[0] = (len >> 16) & 0xff;
	h[1] = (len >> 8) & 0xff;
	h[2] = len & 0xff;
	h[3] = type;
	h[4] = flags;
	h[5] = (streamId >> 24) & 0x7f;
	h[6] = (streamId >> 16) & 0xff;
	h[7] = (streamId >> 8) & 0xff;
	h[8] = streamId & 0xff;
	return concat(h, payload);
}

interface Frame {
	type: number;
	flags: number;
	streamId: number;
	payload: Uint8Array;
}

/** Pulls complete frames from the TLS app-data stream. */
class FrameReader {
	private buf: Uint8Array = new Uint8Array(0);
	constructor(private read: () => Promise<Uint8Array | null>) {}
	async next(): Promise<Frame | null> {
		for (;;) {
			if (this.buf.length >= 9) {
				const len = (this.buf[0]! << 16) | (this.buf[1]! << 8) | this.buf[2]!;
				if (this.buf.length >= 9 + len) {
					const type = this.buf[3]!;
					const flags = this.buf[4]!;
					const streamId = ((this.buf[5]! & 0x7f) << 24) | (this.buf[6]! << 16) | (this.buf[7]! << 8) | this.buf[8]!;
					const payload = this.buf.subarray(9, 9 + len);
					this.buf = this.buf.subarray(9 + len);
					return { type, flags, streamId, payload };
				}
			}
			const chunk = await this.read();
			if (chunk === null) return null;
			this.buf = this.buf.length ? concat(this.buf, chunk) : chunk;
		}
	}
}

const PREFACE = new Uint8Array(Buffer.from('PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n', 'latin1'));

export interface H2Request {
	method: string;
	authority: string; // host[:port]
	path: string;
	headers: Record<string, string>;
	body?: Uint8Array;
}

/** The h2-level fingerprint knobs: SETTINGS (id,value in order) and the opening connection
 *  WINDOW_UPDATE increment. These, with the pseudo-header order, form the "Akamai" h2
 *  fingerprint. The default matches Chrome: `1:65536,2:0,4:6291456,6:262144|15663105|...|m,a,s,p`. */
export interface H2Profile {
	settings: [number, number][];
	connWindowUpdate: number;
}
export const CHROME_H2: H2Profile = {
	settings: [
		[1, 65536], // HEADER_TABLE_SIZE
		[2, 0], // ENABLE_PUSH
		[4, 6291456], // INITIAL_WINDOW_SIZE
		[6, 262144] // MAX_HEADER_LIST_SIZE
	],
	connWindowUpdate: 15663105
};

const readU32 = (b: Uint8Array): number => b[0]! * 0x1000000 + ((b[1]! << 16) | (b[2]! << 8) | b[3]!);
const u32 = (n: number): Uint8Array => Uint8Array.of((n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);

function decompressBody(body: Uint8Array, enc: string | string[] | undefined): Uint8Array {
	const e = (Array.isArray(enc) ? enc.join(',') : enc ?? '').toLowerCase();
	try {
		if (e.includes('zstd') && typeof zlib.zstdDecompressSync === 'function') return new Uint8Array(zlib.zstdDecompressSync(body));
		if (e.includes('br')) return new Uint8Array(zlib.brotliDecompressSync(body));
		if (e.includes('gzip')) return new Uint8Array(zlib.gunzipSync(body));
		if (e.includes('deflate')) return new Uint8Array(zlib.inflateSync(body));
	} catch {
		/* not compressed / corrupt → as-is */
	}
	return body;
}

interface H2Stream {
	headerBytes: Uint8Array;
	bodyParts: Uint8Array[];
	status: number;
	respHeaders: [string, string][];
	recv: number; // bytes received since our last WINDOW_UPDATE
	sendWindow: number; // peer's flow window for our DATA on this stream
	done: boolean;
	settle: (r: HttpResponse) => void;
	fail: (e: Error) => void;
}

/** A persistent HTTP/2 connection: one preface + SETTINGS, then many concurrent streams
 *  multiplexed over the single TLS channel. One shared HPACK decoder (the dynamic table is
 *  connection-wide and order-sensitive) + one read loop dispatching frames by stream id. */
export class H2Connection {
	private nextId = 1; // client streams are odd
	private streams = new Map<number, H2Stream>();
	private hpack = new Hpack();
	private connSendWindow = 65535; // our DATA budget at the connection level
	private peerInitialWindow = 65535; // peer SETTINGS_INITIAL_WINDOW_SIZE → initial stream sendWindow
	private windowWaiters: (() => void)[] = [];
	private goawayLast = Infinity;
	closed = false;

	constructor(private tls: TlsConn) {}

	/** Send the preface, our SETTINGS and the opening WINDOW_UPDATE, then start reading. */
	init(profile: H2Profile = CHROME_H2): void {
		const settings = new Uint8Array(profile.settings.length * 6);
		const sv = new DataView(settings.buffer);
		profile.settings.forEach(([id, val], i) => {
			sv.setUint16(i * 6, id);
			sv.setUint32(i * 6 + 2, val >>> 0);
		});
		this.tls.writeApp(concat(PREFACE, frame(FRAME.SETTINGS, 0, 0, settings), frame(FRAME.WINDOW_UPDATE, 0, 0, u32(profile.connWindowUpdate))));
		void this.readLoop();
	}

	/** Open a new stream for one request; resolves when that stream ends. Safe to call
	 *  many times concurrently — the requests multiplex over the one connection. */
	request(req: H2Request): Promise<HttpResponse> {
		if (this.closed) return Promise.reject(new Error('h2: connection is closed'));
		const id = this.nextId;
		this.nextId += 2;
		if (id > this.goawayLast) return Promise.reject(new Error('h2: server sent GOAWAY, open a new connection'));
		const st: H2Stream = { headerBytes: new Uint8Array(0), bodyParts: [], status: 0, respHeaders: [], recv: 0, sendWindow: this.peerInitialWindow, done: false, settle: () => {}, fail: () => {} };
		this.streams.set(id, st);
		const hdrs: [string, string][] = [
			[':method', req.method],
			[':authority', req.authority],
			[':scheme', 'https'],
			[':path', req.path]
		];
		for (const [k, v] of Object.entries(req.headers)) {
			const lk = k.toLowerCase();
			if (lk === 'host' || lk === 'connection' || lk === 'transfer-encoding' || lk === 'keep-alive' || lk === 'upgrade') continue;
			hdrs.push([lk, v]);
		}
		const hasBody = !!(req.body && req.body.length);
		this.tls.writeApp(frame(FRAME.HEADERS, F_END_HEADERS | (hasBody ? 0 : F_END_STREAM), id, encodeHeaders(hdrs)));
		const p = new Promise<HttpResponse>((res, rej) => {
			st.settle = res;
			st.fail = rej;
		});
		if (hasBody) void this.sendBody(id, st, req.body!);
		return p;
	}

	/** Stream a request body, respecting connection + stream flow-control windows. */
	private async sendBody(id: number, st: H2Stream, body: Uint8Array): Promise<void> {
		let off = 0;
		while (off < body.length && !this.closed) {
			const avail = Math.min(this.connSendWindow, st.sendWindow, 16384);
			if (avail <= 0) {
				await new Promise<void>((r) => this.windowWaiters.push(r));
				continue;
			}
			const n = Math.min(avail, body.length - off);
			const last = off + n >= body.length;
			this.tls.writeApp(frame(FRAME.DATA, last ? F_END_STREAM : 0, id, body.subarray(off, off + n)));
			off += n;
			this.connSendWindow -= n;
			st.sendWindow -= n;
		}
	}

	private wakeWindow(): void {
		const w = this.windowWaiters;
		this.windowWaiters = [];
		for (const f of w) f();
	}

	private async readLoop(): Promise<void> {
		const fr = new FrameReader(() => this.tls.readApp());
		try {
			for (;;) {
				const f = await fr.next();
				if (f === null) return this.fatal(new Error('h2: connection closed'));
				this.onFrame(f);
				if (this.closed) return;
			}
		} catch (e) {
			this.fatal(e as Error);
		}
	}

	private onFrame(f: Frame): void {
		if (f.streamId === 0) {
			if (f.type === FRAME.SETTINGS && !(f.flags & F_ACK)) {
				this.applySettings(f.payload);
				this.tls.writeApp(frame(FRAME.SETTINGS, F_ACK, 0, new Uint8Array(0)));
			} else if (f.type === FRAME.PING && !(f.flags & F_ACK)) {
				this.tls.writeApp(frame(FRAME.PING, F_ACK, 0, f.payload));
			} else if (f.type === FRAME.WINDOW_UPDATE) {
				this.connSendWindow += readU32(f.payload);
				this.wakeWindow();
			} else if (f.type === FRAME.GOAWAY) {
				this.goawayLast = readU32(f.payload) & 0x7fffffff; // last stream the server will process
			}
			return;
		}
		const st = this.streams.get(f.streamId);
		if (!st) return; // unknown or already-finished stream
		if (f.type === FRAME.HEADERS || f.type === FRAME.CONTINUATION) {
			let pl = f.payload;
			let o = 0;
			let padLen = 0;
			if (f.type === FRAME.HEADERS && f.flags & 0x8) padLen = pl[o++]!; // padded
			if (f.type === FRAME.HEADERS && f.flags & 0x20) o += 5; // priority
			st.headerBytes = concat(st.headerBytes, pl.subarray(o, pl.length - padLen));
			if (f.flags & F_END_HEADERS) {
				st.respHeaders = this.hpack.decode(st.headerBytes);
				for (const [k, v] of st.respHeaders) if (k === ':status') st.status = Number(v);
			}
			if (f.flags & F_END_STREAM) this.finish(f.streamId, st);
		} else if (f.type === FRAME.DATA) {
			let pl = f.payload;
			let o = 0;
			let padLen = 0;
			if (f.flags & 0x8) padLen = pl[o++]!;
			st.bodyParts.push(pl.subarray(o, pl.length - padLen));
			st.recv += f.payload.length;
			if (st.recv >= 1 << 18) {
				this.tls.writeApp(frame(FRAME.WINDOW_UPDATE, 0, 0, u32(st.recv)));
				this.tls.writeApp(frame(FRAME.WINDOW_UPDATE, 0, f.streamId, u32(st.recv)));
				st.recv = 0;
			}
			if (f.flags & F_END_STREAM) this.finish(f.streamId, st);
		} else if (f.type === FRAME.WINDOW_UPDATE) {
			st.sendWindow += readU32(f.payload);
			this.wakeWindow();
		} else if (f.type === FRAME.RST_STREAM) {
			this.streams.delete(f.streamId);
			if (!st.done) {
				st.done = true;
				st.fail(new Error('h2: stream reset by server'));
			}
		}
	}

	private applySettings(payload: Uint8Array): void {
		for (let i = 0; i + 6 <= payload.length; i += 6) {
			const id = (payload[i]! << 8) | payload[i + 1]!;
			if (id === 0x4) {
				// INITIAL_WINDOW_SIZE: adjust every open stream's send window by the delta (RFC §6.9.2)
				const val = readU32(payload.subarray(i + 2));
				const delta = val - this.peerInitialWindow;
				this.peerInitialWindow = val;
				for (const s of this.streams.values()) s.sendWindow += delta;
				this.wakeWindow();
			}
		}
	}

	private finish(id: number, st: H2Stream): void {
		if (st.done) return;
		st.done = true;
		this.streams.delete(id);
		const headers: Record<string, string | string[]> = {};
		for (const [k, v] of st.respHeaders) {
			if (k.startsWith(':')) continue;
			const prev = headers[k];
			if (prev === undefined) headers[k] = v;
			else if (Array.isArray(prev)) prev.push(v);
			else headers[k] = [prev, v];
		}
		const body = decompressBody(concat(...st.bodyParts), headers['content-encoding']);
		st.settle({
			status: st.status,
			statusText: '',
			headers,
			body,
			reusable: true,
			text: () => Buffer.from(body).toString('utf8'),
			json: <T>() => JSON.parse(Buffer.from(body).toString('utf8')) as T
		});
	}

	private fatal(e: Error): void {
		this.closed = true;
		this.wakeWindow();
		for (const st of this.streams.values())
			if (!st.done) {
				st.done = true;
				st.fail(e);
			}
		this.streams.clear();
	}

	close(): void {
		this.closed = true;
		try {
			this.tls.close();
		} catch {
			/* already gone */
		}
		this.fatal(new Error('h2: connection closed'));
	}
}

/** One-shot HTTP/2 request (opens a connection, one stream). The caller owns `tls` and
 *  closes it afterwards. For connection reuse / multiplexing use H2Connection via Session. */
export async function h2Request(tls: TlsConn, req: H2Request, profile: H2Profile = CHROME_H2): Promise<HttpResponse> {
	const conn = new H2Connection(tls);
	conn.init(profile);
	return conn.request(req);
}
