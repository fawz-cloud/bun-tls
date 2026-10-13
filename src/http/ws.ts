// WebSocket (RFC 6455) over the fingerprinted TLS channel — so live/socket traffic carries
// the same JA3/JA4 + header identity as the rest of the session (anti-bot WAFs fingerprint
// the WS upgrade too). wss:// only (plain ws has no TLS to fingerprint). Opens with an
// HTTP/1.1 Upgrade, verifies Sec-WebSocket-Accept, then speaks the frame protocol.
import crypto from 'node:crypto';
import { openConnection, type OpenOptions } from './client';
import { modern } from '../fp/fingerprints';
import { resolvePersona, personaHeaders } from '../fp/personas';
import type { Persona } from '../fp/personas';
import type { Fingerprint } from '../tls/clienthello';
import type { TlsConn } from '../tls/handshake';
import { concat } from '../core/bytes';

const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

export interface WsOptions {
	persona?: string | Persona;
	fingerprint?: Fingerprint;
	headers?: Record<string, string>;
	proxy?: string;
	verify?: boolean;
	/** Subprotocols → Sec-WebSocket-Protocol. */
	protocols?: string[];
	timeoutMs?: number;
}

export interface WsMessage {
	data: string | Uint8Array;
	binary: boolean;
}

/** Open a WebSocket over bun-tls. Resolves once the server returns 101 + a valid accept. */
export async function connectWebSocket(url: string, opts: WsOptions = {}): Promise<BunTlsWebSocket> {
	const u = new URL(url);
	if (u.protocol !== 'wss:') throw new Error('bun-tls WebSocket: only wss:// is supported');
	const host = u.hostname;
	const port = u.port ? Number(u.port) : 443;
	const P = opts.persona ? resolvePersona(opts.persona) : null;
	const open: OpenOptions = { host, port, proxy: opts.proxy, fingerprint: opts.fingerprint ?? P?.fingerprint() ?? modern(), verify: opts.verify, timeoutMs: opts.timeoutMs };
	const tls = await openConnection(open);

	const key = crypto.randomBytes(16).toString('base64');
	const headers: Record<string, string> = {
		Host: u.port ? `${host}:${u.port}` : host,
		...(P ? personaHeaders(P) : { 'User-Agent': 'bun-tls/0.1' }),
		Upgrade: 'websocket',
		Connection: 'Upgrade',
		'Sec-WebSocket-Key': key,
		'Sec-WebSocket-Version': '13',
		...(opts.protocols?.length ? { 'Sec-WebSocket-Protocol': opts.protocols.join(', ') } : {}),
		...(opts.headers ?? {})
	};
	const head = [`GET ${u.pathname + u.search || '/'} HTTP/1.1`, ...Object.entries(headers).map(([k, v]) => `${k}: ${v}`)].join('\r\n') + '\r\n\r\n';
	tls.writeApp(new Uint8Array(Buffer.from(head)));

	// Read the 101 handshake response.
	let buf: Uint8Array = new Uint8Array(0);
	let end = -1;
	while (end < 0) {
		const c = await tls.readApp();
		if (c === null) {
			tls.close();
			throw new Error('WebSocket: connection closed during handshake');
		}
		buf = buf.length ? concat(buf, c) : c;
		end = headEnd(buf);
	}
	const headStr = Buffer.from(buf.subarray(0, end)).toString('latin1');
	const status = /^HTTP\/1\.1 (\d{3})/.exec(headStr);
	if (!status || status[1] !== '101') {
		tls.close();
		throw new Error('WebSocket upgrade failed: ' + headStr.split('\r\n')[0]);
	}
	const accept = /sec-websocket-accept:\s*(.+)\r?\n?/i.exec(headStr)?.[1]?.trim();
	const expect = crypto.createHash('sha1').update(key + GUID).digest('base64');
	if (accept !== expect) {
		tls.close();
		throw new Error('WebSocket: bad Sec-WebSocket-Accept');
	}
	return new BunTlsWebSocket(tls, buf.subarray(end + 4), { ja3: tls.ja3, ja3Hash: tls.ja3Hash, ja4: tls.ja4 });
}

const headEnd = (b: Uint8Array): number => {
	for (let i = 0; i + 3 < b.length; i++) if (b[i] === 13 && b[i + 1] === 10 && b[i + 2] === 13 && b[i + 3] === 10) return i;
	return -1;
};

type Frame = { fin: boolean; opcode: number; payload: Uint8Array };

export class BunTlsWebSocket {
	closed = false;
	private inbox: WsMessage[] = [];
	private waiter: ((m: IteratorResult<WsMessage>) => void) | null = null;
	private frag: Uint8Array[] = [];
	private fragBinary = false;

	constructor(
		private tls: TlsConn,
		private leftover: Uint8Array,
		readonly fp: { ja3: string; ja3Hash: string; ja4: string }
	) {
		void this.readLoop();
	}

	/** Send a text (string) or binary (Uint8Array) message. Client frames are masked. */
	send(data: string | Uint8Array): void {
		if (this.closed) throw new Error('WebSocket is closed');
		const binary = typeof data !== 'string';
		const payload = binary ? (data as Uint8Array) : new Uint8Array(Buffer.from(data as string));
		this.tls.writeApp(encodeFrame(binary ? 0x2 : 0x1, payload));
	}

	/** Async iterator over incoming messages; ends when the socket closes. */
	async *messages(): AsyncIterableIterator<WsMessage> {
		for (;;) {
			if (this.inbox.length) {
				yield this.inbox.shift()!;
				continue;
			}
			if (this.closed) return;
			const m = await new Promise<IteratorResult<WsMessage>>((res) => (this.waiter = res));
			if (m.done) return;
			yield m.value;
		}
	}

	close(code = 1000, reason = ''): void {
		if (this.closed) return;
		this.closed = true;
		const r = Buffer.from(reason);
		const body = concat(Uint8Array.of((code >> 8) & 0xff, code & 0xff), new Uint8Array(r));
		try {
			this.tls.writeApp(encodeFrame(0x8, body));
		} catch {
			/* already gone */
		}
		this.finish();
	}

	private push(m: WsMessage): void {
		if (this.waiter) {
			const w = this.waiter;
			this.waiter = null;
			w({ value: m, done: false });
		} else this.inbox.push(m);
	}
	private finish(): void {
		this.closed = true;
		try {
			this.tls.close();
		} catch {
			/* already gone */
		}
		if (this.waiter) {
			const w = this.waiter;
			this.waiter = null;
			w({ value: undefined, done: true });
		}
	}

	private async readLoop(): Promise<void> {
		let buf = this.leftover;
		const next = async (): Promise<boolean> => {
			const c = await this.tls.readApp();
			if (c === null) return false;
			buf = buf.length ? concat(buf, c) : c;
			return true;
		};
		for (;;) {
			const f = parseFrame(buf);
			if (!f) {
				if (await next()) continue;
				this.finish();
				return;
			}
			buf = f.rest;
			const fr = f.frame;
			if (fr.opcode === 0x8) {
				// close: echo and end
				if (!this.closed) {
					try {
						this.tls.writeApp(encodeFrame(0x8, fr.payload));
					} catch {
						/* gone */
					}
				}
				this.finish();
				return;
			} else if (fr.opcode === 0x9) {
				try {
					this.tls.writeApp(encodeFrame(0xa, fr.payload)); // ping → pong
				} catch {
					/* gone */
				}
			} else if (fr.opcode === 0xa) {
				/* pong — ignore */
			} else if (fr.opcode === 0x1 || fr.opcode === 0x2 || fr.opcode === 0x0) {
				if (fr.opcode !== 0x0) this.fragBinary = fr.opcode === 0x2;
				this.frag.push(fr.payload);
				if (fr.fin) {
					const full = concat(...this.frag);
					this.frag = [];
					this.push({ data: this.fragBinary ? full : Buffer.from(full).toString('utf8'), binary: this.fragBinary });
				}
			}
		}
	}
}

/** Encode a client frame (FIN set, always masked per RFC 6455 §5.3). */
function encodeFrame(opcode: number, payload: Uint8Array): Uint8Array {
	const len = payload.length;
	const mask = crypto.randomBytes(4);
	let header: number[] = [0x80 | opcode];
	if (len < 126) header.push(0x80 | len);
	else if (len < 65536) header.push(0x80 | 126, (len >> 8) & 0xff, len & 0xff);
	else header.push(0x80 | 127, 0, 0, 0, 0, (len >>> 24) & 0xff, (len >>> 16) & 0xff, (len >>> 8) & 0xff, len & 0xff);
	const masked = new Uint8Array(len);
	for (let i = 0; i < len; i++) masked[i] = payload[i]! ^ mask[i & 3]!;
	return concat(new Uint8Array(header), new Uint8Array(mask), masked);
}

/** Parse one server frame from `buf`; null if incomplete. Server frames are not masked. */
function parseFrame(buf: Uint8Array): { frame: Frame; rest: Uint8Array } | null {
	if (buf.length < 2) return null;
	const fin = (buf[0]! & 0x80) !== 0;
	const opcode = buf[0]! & 0x0f;
	const masked = (buf[1]! & 0x80) !== 0;
	let len = buf[1]! & 0x7f;
	let off = 2;
	if (len === 126) {
		if (buf.length < 4) return null;
		len = (buf[2]! << 8) | buf[3]!;
		off = 4;
	} else if (len === 127) {
		if (buf.length < 10) return null;
		len = Number((BigInt(buf[2]!) << 56n) | (BigInt(buf[3]!) << 48n) | (BigInt(buf[4]!) << 40n) | (BigInt(buf[5]!) << 32n) | (BigInt(buf[6]!) << 24n) | (BigInt(buf[7]!) << 16n) | (BigInt(buf[8]!) << 8n) | BigInt(buf[9]!));
		off = 10;
	}
	const maskKey = masked ? buf.subarray(off, off + 4) : null;
	if (masked) off += 4;
	if (buf.length < off + len) return null;
	let payload = buf.subarray(off, off + len);
	if (maskKey) {
		const u = new Uint8Array(len);
		for (let i = 0; i < len; i++) u[i] = payload[i]! ^ maskKey[i & 3]!;
		payload = u;
	}
	return { frame: { fin, opcode, payload }, rest: buf.subarray(off + len) };
}
