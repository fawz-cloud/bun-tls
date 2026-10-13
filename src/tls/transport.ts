// Transport = raw byte stream. TCP via Bun.connect (wrapped as async
// read()/write()). HTTP proxy CONNECT included. The handshake & record layers
// don't know whether this is a socket/proxy/mock — easy to test with a mock.
import { lookup } from 'node:dns/promises';
import { concat } from '../core/bytes';

export interface Transport {
	write(b: Uint8Array): void;
	/** Write and resolve once the kernel has accepted everything queued (backpressure-aware).
	 *  Awaiting it between chunks yields to the event loop, so the peer reads while we
	 *  prepare the next chunk — lets a large upload pipeline instead of blocking. */
	writeAsync(b: Uint8Array): Promise<void>;
	/** null = EOF / closed. */
	read(): Promise<Uint8Array | null>;
	close(): void;
}

/** Settle with `p`, or reject with the signal's reason as soon as it aborts. A value that
 *  arrives after the abort goes to `onLate` (close it — nothing in flight may leak). */
function abortable<T>(p: Promise<T>, signal: AbortSignal | undefined, onLate?: (v: T) => void): Promise<T> {
	if (!signal) return p;
	if (signal.aborted) {
		p.then((v) => onLate?.(v), () => {});
		return Promise.reject(signal.reason);
	}
	return new Promise<T>((res, rej) => {
		const stop = () => {
			p.then((v) => onLate?.(v), () => {});
			rej(signal.reason);
		};
		signal.addEventListener('abort', stop, { once: true });
		p.then(
			(v) => {
				signal.removeEventListener('abort', stop);
				if (signal.aborted) onLate?.(v);
				else res(v);
			},
			(e) => {
				signal.removeEventListener('abort', stop);
				rej(signal.aborted ? signal.reason : e);
			}
		);
	});
}

/** While a proxy handshake runs on `conn`, an abort closes it (its pending read then sees EOF
 *  and the negotiation throws); returns the cleanup that detaches the listener. */
function closeOnAbort(conn: RawConn, signal: AbortSignal | undefined): () => void {
	if (!signal) return () => {};
	const stop = () => conn.close();
	signal.addEventListener('abort', stop, { once: true });
	return () => signal.removeEventListener('abort', stop);
}

// DNS cache: a fresh connection per request otherwise re-resolves the host every
// time (what curl avoids with its in-process cache). TTL 60s. IP literals skip it.
const dnsCache = new Map<string, { ip: string; exp: number }>();
async function resolveHost(host: string): Promise<string> {
	if (/^\d+\.\d+\.\d+\.\d+$/.test(host) || host.includes(':')) return host; // IPv4/IPv6 literal
	const now = Date.now();
	const hit = dnsCache.get(host);
	if (hit && hit.exp > now) return hit.ip;
	const { address } = await lookup(host);
	dnsCache.set(host, { ip: address, exp: now + 60_000 });
	return address;
}

/** Byte queue: pushed from the socket callback; read() awaits when empty. */
class ByteQueue {
	private chunks: (Uint8Array | null)[] = [];
	private waiter: ((v: Uint8Array | null) => void) | null = null;
	push(b: Uint8Array | null): void {
		if (this.waiter) {
			const w = this.waiter;
			this.waiter = null;
			w(b);
		} else {
			this.chunks.push(b);
		}
	}
	/** Put leftover bytes back at the front (after parsing CONNECT headers). */
	unshift(b: Uint8Array): void {
		if (b.length) this.chunks.unshift(b);
	}
	read(): Promise<Uint8Array | null> {
		if (this.chunks.length) return Promise.resolve(this.chunks.shift()!);
		return new Promise((res) => (this.waiter = res));
	}
}

interface RawConn extends Transport {
	q: ByteQueue;
}

interface BunSock {
	write(b: Uint8Array): number;
	end(): void;
	setNoDelay?(v: boolean): void;
}

async function rawConnect(host: string, port: number, signal?: AbortSignal): Promise<RawConn> {
	signal?.throwIfAborted();
	const q = new ByteQueue();
	let closed = false;
	// Outbound queue with backpressure: sock.write() returns the bytes accepted; the
	// rest must wait for `drain`. Ignoring this drops bytes on large writes (e.g. a
	// 10MB upload → hundreds of records) → the server sees a truncated body. FIFO.
	const outQ: Uint8Array[] = [];
	let drainWaiters: (() => void)[] = [];
	let sock!: BunSock;
	const flush = () => {
		while (outQ.length) {
			const b = outQ[0]!;
			const n = sock.write(b);
			if (n < b.length) {
				outQ[0] = b.subarray(n); // partial — keep remainder, resume on drain
				return;
			}
			outQ.shift();
		}
		// fully flushed → wake anyone awaiting backpressure relief
		if (drainWaiters.length) {
			const w = drainWaiters;
			drainWaiters = [];
			for (const f of w) f();
		}
	};
	const hostname = await abortable(resolveHost(host), signal);
	const connecting = Bun.connect({
		hostname,
		port,
		socket: {
			binaryType: 'uint8array',
			data(_s, data: Uint8Array) {
				// Bun hands each data() a fresh, exact-size buffer it never reuses (proven by
				// test/transport.test.ts), so we adopt it directly — no copy. RecordReader holds
				// views into these across awaits, which is safe exactly because they are not reused.
				q.push(data);
			},
			drain() {
				flush(); // socket writable again → push queued bytes, wake waiters
			},
			close() {
				if (!closed) {
					closed = true;
					q.push(null);
				}
			},
			error(_s, e) {
				q.push(null);
				console.error('[transport] socket error:', (e as Error)?.message ?? e);
			}
		}
	});
	// A connect still pending when the caller gives up is closed the moment it lands.
	sock = (await abortable(connecting, signal, (s) => s.end())) as unknown as BunSock;
	// Disable Nagle: our handshake/request writes are small and latency-sensitive;
	// Nagle + delayed-ACK can add tens of ms. (Guarded — older Bun may lack it.)
	sock.setNoDelay?.(true);
	return {
		q,
		write(b) {
			outQ.push(b);
			flush();
		},
		writeAsync(b) {
			outQ.push(b);
			flush();
			if (!outQ.length) return Promise.resolve(); // accepted immediately, no backpressure
			return new Promise<void>((res) => drainWaiters.push(res));
		},
		read: () => q.read(),
		close() {
			if (!closed) {
				closed = true;
				q.push(null); // wake any pending read() so a timeout/cancellation unblocks it
				try {
					sock.end();
				} catch {
					/* already closed */
				}
			}
		}
	};
}

/** TCP connect. `signal` aborts the DNS lookup + connect (a late socket is closed). */
export const tcpConnect = (host: string, port: number, signal?: AbortSignal): Promise<Transport> => rawConnect(host, port, signal);

/** Read exactly `n` bytes from a raw connection, buffering across chunks; any surplus is
 *  pushed back for the next reader. */
async function readExact(conn: RawConn, n: number): Promise<Uint8Array> {
	let buf: Uint8Array = new Uint8Array(0);
	while (buf.length < n) {
		const c = await conn.read();
		if (c === null) throw new Error('connection closed mid-read');
		buf = buf.length ? concat(buf, c) : c;
	}
	if (buf.length > n) conn.q.unshift(buf.subarray(n));
	return buf.subarray(0, n);
}

/** SOCKS5 proxy (RFC 1928, + RFC 1929 user/pass). The hostname is sent to the proxy to
 *  resolve (socks5h semantics). `proxyUrl` = socks5://[user:pass@]host:port. TLS on top. */
export async function socks5Connect(proxyUrl: string, targetHost: string, targetPort: number, signal?: AbortSignal): Promise<Transport> {
	const pu = new URL(proxyUrl);
	const conn = await rawConnect(pu.hostname, Number(pu.port || 1080), signal);
	const detach = closeOnAbort(conn, signal); // a proxy that never answers cannot hang the dial
	try {
	const user = pu.username ? decodeURIComponent(pu.username) : '';
	const pass = pu.password ? decodeURIComponent(pu.password) : '';
	// greeting: offer no-auth, plus user/pass when credentials are present
	const methods = user ? [0x00, 0x02] : [0x00];
	conn.write(Uint8Array.of(0x05, methods.length, ...methods));
	const sel = await readExact(conn, 2);
	if (sel[0] !== 0x05) throw new Error('socks5: unexpected version 0x' + sel[0]!.toString(16));
	if (sel[1] === 0x02) {
		const u = Buffer.from(user);
		const p = Buffer.from(pass);
		conn.write(concat(Uint8Array.of(0x01, u.length), new Uint8Array(u), Uint8Array.of(p.length), new Uint8Array(p)));
		const auth = await readExact(conn, 2);
		if (auth[1] !== 0x00) throw new Error('socks5: authentication failed');
	} else if (sel[1] !== 0x00) {
		throw new Error('socks5: no acceptable auth method (0x' + sel[1]!.toString(16) + ')');
	}
	// CONNECT by domain name (ATYP 0x03) so the proxy resolves it
	const host = Buffer.from(targetHost);
	conn.write(
		concat(Uint8Array.of(0x05, 0x01, 0x00, 0x03, host.length), new Uint8Array(host), Uint8Array.of((targetPort >> 8) & 0xff, targetPort & 0xff))
	);
	const rep = await readExact(conn, 4); // VER REP RSV ATYP
	if (rep[1] !== 0x00) throw new Error('socks5 CONNECT failed: reply 0x' + rep[1]!.toString(16));
	const atyp = rep[3];
	const addrLen = atyp === 0x01 ? 4 : atyp === 0x04 ? 16 : atyp === 0x03 ? (await readExact(conn, 1))[0]! : 0;
	await readExact(conn, addrLen + 2); // BND.ADDR + BND.PORT (ignored)
	return { write: conn.write, writeAsync: conn.writeAsync, read: conn.read, close: conn.close };
	} catch (e) {
		conn.close(); // a failed negotiation must not leak the proxy socket
		throw signal?.aborted ? signal.reason : e;
	} finally {
		detach();
	}
}

/** Tunnel through a proxy and return a byte transport for TLS to run on. Dispatches by
 *  scheme: `socks5://`/`socks5h://` → SOCKS5, otherwise HTTP `CONNECT`.
 *  `proxyUrl` = http|socks5://[user:pass@]host:port. */
export async function proxyConnect(proxyUrl: string, targetHost: string, targetPort: number, signal?: AbortSignal): Promise<Transport> {
	if (/^socks/i.test(proxyUrl)) return socks5Connect(proxyUrl, targetHost, targetPort, signal);
	const pu = new URL(proxyUrl);
	const conn = await rawConnect(pu.hostname, Number(pu.port || 80), signal);
	const detach = closeOnAbort(conn, signal); // a proxy that never answers cannot hang the dial
	try {
	const authority = `${targetHost}:${targetPort}`;
	const lines = [`CONNECT ${authority} HTTP/1.1`, `Host: ${authority}`];
	if (pu.username) {
		const cred = Buffer.from(`${decodeURIComponent(pu.username)}:${decodeURIComponent(pu.password)}`).toString('base64');
		lines.push(`Proxy-Authorization: Basic ${cred}`);
	}
	conn.write(new Uint8Array(Buffer.from(lines.join('\r\n') + '\r\n\r\n')));

	// Read the CONNECT response until the header terminator (\r\n\r\n).
	let buf: Uint8Array = new Uint8Array(0);
	let sep = -1;
	while (sep < 0) {
		const chunk = await conn.read();
		if (chunk === null) throw new Error('proxy closed before replying to CONNECT');
		buf = concat(buf, chunk);
		for (let i = 0; i + 3 < buf.length; i++)
			if (buf[i] === 13 && buf[i + 1] === 10 && buf[i + 2] === 13 && buf[i + 3] === 10) {
				sep = i;
				break;
			}
	}
	const head = Buffer.from(buf.subarray(0, sep)).toString('latin1');
	const status = /^HTTP\/1\.[01] (\d{3})/.exec(head);
	if (!status || status[1] !== '200') {
		conn.close();
		throw new Error(`proxy CONNECT failed: ${head.split('\r\n')[0]}`);
	}
	conn.q.unshift(buf.subarray(sep + 4)); // bytes the server already sent
	return { write: conn.write, writeAsync: conn.writeAsync, read: conn.read, close: conn.close };
	} catch (e) {
		conn.close(); // a failed CONNECT negotiation must not leak the proxy socket
		throw signal?.aborted ? signal.reason : e;
	} finally {
		detach();
	}
}
