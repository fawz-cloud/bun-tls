// Transport = raw byte stream. TCP via Bun.connect (wrapped as async
// read()/write()). HTTP proxy CONNECT included. The handshake & record layers
// don't know whether this is a socket/proxy/mock — easy to test with a mock.
import { lookup } from 'node:dns/promises';
import { concat } from '../core/bytes';

export interface Transport {
	write(b: Uint8Array): void;
	/** null = EOF / closed. */
	read(): Promise<Uint8Array | null>;
	close(): void;
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

async function rawConnect(host: string, port: number): Promise<RawConn> {
	const q = new ByteQueue();
	let closed = false;
	// Outbound queue with backpressure: sock.write() returns the bytes accepted; the
	// rest must wait for `drain`. Ignoring this drops bytes on large writes (e.g. a
	// 10MB upload → hundreds of records) → the server sees a truncated body. FIFO.
	const outQ: Uint8Array[] = [];
	let sock!: BunSock;
	const flush = () => {
		while (outQ.length) {
			const b = outQ[0]!;
			const n = sock.write(b);
			if (n < b.length) {
				outQ[0] = b.subarray(n); // partial — keep remainder, resume on drain
				break;
			}
			outQ.shift();
		}
	};
	sock = (await Bun.connect({
		hostname: await resolveHost(host),
		port,
		socket: {
			binaryType: 'uint8array',
			data(_s, data: Uint8Array) {
				q.push(new Uint8Array(data)); // Bun reuses the buffer → copy
			},
			drain() {
				flush();
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
	})) as unknown as BunSock;
	// Disable Nagle: our handshake/request writes are small and latency-sensitive;
	// Nagle + delayed-ACK can add tens of ms. (Guarded — older Bun may lack it.)
	sock.setNoDelay?.(true);
	return {
		q,
		write(b) {
			outQ.push(b);
			flush();
		},
		read: () => q.read(),
		close() {
			if (!closed) {
				closed = true;
				try {
					sock.end();
				} catch {
					/* already closed */
				}
			}
		}
	};
}

export const tcpConnect = (host: string, port: number): Promise<Transport> => rawConnect(host, port);

/** Tunnel through an HTTP proxy: CONNECT host:port, read 200, push back any
 *  leftover bytes. `proxyUrl` = http://[user:pass@]host:port. TLS runs on top. */
export async function proxyConnect(proxyUrl: string, targetHost: string, targetPort: number): Promise<Transport> {
	const pu = new URL(proxyUrl);
	const conn = await rawConnect(pu.hostname, Number(pu.port || 80));
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
	return { write: conn.write, read: conn.read, close: conn.close };
}
