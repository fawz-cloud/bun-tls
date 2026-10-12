// High-level API, curl_cffi-style: request({ url, method, headers, body,
// fingerprint, proxy, verify }). One connection per request (Connection: close).
// openConnection + roundtrip are the reusable pieces Session uses for keep-alive.
import type { Fingerprint, ResumeSpec } from '../tls/clienthello';
import { modern } from '../fp/fingerprints';
import { TlsClient } from '../tls/handshake';
import type { Ticket } from '../tls/resumption';
import { HttpResponse, readResponse, serializeRequest } from './http1';
import { proxyConnect, tcpConnect } from '../tls/transport';
import { concat } from '../core/bytes';

export interface RequestOptions {
	url: string;
	method?: string;
	headers?: Record<string, string>;
	body?: string | Uint8Array;
	fingerprint?: Fingerprint;
	/** Total timeout (ms). */
	timeoutMs?: number;
	/** HTTP proxy: http://[user:pass@]host:port (CONNECT tunnel). */
	proxy?: string;
	/** Verify the server certificate (default true). false = skip. */
	verify?: boolean;
}

export interface ClientResponse extends HttpResponse {
	ja3: string;
	ja3Hash: string;
	ja3n: string;
	ja3nHash: string;
	ja4: string;
	alpn: string | null;
}

const DEFAULT_HEADERS = (host: string): Record<string, string> => ({
	Host: host,
	'User-Agent': 'bun-tls/0.1',
	Accept: '*/*',
	'Accept-Encoding': 'gzip, deflate, br, zstd'
});

export interface OpenOptions {
	host: string;
	port: number;
	proxy?: string;
	fingerprint?: Fingerprint;
	verify?: boolean;
	timeoutMs?: number;
	/** Resume from a stored ticket (pre_shared_key); set resume.earlyData for 0-RTT. */
	resume?: ResumeSpec;
	/** Request bytes to send as 0-RTT early data (with resume.earlyData). */
	earlyData?: Uint8Array;
	/** Store each NewSessionTicket the server sends. */
	onTicket?: (t: Ticket) => void;
}

/** Dial (TCP or proxy CONNECT) + TLS 1.3 handshake → a ready TlsClient. */
export async function openConnection(o: OpenOptions): Promise<TlsClient> {
	const t = o.proxy ? await proxyConnect(o.proxy, o.host, o.port) : await tcpConnect(o.host, o.port);
	const tls = new TlsClient(t, {
		host: o.host,
		fingerprint: o.fingerprint ?? modern(),
		verify: o.verify,
		resume: o.resume,
		earlyData: o.earlyData,
		onTicket: o.onTicket
	});
	const timer = o.timeoutMs ? setTimeout(() => tls.close(), o.timeoutMs) : null;
	try {
		await tls.handshake();
	} finally {
		if (timer) clearTimeout(timer);
	}
	return tls;
}

export interface RoundtripOptions {
	method: string;
	host: string;
	path: string;
	headers: Record<string, string>;
	body?: Uint8Array;
	/** Advertise Connection: keep-alive (reuse) vs close. */
	keepAlive: boolean;
}

function rtHeaders(o: RoundtripOptions): Record<string, string> {
	const headers: Record<string, string> = {
		...DEFAULT_HEADERS(o.host),
		...o.headers,
		Connection: o.keepAlive ? 'keep-alive' : 'close'
	};
	if (o.body && o.body.length) headers['Content-Length'] = String(o.body.length);
	return headers;
}

/** The full request (head + body) as one buffer — used as 0-RTT early data. */
export function serializeForEarly(o: RoundtripOptions): Uint8Array {
	const head = serializeRequest({ method: o.method, host: o.host, path: o.path, headers: rtHeaders(o) });
	return o.body && o.body.length ? concat(head, o.body) : head;
}

/** Send one request + read one response over an already-handshaked TlsClient. Does NOT
 *  close the connection — the caller decides (see ClientResponse.reusable). When
 *  `alreadySent` (the request went out as 0-RTT early data), skip the write and just read. */
export async function roundtrip(tls: TlsClient, o: RoundtripOptions, alreadySent = false): Promise<ClientResponse> {
	if (!alreadySent) {
		// Head and body written separately (no big copy to prepend the header). A large body
		// streams in backpressure-paced batches so it pipelines with the server's read; a
		// small one goes in a single write for lowest latency.
		tls.writeApp(serializeRequest({ method: o.method, host: o.host, path: o.path, headers: rtHeaders(o) }));
		if (o.body && o.body.length) {
			if (o.body.length > 256 * 1024) await tls.writeAppStream(o.body);
			else tls.writeApp(o.body);
		}
	}
	const res = await readResponse(() => tls.readApp(), o.method);
	return Object.assign(res, {
		ja3: tls.ja3,
		ja3Hash: tls.ja3Hash,
		ja3n: tls.ja3n,
		ja3nHash: tls.ja3nHash,
		ja4: tls.ja4,
		alpn: tls.alpn
	});
}

export async function request(opts: RequestOptions): Promise<ClientResponse> {
	const u = new URL(opts.url);
	if (u.protocol !== 'https:') throw new Error('only https (TLS) is supported');
	const host = u.hostname;
	const port = u.port ? Number(u.port) : 443;
	const bodyBytes = typeof opts.body === 'string' ? new Uint8Array(Buffer.from(opts.body)) : opts.body;

	const tls = await openConnection({ host, port, proxy: opts.proxy, fingerprint: opts.fingerprint, verify: opts.verify, timeoutMs: opts.timeoutMs });
	const timer = opts.timeoutMs ? setTimeout(() => tls.close(), opts.timeoutMs) : null;
	try {
		return await roundtrip(tls, {
			method: opts.method ?? 'GET',
			host,
			path: u.pathname + u.search,
			headers: opts.headers ?? {},
			body: bodyBytes,
			keepAlive: false
		});
	} finally {
		if (timer) clearTimeout(timer);
		tls.close();
	}
}
