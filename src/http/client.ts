// High-level API, curl_cffi-style: request({ url, method, headers, body,
// fingerprint, proxy, verify }). One connection per request (Connection: close).
// openConnection + roundtrip are the reusable pieces Session uses for keep-alive.
import type { Fingerprint, ResumeSpec } from '../tls/clienthello';
import { modern, tls12 as tls12Fp } from '../fp/fingerprints';
import { resolvePersona, personaHeaders, type Persona } from '../fp/personas';
import { alpn as alpnExt } from '../tls/extensions';
import { Ext } from '../core/consts';
import { TlsClient, Negotiated12, type TlsConn } from '../tls/handshake';
import { Tls12Client } from '../tls/handshake12';
import type { OcspMode } from '../tls/verify';
import type { Ticket } from '../tls/resumption';
import { HttpResponse, readResponse, serializeRequest } from './http1';
import { h2Request } from './h2';
import { proxyConnect, tcpConnect } from '../tls/transport';
import { concat } from '../core/bytes';

export interface RequestOptions {
	url: string;
	method?: string;
	headers?: Record<string, string>;
	body?: string | Uint8Array;
	fingerprint?: Fingerprint;
	/** A coherent browser identity: sets the TLS fingerprint, HTTP/2, and the real header
	 *  set + order + User-Agent together. A name ('chrome'|'edge'|'firefox'|'safari') or a
	 *  Persona. An explicit `fingerprint`/`http2`/`headers` still override the persona's. */
	persona?: string | Persona;
	/** Total timeout (ms). */
	timeoutMs?: number;
	/** HTTP proxy: http://[user:pass@]host:port (CONNECT tunnel). */
	proxy?: string;
	/** Verify the server certificate (default true). false = skip. */
	verify?: boolean;
	/** OCSP revocation check (default 'off'): 'soft' = browser-style (tolerate missing),
	 *  'hard' = require a good stapled-or-fetched response. 'revoked' always fails. */
	ocsp?: OcspMode;
	/** Negotiate and use HTTP/2 (ALPN h2). Falls back to HTTP/1.1 if the server declines.
	 *  One-shot only — Session keep-alive is HTTP/1.1. */
	http2?: boolean;
	/** Send a TLS 1.2-only ClientHello (ECDHE + AEAD) instead of the default 1.3 + 1.2 one.
	 *  Not needed for 1.2-only servers — the default hello already falls back to 1.2 with
	 *  them, as browsers do; use it to present a 1.2 client's fingerprint. Uses the `tls12`
	 *  preset unless a fingerprint is given. */
	tls12?: boolean;
}

/** Return a copy of `fp` whose ALPN advertises h2 (then http/1.1), so the server may
 *  select HTTP/2. If the fingerprint has no ALPN extension, h2 is appended. */
export function withH2(fp: Fingerprint): Fingerprint {
	let found = false;
	const extensions = fp.extensions.map((e) => (e.type === Ext.alpn ? ((found = true), alpnExt(['h2', 'http/1.1'])) : e));
	if (!found) extensions.push(alpnExt(['h2', 'http/1.1']));
	return { ...fp, extensions };
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
	ocsp?: OcspMode;
	/** Send a TLS 1.2-only ClientHello (the default one offers 1.3 + 1.2 and falls back). */
	tls12?: boolean;
	timeoutMs?: number;
	/** Resume from a stored ticket (pre_shared_key); set resume.earlyData for 0-RTT. */
	resume?: ResumeSpec;
	/** Request bytes to send as 0-RTT early data (with resume.earlyData). */
	earlyData?: Uint8Array;
	/** Store each NewSessionTicket the server sends. */
	onTicket?: (t: Ticket) => void;
	/** Cancel the dial + handshake (rejects with the signal's reason). */
	signal?: AbortSignal;
}

/** Dial (TCP or proxy CONNECT/SOCKS5) + TLS handshake (1.3, or 1.2 when `tls12`) → a ready
 *  conn. `timeoutMs` bounds ALL of it — DNS, TCP connect, the proxy negotiation and the
 *  handshake — and `signal` cancels the same way; nothing in flight outlives either. */
export async function openConnection(o: OpenOptions): Promise<TlsConn> {
	o.signal?.throwIfAborted();
	const ac = new AbortController();
	const onAbort = () => ac.abort(o.signal!.reason);
	o.signal?.addEventListener('abort', onAbort, { once: true });
	const timer = o.timeoutMs ? setTimeout(() => ac.abort(new Error(`connect timed out after ${o.timeoutMs} ms`)), o.timeoutMs) : null;
	let t: import('../tls/transport').Transport | null = null;
	const kill = () => t?.close(); // closing the transport ends a handshake that is still waiting on it
	ac.signal.addEventListener('abort', kill, { once: true });
	try {
		t = o.proxy ? await proxyConnect(o.proxy, o.host, o.port, ac.signal) : await tcpConnect(o.host, o.port, ac.signal);
		ac.signal.throwIfAborted(); // aborted in the instant the dial settled
		const tls = o.tls12
			? new Tls12Client(t, { host: o.host, fingerprint: o.fingerprint ?? tls12Fp(), verify: o.verify, ocsp: o.ocsp })
			: new TlsClient(t, {
					host: o.host,
					fingerprint: o.fingerprint ?? modern(),
					verify: o.verify,
					ocsp: o.ocsp,
					resume: o.resume,
					earlyData: o.earlyData,
					onTicket: o.onTicket
				});
		try {
			await tls.handshake();
		} catch (e) {
			if (e instanceof Negotiated12) {
				// A TLS 1.2-only server answered our (1.3 + 1.2) hello with 1.2: finish the handshake
				// as TLS 1.2 on the same connection, as a browser would.
				const t12 = new Tls12Client(t, { host: o.host, fingerprint: o.fingerprint ?? modern(), verify: o.verify, ocsp: o.ocsp, continueFrom: e.state });
				try {
					await t12.handshake();
				} catch (e2) {
					t12.close();
					throw e2;
				}
				ac.signal.throwIfAborted();
				return t12;
			}
			tls.close(); // a failed handshake must not leak the socket
			throw e;
		}
		ac.signal.throwIfAborted();
		return tls;
	} catch (e) {
		t?.close();
		throw ac.signal.aborted ? ac.signal.reason : e;
	} finally {
		if (timer) clearTimeout(timer);
		o.signal?.removeEventListener('abort', onAbort);
		ac.signal.removeEventListener('abort', kill);
	}
}

/** Race `p` against the time left until `deadline` (ms since epoch; 0 = none). On expiry
 *  `onExpire` runs (close the connection so its pending read ends) and the call rejects with
 *  a timeout error. */
export async function withDeadline<T>(deadline: number, p: Promise<T>, onExpire?: () => void): Promise<T> {
	if (!deadline) return p;
	p.catch(() => {}); // the loser's later rejection is expected — don't leave it unhandled
	let timer!: ReturnType<typeof setTimeout>;
	const expire = new Promise<never>((_, rej) => {
		timer = setTimeout(() => {
			try {
				onExpire?.();
			} catch {
				/* already gone */
			}
			rej(new Error('request timed out'));
		}, Math.max(0, deadline - Date.now()));
	});
	try {
		return await Promise.race([p, expire]);
	} finally {
		clearTimeout(timer);
	}
}

/** Milliseconds left until `deadline` (≥1, so a nearly spent budget still fails cleanly). */
export const timeLeft = (deadline: number): number | undefined => (deadline ? Math.max(1, deadline - Date.now()) : undefined);

export interface RoundtripOptions {
	method: string;
	host: string;
	path: string;
	headers: Record<string, string>;
	body?: Uint8Array;
	/** Advertise Connection: keep-alive (reuse) vs close. */
	keepAlive: boolean;
	/** Persona-supplied base headers (Host + browser-realistic order). When set it replaces
	 *  the generic defaults, so the persona's header order is preserved on the wire. */
	baseHeaders?: Record<string, string>;
}

function rtHeaders(o: RoundtripOptions): Record<string, string> {
	const headers: Record<string, string> = { ...(o.baseHeaders ?? DEFAULT_HEADERS(o.host)), ...o.headers };
	// Only add Connection if the base didn't place it (keeps a persona's header order intact).
	if (!Object.keys(headers).some((k) => k.toLowerCase() === 'connection')) headers.Connection = o.keepAlive ? 'keep-alive' : 'close';
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
export async function roundtrip(tls: TlsConn, o: RoundtripOptions, alreadySent = false): Promise<ClientResponse> {
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

	// A persona supplies the TLS fingerprint, HTTP/2, and the browser's real headers together;
	// an explicit fingerprint/http2/headers still wins.
	const p = opts.persona ? resolvePersona(opts.persona) : null;
	const useH2 = opts.http2 ?? p?.http2 ?? false;
	const baseFp = opts.fingerprint ?? p?.fingerprint();
	const personaBase = p ? personaHeaders(p) : undefined;
	const fingerprint = useH2 ? withH2(baseFp ?? modern()) : baseFp;
	// timeoutMs = ONE budget for the whole request: dial + handshake + request + response.
	const deadline = opts.timeoutMs ? Date.now() + opts.timeoutMs : 0;
	const tls = await openConnection({ host, port, proxy: opts.proxy, fingerprint, verify: opts.verify, ocsp: opts.ocsp, tls12: opts.tls12, timeoutMs: opts.timeoutMs });
	try {
		// Use HTTP/2 only if the server actually selected it via ALPN; otherwise HTTP/1.1.
		if (useH2 && tls.alpn === 'h2') {
			const res = await withDeadline(
				deadline,
				h2Request(
					tls,
					{
						method: opts.method ?? 'GET',
						authority: u.port ? `${host}:${u.port}` : host,
						path: u.pathname + u.search,
						headers: { ...(personaBase ?? DEFAULT_HEADERS(host)), ...(opts.headers ?? {}) },
						body: bodyBytes
					},
					p?.h2Profile
				),
				() => tls.close()
			);
			return Object.assign(res, { ja3: tls.ja3, ja3Hash: tls.ja3Hash, ja3n: tls.ja3n, ja3nHash: tls.ja3nHash, ja4: tls.ja4, alpn: tls.alpn });
		}
		return await withDeadline(
			deadline,
			roundtrip(tls, {
				method: opts.method ?? 'GET',
				host,
				path: u.pathname + u.search,
				headers: opts.headers ?? {},
				baseHeaders: personaBase ? { Host: host, ...personaBase } : undefined,
				body: bodyBytes,
				keepAlive: false
			}),
			() => tls.close()
		);
	} finally {
		tls.close();
	}
}
