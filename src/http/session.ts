// Session, like curl_cffi/requests: a cookie jar + redirect following + default
// headers/fingerprint/proxy/verify that persist across requests. The single-shot
// request() in client.ts keeps no state; Session does.
import { openConnection, roundtrip, serializeForEarly, withH2, type ClientResponse, type OpenOptions, type RoundtripOptions } from './client';
import type { RequestOptions } from './client';
import { modern } from '../fp/fingerprints';
import { resolvePersona, personaHeaders, type Persona } from '../fp/personas';
import type { Fingerprint } from '../tls/clienthello';
import type { OcspMode } from '../tls/verify';
import type { TlsConn } from '../tls/handshake';
import { H2Connection, type H2Profile } from './h2';
import { TicketStore } from '../tls/resumption';
import { isPublicSuffix } from './psl';

interface H2Entry {
	conn: H2Connection;
	fp: { ja3: string; ja3Hash: string; ja3n: string; ja3nHash: string; ja4: string; alpn: string | null };
}

interface Cookie {
	value: string;
	domain: string;
	path: string;
	expires: number; // epoch ms; 0 = session
	secure: boolean;
	sameSite: string; // lax | strict | none (stored; a programmatic client sends same-site)
}

/** Simple cookie jar: domain (suffix) + path (prefix) matching. */
export class CookieJar {
	private jar = new Map<string, Cookie>();
	setFromHeader(setCookie: string | string[] | undefined, url: URL): void {
		if (!setCookie) return;
		const host = url.hostname.toLowerCase();
		for (const line of Array.isArray(setCookie) ? setCookie : [setCookie]) {
			const parts = line.split(';');
			const nv = parts[0]!;
			const eq = nv.indexOf('=');
			if (eq < 0) continue;
			const name = nv.slice(0, eq).trim();
			const value = nv.slice(eq + 1).trim();
			const c: Cookie = { value, domain: host, path: '/', expires: 0, secure: false, sameSite: 'lax' };
			let domainAttr = '';
			let hasDomain = false;
			for (const a of parts.slice(1)) {
				const i = a.indexOf('=');
				const k = (i < 0 ? a : a.slice(0, i)).trim().toLowerCase();
				const v = i < 0 ? '' : a.slice(i + 1).trim();
				if (k === 'domain') {
					hasDomain = true;
					domainAttr = v.replace(/^\./, '').toLowerCase();
				} else if (k === 'path') c.path = v || '/';
				else if (k === 'secure') c.secure = true;
				else if (k === 'samesite') c.sameSite = v.toLowerCase();
				else if (k === 'max-age') c.expires = Date.now() + Number(v) * 1000;
				else if (k === 'expires' && !c.expires) c.expires = Date.parse(v) || 0;
			}
			// Cookie prefixes (RFC 6265bis §5.5): __Secure- needs Secure; __Host- needs
			// Secure, Path=/, and no Domain (host-only).
			if (name.startsWith('__Secure-') && !c.secure) continue;
			if (name.startsWith('__Host-') && (!c.secure || c.path !== '/' || hasDomain)) continue;
			// Domain attribute: never a public suffix (supercookie guard), and the host must
			// be within it. Otherwise the cookie is host-only.
			if (hasDomain) {
				if (isPublicSuffix(domainAttr)) continue;
				if (host !== domainAttr && !host.endsWith('.' + domainAttr)) continue;
				c.domain = domainAttr;
			}
			const key = `${c.domain}|${c.path}|${name}`;
			this.jar.set(key, c);
			if (value === '' || /deleted/i.test(value)) this.jar.delete(key);
		}
	}
	header(url: URL): string {
		const now = Date.now();
		const out: string[] = [];
		for (const [key, c] of this.jar) {
			if (c.expires && c.expires < now) {
				this.jar.delete(key);
				continue;
			}
			if (c.secure && url.protocol !== 'https:') continue;
			const host = url.hostname;
			const domOk = host === c.domain || host.endsWith('.' + c.domain);
			const pathOk = url.pathname === c.path || url.pathname.startsWith(c.path.endsWith('/') ? c.path : c.path + '/');
			if (domOk && pathOk) out.push(`${key.split('|')[2]}=${c.value}`);
		}
		return out.join('; ');
	}
}

export interface SessionOptions {
	fingerprint?: Fingerprint;
	/** Coherent browser identity (TLS + HTTP/2 + headers): a name
	 *  ('chrome'|'edge'|'firefox'|'safari') or a Persona. Applied to every request. */
	persona?: string | Persona;
	headers?: Record<string, string>;
	proxy?: string;
	verify?: boolean;
	/** OCSP revocation check (default 'off'): 'soft' tolerates missing, 'hard' requires good. */
	ocsp?: OcspMode;
	/** Speak TLS 1.2 instead of 1.3 (ECDHE + AEAD) for 1.2-only servers. Default false. */
	tls12?: boolean;
	/** Max redirects to follow (default 10, 0 = don't follow). */
	maxRedirects?: number;
	timeoutMs?: number;
	/** Reuse connections across requests to the same host (default true). This is
	 *  the big win over one-shot request(): subsequent requests skip the TLS
	 *  handshake entirely, like curl keep-alive. Set false to force a fresh
	 *  connection per request. */
	keepAlive?: boolean;
	/** Opt in to TLS 1.3 0-RTT early data on NEW connections when the server issued a
	 *  ticket allowing it (default false). Even when enabled it is only applied to GET/HEAD,
	 *  but early data can still be replayed by an attacker — whether that is harmless
	 *  depends on the endpoint. Enable only for endpoints where a replayed request is safe.
	 *  Resumption (1-RTT, no early data) is used regardless. */
	zeroRtt?: boolean;
	/** Use HTTP/2 when the server negotiates ALPN h2 (default false). One h2 connection per
	 *  host is kept and requests multiplex over it; falls back to HTTP/1.1 if h2 is declined. */
	http2?: boolean;
}

export class Session {
	readonly cookies = new CookieJar();
	/** Idle keep-alive connections, keyed by proxy|host:port. */
	private pool = new Map<string, TlsConn[]>();
	/** Resumption tickets (per host), captured from NewSessionTickets. */
	private tickets = new TicketStore();
	/** Live multiplexed HTTP/2 connections, keyed by proxy|host:port. */
	private h2pool = new Map<string, H2Entry>();
	constructor(private opts: SessionOptions = {}) {}

	async request(req: RequestOptions): Promise<ClientResponse> {
		const maxRedirects = this.opts.maxRedirects ?? 10;
		const keepAlive = this.opts.keepAlive ?? true;
		const persona = req.persona ?? this.opts.persona;
		const P = persona ? resolvePersona(persona) : null;
		const useH2 = req.http2 ?? this.opts.http2 ?? P?.http2 ?? false;
		let url = req.url;
		let method = req.method ?? 'GET';
		let body: Uint8Array | undefined = typeof req.body === 'string' ? new Uint8Array(Buffer.from(req.body)) : req.body;
		for (let hop = 0; ; hop++) {
			const u = new URL(url);
			if (u.protocol !== 'https:') throw new Error('only https (TLS) is supported');
			const host = u.hostname;
			const port = u.port ? Number(u.port) : 443;
			const open: OpenOptions = {
				host,
				port,
				proxy: req.proxy ?? this.opts.proxy,
				fingerprint: req.fingerprint ?? this.opts.fingerprint ?? P?.fingerprint(),
				verify: req.verify ?? this.opts.verify,
				ocsp: req.ocsp ?? this.opts.ocsp,
				tls12: req.tls12 ?? this.opts.tls12,
				timeoutMs: req.timeoutMs ?? this.opts.timeoutMs
			};
			const cookieHeader = this.cookies.header(u);
			const userHeaders = { ...(this.opts.headers ?? {}), ...(req.headers ?? {}), ...(cookieHeader ? { Cookie: cookieHeader } : {}) };
			const rt: RoundtripOptions = {
				method,
				host,
				path: u.pathname + u.search,
				headers: userHeaders,
				baseHeaders: P ? { Host: host, ...personaHeaders(P) } : undefined,
				body,
				keepAlive
			};
			const key = `${open.proxy ?? ''}|${host}:${port}`;
			const res = useH2
				? await this.h2send(
						key,
						open,
						{
							method,
							authority: port === 443 ? host : `${host}:${port}`,
							path: rt.path,
							headers: P ? { ...personaHeaders(P), ...userHeaders } : userHeaders,
							body
						},
						P?.h2Profile
					)
				: await this.send(key, open, rt, keepAlive);
			this.cookies.setFromHeader(res.headers['set-cookie'], u);

			const loc = res.headers['location'];
			const location = Array.isArray(loc) ? loc[0] : loc;
			if (hop < maxRedirects && location && res.status >= 300 && res.status < 400) {
				url = new URL(location, u).toString();
				if (res.status === 301 || res.status === 302 || res.status === 303) {
					method = method === 'HEAD' ? 'HEAD' : 'GET';
					body = undefined;
				}
				continue;
			}
			return res;
		}
	}

	/** One request, reusing a pooled connection when possible. A pooled connection
	 *  the server has silently closed fails the write/read → we drop it and retry on
	 *  the next pooled one, finally dialing fresh. (Standard keep-alive retry; a POST
	 *  that was already received by the server before the reset could be re-sent.) */
	private async send(key: string, open: OpenOptions, rt: RoundtripOptions, keepAlive: boolean): Promise<ClientResponse> {
		// 1) Reuse a live pooled connection — no handshake at all (fastest).
		const idle = this.pool.get(key);
		while (idle && idle.length) {
			const tls = idle.pop()!;
			try {
				return this.recycle(key, tls, await roundtrip(tls, rt), keepAlive);
			} catch {
				try {
					tls.close();
				} catch {
					/* already gone */
				}
			}
		}
		// 2) New connection: resume from a stored ticket if we have one. With zeroRtt opted
		//    in, a GET/HEAD also rides in the ClientHello as early data when allowed.
		const ticket = this.tickets.take(open.host);
		const idempotent = rt.method === 'GET' || rt.method === 'HEAD';
		const use0rtt = !!ticket && ticket.maxEarlyData > 0 && idempotent && (this.opts.zeroRtt ?? false);
		const resume = ticket ? { ticket, earlyData: use0rtt } : undefined;
		const earlyData = use0rtt ? serializeForEarly(rt) : undefined;
		const tls = await openConnection({ ...open, resume, earlyData, onTicket: (t) => this.tickets.add(open.host, t) });
		return this.recycle(key, tls, await roundtrip(tls, rt, tls.earlyAccepted), keepAlive);
	}

	private recycle(key: string, tls: TlsConn, res: ClientResponse, keepAlive: boolean): ClientResponse {
		if (keepAlive && res.reusable) (this.pool.get(key) ?? this.pool.set(key, []).get(key)!).push(tls);
		else tls.close();
		return res;
	}

	/** One request over a kept, multiplexed HTTP/2 connection (dialing + preface once per
	 *  host). If the server declines ALPN h2, do this one request over HTTP/1.1 instead. */
	private async h2send(
		key: string,
		open: OpenOptions,
		req: { method: string; authority: string; path: string; headers: Record<string, string>; body?: Uint8Array },
		profile?: H2Profile
	): Promise<ClientResponse> {
		let entry = this.h2pool.get(key);
		if (entry && entry.conn.closed) {
			this.h2pool.delete(key);
			entry = undefined;
		}
		if (!entry) {
			const tls = await openConnection({ ...open, fingerprint: withH2(open.fingerprint ?? modern()), onTicket: (t) => this.tickets.add(open.host, t) });
			const fp = { ja3: tls.ja3, ja3Hash: tls.ja3Hash, ja3n: tls.ja3n, ja3nHash: tls.ja3nHash, ja4: tls.ja4, alpn: tls.alpn };
			if (tls.alpn !== 'h2') {
				// server declined h2 → serve this request over HTTP/1.1 and drop the socket
				const res = await roundtrip(tls, { method: req.method, host: open.host, path: req.path, headers: req.headers, body: req.body, keepAlive: false });
				tls.close();
				return res;
			}
			const conn = new H2Connection(tls);
			conn.init(profile);
			entry = { conn, fp };
			this.h2pool.set(key, entry);
		}
		const res = await entry.conn.request(req);
		return Object.assign(res, entry.fp);
	}

	/** Close all pooled connections (keep-alive and HTTP/2). Call when done with the Session. */
	close(): void {
		for (const list of this.pool.values())
			for (const tls of list)
				try {
					tls.close();
				} catch {
					/* already gone */
				}
		this.pool.clear();
		for (const entry of this.h2pool.values()) entry.conn.close();
		this.h2pool.clear();
	}

	get = (url: string, o: Partial<RequestOptions> = {}) => this.request({ ...o, url, method: 'GET' });
	post = (url: string, o: Partial<RequestOptions> = {}) => this.request({ ...o, url, method: 'POST' });
}
