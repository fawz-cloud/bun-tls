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
	/** No Domain attribute → the cookie is sent ONLY to the exact host (RFC 6265 §5.3). */
	hostOnly: boolean;
	expires: number; // epoch ms; 0 = session
	secure: boolean;
	sameSite: string; // lax | strict | none (stored; a programmatic client sends same-site)
}

/** A connection's security policy. Pooled connections and resumption tickets are keyed by
 *  it so a looser-policy connection (verify:false, ocsp:off) is NEVER reused — or resumed
 *  into — a stricter request (verify:true, ocsp:hard). */
function policyOf(o: OpenOptions): string {
	return `v${o.verify !== false ? 1 : 0}o${o.ocsp ?? 'off'}t${o.tls12 ? 1 : 0}`;
}

/** RFC 6265 §5.1.4 default-path: the directory of the request URI (not always "/"). */
function defaultPath(pathname: string): string {
	if (!pathname.startsWith('/')) return '/';
	const i = pathname.lastIndexOf('/');
	return i <= 0 ? '/' : pathname.slice(0, i);
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
			const c: Cookie = { value, domain: host, path: defaultPath(url.pathname), hostOnly: true, expires: 0, secure: false, sameSite: 'lax' };
			let domainAttr = '';
			let hasDomain = false;
			for (const a of parts.slice(1)) {
				const i = a.indexOf('=');
				const k = (i < 0 ? a : a.slice(0, i)).trim().toLowerCase();
				const v = i < 0 ? '' : a.slice(i + 1).trim();
				if (k === 'domain') {
					hasDomain = true;
					domainAttr = v.replace(/^\./, '').toLowerCase();
				} else if (k === 'path' && v.startsWith('/')) c.path = v; // else keep the default-path
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
				c.hostOnly = false; // a Domain attribute makes the cookie valid for subdomains too
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
			const domOk = c.hostOnly ? host === c.domain : host === c.domain || host.endsWith('.' + c.domain);
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
	/** In-flight h2 dials, so concurrent requests to a new host share one connection. */
	private h2dial = new Map<string, Promise<H2Entry | null>>();
	private closedFlag = false;
	/** Per-name persona cache: resolve, fingerprint template and header set are all the same for
	 *  every request to a named persona, so build them once. Only cached when the persona is given
	 *  by name — a Persona object the caller supplies could differ per request. The fingerprint
	 *  template is safe to share: all per-connection randomness (GREASE, permute) happens at dial. */
	private personaCache = new Map<string, { P: Persona; fp: Fingerprint; hdrs: Record<string, string> }>();
	constructor(private opts: SessionOptions = {}) {}

	/** Resolve a persona and its cached fingerprint + headers. For a named persona the result is
	 *  memoized; for a Persona object it is rebuilt (fp per-call to preserve any custom behavior). */
	private persona(p: string | Persona | undefined): { P: Persona; fp: Fingerprint; hdrs: Record<string, string> } | null {
		if (!p) return null;
		if (typeof p !== 'string') {
			const P = resolvePersona(p);
			return { P, fp: P.fingerprint(), hdrs: personaHeaders(P) };
		}
		let c = this.personaCache.get(p);
		if (!c) {
			const P = resolvePersona(p);
			c = { P, fp: P.fingerprint(), hdrs: personaHeaders(P) };
			this.personaCache.set(p, c);
		}
		return c;
	}

	async request(req: RequestOptions): Promise<ClientResponse> {
		const maxRedirects = this.opts.maxRedirects ?? 10;
		const keepAlive = this.opts.keepAlive ?? true;
		const pc = this.persona(req.persona ?? this.opts.persona);
		const P = pc?.P ?? null;
		const useH2 = req.http2 ?? this.opts.http2 ?? P?.http2 ?? false;
		let url = req.url;
		let method = req.method ?? 'GET';
		let body: Uint8Array | undefined = typeof req.body === 'string' ? new Uint8Array(Buffer.from(req.body)) : req.body;
		let first: URL | null = null; // the original request URL; auth headers belong to its origin only
		for (let hop = 0; ; hop++) {
			const u = new URL(url);
			if (u.protocol !== 'https:') throw new Error('only https (TLS) is supported');
			if (hop === 0) first = u;
			const host = u.hostname;
			const port = u.port ? Number(u.port) : 443;
			const open: OpenOptions = {
				host,
				port,
				proxy: req.proxy ?? this.opts.proxy,
				fingerprint: req.fingerprint ?? this.opts.fingerprint ?? pc?.fp,
				verify: req.verify ?? this.opts.verify,
				ocsp: req.ocsp ?? this.opts.ocsp,
				tls12: req.tls12 ?? this.opts.tls12,
				timeoutMs: req.timeoutMs ?? this.opts.timeoutMs
			};
			const cookieHeader = this.cookies.header(u);
			const userHeaders: Record<string, string> = { ...(this.opts.headers ?? {}), ...(req.headers ?? {}), ...(cookieHeader ? { Cookie: cookieHeader } : {}) };
			// Never forward credentials to a different origin across a redirect (the Cookie
			// jar already scopes cookies per origin; this covers an explicit Authorization).
			if (first && u.origin !== first.origin) for (const k of Object.keys(userHeaders)) if (/^(authorization|proxy-authorization)$/i.test(k)) delete userHeaders[k];
			const rt: RoundtripOptions = {
				method,
				host,
				path: u.pathname + u.search,
				headers: userHeaders,
				baseHeaders: pc ? { Host: host, ...pc.hdrs } : undefined,
				body,
				keepAlive
			};
			const key = `${open.proxy ?? ''}|${host}:${port}|${policyOf(open)}`;
			const res = useH2
				? await this.h2send(
						key,
						open,
						{
							method,
							authority: port === 443 ? host : `${host}:${port}`,
							path: rt.path,
							headers: pc ? { ...pc.hdrs, ...userHeaders } : userHeaders,
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
		const idempotent = rt.method === 'GET' || rt.method === 'HEAD';
		// 1) Reuse a live pooled connection — no handshake at all (fastest, the common path).
		const idle = this.pool.get(key);
		while (idle && idle.length) {
			const tls = idle.pop()!;
			try {
				const rtp = roundtrip(tls, rt);
				return this.recycle(key, tls, await (open.timeoutMs ? this.timed(open.timeoutMs, tls, rtp) : rtp), keepAlive);
			} catch (e) {
				try {
					tls.close();
				} catch {
					/* already gone */
				}
				// A non-idempotent request may have already been received + processed by the
				// server before the reset — never silently re-send it (at-most-once).
				if (!idempotent) throw e;
			}
		}
		// 2) New connection: resume from a stored ticket if we have one. With zeroRtt opted
		//    in, a GET/HEAD also rides in the ClientHello as early data when allowed.
		const tkey = `${open.host}|${policyOf(open)}`; // tickets scoped to the same policy as the pool (only needed when dialing)
		const ticket = this.tickets.take(tkey);
		const use0rtt = !!ticket && ticket.maxEarlyData > 0 && idempotent && (this.opts.zeroRtt ?? false);
		const resume = ticket ? { ticket, earlyData: use0rtt } : undefined;
		const earlyData = use0rtt ? serializeForEarly(rt) : undefined;
		const tls = await openConnection({ ...open, resume, earlyData, onTicket: (t) => this.tickets.add(tkey, t) });
		const rtp = roundtrip(tls, rt, tls.earlyAccepted);
		return this.recycle(key, tls, await (open.timeoutMs ? this.timed(open.timeoutMs, tls, rtp) : rtp), keepAlive);
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
			// Deduplicate the dial: a cold burst of N concurrent requests shares ONE connection
			// (otherwise each opens its own, defeating multiplexing — audit A06).
			let dial = this.h2dial.get(key);
			if (!dial) {
				dial = this.dialH2(key, open, profile).finally(() => this.h2dial.delete(key));
				this.h2dial.set(key, dial);
			}
			const dialed = await dial;
			if (dialed === null) {
				// server declined h2 on this host → serve this request over HTTP/1.1
				const tls = await openConnection({ ...open });
				const res = await roundtrip(tls, { method: req.method, host: open.host, path: req.path, headers: req.headers, body: req.body, keepAlive: false });
				tls.close();
				return res;
			}
			entry = dialed;
		}
		const res = await entry.conn.request(req, open.timeoutMs); // per-stream deadline, not the whole conn
		return Object.assign(res, entry.fp);
	}

	/** Race a roundtrip against a deadline that closes the (single) connection on expiry. */
	private async timed<T>(ms: number | undefined, tls: TlsConn, p: Promise<T>): Promise<T> {
		if (!ms) return p;
		p.catch(() => {}); // the loser's later rejection is expected — don't leave it unhandled
		let timer!: ReturnType<typeof setTimeout>;
		const deadline = new Promise<never>((_, rej) => {
			timer = setTimeout(() => {
				try {
					tls.close();
				} catch {
					/* already gone */
				}
				rej(new Error('request timed out'));
			}, ms);
		});
		try {
			return await Promise.race([p, deadline]);
		} finally {
			clearTimeout(timer);
		}
	}

	/** Dial one HTTP/2 connection for `key`, pool it, and return its entry — or null if the
	 *  server declined ALPN h2 (the caller then falls back to HTTP/1.1). */
	private async dialH2(key: string, open: OpenOptions, profile?: H2Profile): Promise<H2Entry | null> {
		const tls = await openConnection({ ...open, fingerprint: withH2(open.fingerprint ?? modern()), onTicket: (t) => this.tickets.add(`${open.host}|${policyOf(open)}`, t) });
		if (tls.alpn !== 'h2') {
			tls.close();
			return null;
		}
		const conn = new H2Connection(tls);
		conn.init(profile);
		const entry: H2Entry = { conn, fp: { ja3: tls.ja3, ja3Hash: tls.ja3Hash, ja3n: tls.ja3n, ja3nHash: tls.ja3nHash, ja4: tls.ja4, alpn: tls.alpn } };
		if (this.closedFlag) conn.close(); // Session was closed while we dialed — don't leak it
		else this.h2pool.set(key, entry);
		return entry;
	}

	/** Close all pooled connections (keep-alive and HTTP/2). Call when done with the Session. */
	close(): void {
		this.closedFlag = true; // any dial still in flight closes itself on resolve
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
