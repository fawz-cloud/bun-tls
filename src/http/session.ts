// Session, like curl_cffi/requests: a cookie jar + redirect following + default
// headers/fingerprint/proxy/verify that persist across requests. The single-shot
// request() in client.ts keeps no state; Session does.
import { openConnection, roundtrip, serializeForEarly, type ClientResponse, type OpenOptions, type RoundtripOptions } from './client';
import type { RequestOptions } from './client';
import type { Fingerprint } from '../tls/clienthello';
import type { TlsClient } from '../tls/handshake';
import { TicketStore } from '../tls/resumption';

interface Cookie {
	value: string;
	domain: string;
	path: string;
	expires: number; // epoch ms; 0 = session
	secure: boolean;
}

/** Simple cookie jar: domain (suffix) + path (prefix) matching. */
export class CookieJar {
	private jar = new Map<string, Cookie>();
	setFromHeader(setCookie: string | string[] | undefined, url: URL): void {
		if (!setCookie) return;
		for (const line of Array.isArray(setCookie) ? setCookie : [setCookie]) {
			const parts = line.split(';');
			const [nv, ...attrs] = parts;
			const eq = nv!.indexOf('=');
			if (eq < 0) continue;
			const name = nv!.slice(0, eq).trim();
			const value = nv!.slice(eq + 1).trim();
			const c: Cookie = { value, domain: url.hostname, path: '/', expires: 0, secure: false };
			for (const a of attrs) {
				const i = a.indexOf('=');
				const k = (i < 0 ? a : a.slice(0, i)).trim().toLowerCase();
				const v = i < 0 ? '' : a.slice(i + 1).trim();
				if (k === 'domain') c.domain = v.replace(/^\./, '');
				else if (k === 'path') c.path = v || '/';
				else if (k === 'secure') c.secure = true;
				else if (k === 'max-age') c.expires = Date.now() + Number(v) * 1000;
				else if (k === 'expires' && !c.expires) c.expires = Date.parse(v) || 0;
			}
			this.jar.set(`${c.domain}|${c.path}|${name}`, c);
			if (value === '' || /deleted/i.test(value)) this.jar.delete(`${c.domain}|${c.path}|${name}`);
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
	headers?: Record<string, string>;
	proxy?: string;
	verify?: boolean;
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
}

export class Session {
	readonly cookies = new CookieJar();
	/** Idle keep-alive connections, keyed by proxy|host:port. */
	private pool = new Map<string, TlsClient[]>();
	/** Resumption tickets (per host), captured from NewSessionTickets. */
	private tickets = new TicketStore();
	constructor(private opts: SessionOptions = {}) {}

	async request(req: RequestOptions): Promise<ClientResponse> {
		const maxRedirects = this.opts.maxRedirects ?? 10;
		const keepAlive = this.opts.keepAlive ?? true;
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
				fingerprint: req.fingerprint ?? this.opts.fingerprint,
				verify: req.verify ?? this.opts.verify,
				timeoutMs: req.timeoutMs ?? this.opts.timeoutMs
			};
			const cookieHeader = this.cookies.header(u);
			const rt: RoundtripOptions = {
				method,
				host,
				path: u.pathname + u.search,
				headers: { ...(this.opts.headers ?? {}), ...(req.headers ?? {}), ...(cookieHeader ? { Cookie: cookieHeader } : {}) },
				body,
				keepAlive
			};
			const res = await this.send(`${open.proxy ?? ''}|${host}:${port}`, open, rt, keepAlive);
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

	private recycle(key: string, tls: TlsClient, res: ClientResponse, keepAlive: boolean): ClientResponse {
		if (keepAlive && res.reusable) (this.pool.get(key) ?? this.pool.set(key, []).get(key)!).push(tls);
		else tls.close();
		return res;
	}

	/** Close all pooled connections. Call when done with the Session. */
	close(): void {
		for (const list of this.pool.values())
			for (const tls of list)
				try {
					tls.close();
				} catch {
					/* already gone */
				}
		this.pool.clear();
	}

	get = (url: string, o: Partial<RequestOptions> = {}) => this.request({ ...o, url, method: 'GET' });
	post = (url: string, o: Partial<RequestOptions> = {}) => this.request({ ...o, url, method: 'POST' });
}
