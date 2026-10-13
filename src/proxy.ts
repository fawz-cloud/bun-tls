// A local HTTP proxy that re-originates each request through bun-tls with a chosen
// persona — so ANY tool or language (not just JS) can borrow the fingerprint by pointing
// its HTTP_PROXY at this server. TLS is end-to-end, so this cannot transparently
// re-fingerprint a client's own HTTPS (that needs a MITM CA); instead a tool requests the
// target and bun-tls makes the real HTTPS request with the persona and returns the response.
//
//   bun src/cli.ts proxy --port 8888 --persona chrome
//   HTTP_PROXY=http://127.0.0.1:8888 curl http://example.com/      # upgraded to https upstream
//   curl 'http://127.0.0.1:8888/https://example.com/'              # or target in the path
//   curl -H 'x-bt-url: https://example.com/' http://127.0.0.1:8888 # or in a header
import { request } from './http/client';
import type { Persona } from './fp/personas';

export interface ProxyOptions {
	port?: number;
	host?: string;
	/** Persona applied to every upstream request (default 'chrome'). */
	persona?: string | Persona;
	/** Verify upstream certificates (default true). */
	verify?: boolean;
}

/** Work out the upstream URL from a proxied request: an absolute request-target (what a
 *  client using us as its HTTP_PROXY sends), an `x-bt-url` header, or a `/<url>` path. */
function targetUrl(req: Request): string | null {
	const u = new URL(req.url);
	const header = req.headers.get('x-bt-url');
	if (header) return header;
	// HTTP_PROXY forward-proxy: req.url is the absolute target the client asked for.
	if (u.hostname !== '127.0.0.1' && u.hostname !== 'localhost') return req.url.replace(/^http:/, 'https:');
	// Gateway form: http://127.0.0.1:8888/https://target/path  (or /target/path → https)
	const rest = u.pathname.slice(1) + u.search;
	if (!rest || rest === 'favicon.ico') return null;
	if (/^https?:\/\//.test(rest)) return rest.replace(/^http:/, 'https:');
	return 'https://' + rest;
}

const HOP = new Set(['host', 'connection', 'proxy-connection', 'keep-alive', 'transfer-encoding', 'upgrade', 'x-bt-url']);
// Identity headers the PERSONA must own — never forward the client's (a tool's own
// User-Agent over a Chrome TLS fingerprint is exactly the incoherence we avoid). App
// headers (authorization, cookie, content-type, custom x-*) are forwarded.
const IDENTITY = new Set(['user-agent', 'accept', 'accept-encoding', 'accept-language', 'upgrade-insecure-requests', 'priority']);
const personaOwned = (k: string): boolean => IDENTITY.has(k) || k.startsWith('sec-');

/** Start the proxy. Returns the Bun server (call `.stop()` to shut down). */
export function startProxy(opts: ProxyOptions = {}): ReturnType<typeof Bun.serve> {
	const persona = opts.persona ?? 'chrome';
	return Bun.serve({
		hostname: opts.host ?? '127.0.0.1',
		port: opts.port ?? 8888,
		idleTimeout: 60,
		async fetch(req) {
			const url = targetUrl(req);
			if (!url) return new Response('bun-tls proxy. Use it as HTTP_PROXY, or GET /<https target url>.\n', { status: 200 });
			// Forward the client's headers except hop-by-hop ones; the persona sets the rest.
			const headers: Record<string, string> = {};
			for (const [k, v] of req.headers) {
				const lk = k.toLowerCase();
				if (!HOP.has(lk) && !personaOwned(lk)) headers[k] = v; // persona owns the identity headers
			}
			const body = req.method === 'GET' || req.method === 'HEAD' ? undefined : new Uint8Array(await req.arrayBuffer());
			try {
				const r = await request({ url, method: req.method, headers, body, persona, verify: opts.verify, timeoutMs: 30000 });
				// Strip hop-by-hop + content-encoding (bun-tls already decoded the body).
				const out = new Headers();
				for (const [k, v] of Object.entries(r.headers)) {
					const lk = k.toLowerCase();
					if (HOP.has(lk) || lk === 'content-encoding' || lk === 'content-length') continue;
					for (const one of Array.isArray(v) ? v : [v]) out.append(k, one);
				}
				return new Response(r.body, { status: r.status, statusText: r.statusText, headers: out });
			} catch (e) {
				return new Response('bun-tls proxy upstream error: ' + (e as Error).message + '\n', { status: 502 });
			}
		}
	});
}
