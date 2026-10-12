// Personas: a coherent browser identity across ALL fingerprinting layers at once —
// the TLS ClientHello (JA3/JA4), the HTTP/2 settings fingerprint, AND the HTTP header
// set + order + User-Agent — from one source of truth. This is the piece anti-bot WAFs
// use to catch fingerprint-spoofing clients: a Chrome JA3 paired with a non-Chrome header
// order (or a curl User-Agent) is a dead giveaway. A persona guarantees they all match.
//
// Chrome/Edge additionally permute their TLS extensions + rotate GREASE every connection
// (as the real browsers do), so the RAW JA3 differs each time while staying a valid Chrome
// shape — there is no single JA3 string for a WAF to block-list. Firefox/Safari keep a
// fixed order, matching the real clients.
import type { Fingerprint } from '../tls/clienthello';
import { chrome131, firefox148 } from './fingerprints';
import { clients } from './clients';
import { CHROME_H2, FIREFOX_H2, SAFARI_H2, type H2Profile } from '../http/h2';

const UA = {
	chrome: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
	edge: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0',
	firefox: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:148.0) Gecko/20100101 Firefox/148.0',
	safari: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15'
};

const ACCEPT_HTML =
	'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7';

/** A persona = one real browser build, consistent across TLS + HTTP/2 + HTTP headers. */
export interface Persona {
	name: string;
	/** TLS fingerprint (Chrome/Edge permute + GREASE per connection). */
	fingerprint: () => Fingerprint;
	/** Browsers use HTTP/2 — default the request to h2 (still falls back to h1). */
	http2: boolean;
	/** The browser's own HTTP/2 (Akamai) fingerprint, so h2 stays coherent with the TLS
	 *  and header identity (a Chrome JA3 over a Chrome h2 profile, Firefox over Firefox…). */
	h2Profile: H2Profile;
	/** Default request headers in the browser's real order (a navigation GET). Host /
	 *  :authority, Connection, Content-Length and Cookie are added by the request layer.
	 *  User code can override any value; unknown headers are appended. */
	headers: [string, string][];
}

const chromeHeaders = (brand: string): [string, string][] => [
	['sec-ch-ua', brand],
	['sec-ch-ua-mobile', '?0'],
	['sec-ch-ua-platform', '"Windows"'],
	['upgrade-insecure-requests', '1'],
	['user-agent', ''], // filled per persona below
	['accept', ACCEPT_HTML],
	['sec-fetch-site', 'none'],
	['sec-fetch-mode', 'navigate'],
	['sec-fetch-user', '?1'],
	['sec-fetch-dest', 'document'],
	['accept-encoding', 'gzip, deflate, br, zstd'],
	['accept-language', 'en-US,en;q=0.9']
];
const withUA = (h: [string, string][], ua: string): [string, string][] => h.map(([k, v]) => (k === 'user-agent' ? [k, ua] : [k, v]));

export const personas: Record<string, () => Persona> = {
	chrome: () => ({
		name: 'chrome',
		fingerprint: chrome131,
		http2: true,
		h2Profile: CHROME_H2,
		headers: withUA(chromeHeaders('"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"'), UA.chrome)
	}),
	edge: () => ({
		name: 'edge',
		fingerprint: chrome131, // Edge 131 is Chromium — same TLS stack
		http2: true,
		h2Profile: CHROME_H2,
		headers: withUA(chromeHeaders('"Microsoft Edge";v="131", "Chromium";v="131", "Not_A Brand";v="24"'), UA.edge)
	}),
	firefox: () => ({
		name: 'firefox',
		fingerprint: firefox148,
		http2: true,
		h2Profile: FIREFOX_H2,
		headers: [
			['user-agent', UA.firefox],
			['accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8'],
			['accept-language', 'en-US,en;q=0.5'],
			['accept-encoding', 'gzip, deflate, br, zstd'],
			['upgrade-insecure-requests', '1'],
			['sec-fetch-dest', 'document'],
			['sec-fetch-mode', 'navigate'],
			['sec-fetch-site', 'none'],
			['sec-fetch-user', '?1'],
			['priority', 'u=0, i']
		]
	}),
	safari: () => ({
		name: 'safari',
		fingerprint: clients.safari!,
		http2: true,
		h2Profile: SAFARI_H2,
		headers: [
			['accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'],
			['accept-encoding', 'gzip, deflate, br'], // Safari does not send zstd
			['user-agent', UA.safari],
			['accept-language', 'en-US,en;q=0.9'],
			['priority', 'u=0, i']
		]
	})
};

/** Resolve a persona by name or pass one through. Unknown name → error. */
export function resolvePersona(p: string | Persona): Persona {
	if (typeof p !== 'string') return p;
	const make = personas[p];
	if (!make) throw new Error(`unknown persona "${p}" (have: ${Object.keys(personas).join(', ')})`);
	return make();
}

/** A random persona (uniform over the registry) — for rotating identities across requests. */
export function randomPersona(): Persona {
	const names = Object.keys(personas);
	return personas[names[Math.floor(Math.random() * names.length)]!]!();
}

/** The persona's default headers as an ordered object (no Host — the request layer adds
 *  Host for HTTP/1.1 and :authority for HTTP/2). User headers are layered by the caller. */
export function personaHeaders(p: Persona): Record<string, string> {
	const out: Record<string, string> = {};
	for (const [k, v] of p.headers) out[k] = v;
	return out;
}
