// Web search without an API key or a browser, through bun-tls (so each request carries a
// real browser's fingerprint). Google and Bing now render results client-side or wrap them,
// so the reliable server-rendered engines are DuckDuckGo's HTML/Lite endpoints and Bing;
// Brave and Startpage gate their SEARCH endpoint on IP reputation (their homepage loads, the
// query 429s / redirects to a CAPTCHA) — the TLS fingerprint already passes, so those two
// need a clean IP via `proxy` (a residential/mobile proxy), not a different fingerprint.
import { fetch as btFetch } from './fetchlike';
import type { Persona } from '../fp/personas';

export interface SearchResult {
	title: string;
	url: string;
	snippet: string;
}

export type SearchEngine = 'duckduckgo' | 'bing' | 'brave' | 'startpage';

export interface SearchOptions {
	engine?: SearchEngine;
	/** Max results (default 10). */
	limit?: number;
	persona?: string | Persona;
	/** A proxy — required to reach Brave/Startpage from a flagged IP. `http://…` or `socks5://…`. */
	proxy?: string;
	timeoutMs?: number;
	/** Retries on a 429/503 from the engine, with backoff (default 2). */
	retries?: number;
}

const ENT: Record<string, string> = { amp: '&', lt: '<', gt: '>', quot: '"', '#39': "'", '#x27': "'", nbsp: ' ', '#0183': '·', '#183': '·' };
const decode = (s: string): string =>
	s
		.replace(/<[^>]+>/g, '')
		.replace(/&(#x?[0-9a-f]+|[a-z]+);/gi, (m, e: string) => ENT[e.toLowerCase()] ?? (e[0] === '#' ? String.fromCodePoint(e[1] === 'x' ? parseInt(e.slice(2), 16) : +e.slice(1)) : m))
		.replace(/\s+/g, ' ')
		.trim();

/** Decode Bing's /ck/a redirect wrapper → the real destination (base64url in the `u=a1…` param). */
function bingTarget(href: string): string {
	const m = href.match(/[?&]u=a1([A-Za-z0-9_-]+)/);
	if (!m) return href.startsWith('http') ? href : '';
	try {
		const b64 = m[1]!.replace(/-/g, '+').replace(/_/g, '/');
		return Buffer.from(b64 + '='.repeat((4 - (b64.length % 4)) % 4), 'base64').toString('utf8');
	} catch {
		return '';
	}
}

const PARSE: Record<SearchEngine, (html: string) => SearchResult[]> = {
	// DDG HTML/Lite: each result is an <a class="result-link" href="…/l/?uddg=<dest>">title</a>
	// followed by a <td class="result-snippet">…</td> (or <a class="result-snippet">).
	duckduckgo(html) {
		const out: SearchResult[] = [];
		const links = [...html.matchAll(/<a[^>]+href="([^"]*uddg=[^"]+)"[^>]*class=['"]result-link['"][^>]*>([\s\S]*?)<\/a>/gi)];
		const snips = [...html.matchAll(/class=['"]result-snippet['"][^>]*>([\s\S]*?)<\/(?:td|a)>/gi)].map((m) => decode(m[1]!));
		links.forEach((m, i) => {
			const uddg = m[1]!.match(/uddg=([^&"]+)/);
			const url = uddg ? decodeURIComponent(uddg[1]!) : '';
			if (url) out.push({ title: decode(m[2]!), url, snippet: snips[i] ?? '' });
		});
		return out;
	},
	bing(html) {
		const out: SearchResult[] = [];
		for (const m of html.matchAll(/<li class="b_algo"[\s\S]*?<h2>\s*<a[^>]+href="([^"]+)"[^>]*>([\s\S]*?)<\/a>[\s\S]*?(?:<p[^>]*class="[^"]*b_lineclamp[^"]*"[^>]*>([\s\S]*?)<\/p>|<\/li>)/gi)) {
			const url = bingTarget(m[1]!.replace(/&amp;/g, '&'));
			if (url) out.push({ title: decode(m[2]!), url, snippet: decode(m[3] ?? '') });
		}
		return out;
	},
	// Brave + Startpage gate their search endpoint by IP, so their result HTML can't be
	// captured from a blocked IP to pin exact selectors against. Rather than guess class
	// names, pull the organic links generically: external <a> whose anchor text reads like a
	// title (several words), first occurrence wins. Reached only through a clean `proxy`.
	brave: (html) => externalResults(html, 'brave.com'),
	startpage: (html) => externalResults(html, 'startpage.com')
};

/** Engine-agnostic result scrape: external links with a title-like anchor text, deduped by
 *  destination. Skips the engine's own domain and common asset/CDN hosts. */
function externalResults(html: string, engineDomain: string): SearchResult[] {
	const out: SearchResult[] = [];
	const seen = new Set<string>();
	const skip = new RegExp(`(?:${engineDomain.replace('.', '\\.')}|gstatic|googleapis|cloudfront|cdn\\.|w3\\.org|schema\\.org|/sorry/)`, 'i');
	for (const m of html.matchAll(/<a[^>]+href="(https?:\/\/[^"]+)"[^>]*>([\s\S]*?)<\/a>/gi)) {
		const url = m[1]!.replace(/&amp;/g, '&');
		const title = decode(m[2]!);
		if (skip.test(url) || seen.has(url) || title.split(' ').length < 2 || title.length < 8) continue;
		seen.add(url);
		out.push({ title, url, snippet: '' });
	}
	return out;
}

/** Parse an engine's result HTML into `{ title, url, snippet }[]` — exposed for HTML you
 *  captured yourself (e.g. a page fetched through your own proxy). `search()` calls it. */
export function parseSearchResults(engine: SearchEngine, html: string): SearchResult[] {
	return PARSE[engine](html);
}

function endpoint(engine: SearchEngine, q: string): string {
	const e = encodeURIComponent(q);
	switch (engine) {
		case 'duckduckgo':
			return `https://lite.duckduckgo.com/lite/?q=${e}`;
		case 'bing':
			return `https://www.bing.com/search?q=${e}`;
		case 'brave':
			return `https://search.brave.com/search?q=${e}&source=web`;
		case 'startpage':
			return `https://www.startpage.com/sp/search?query=${e}`;
	}
}

const BLOCKED = /\/sorry\/|captcha-block|too many requests|unusual traffic/i;
const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

/**
 * Search the web and get back `{ title, url, snippet }[]` — no API key, no browser.
 * `duckduckgo` (default) and `bing` work from any IP; `brave` and `startpage` gate the query
 * on IP reputation, so pass a residential `proxy` for those. Throws if the engine blocks the
 * request (429 / CAPTCHA) after the retries.
 */
export async function search(query: string, opts: SearchOptions = {}): Promise<SearchResult[]> {
	const engine = opts.engine ?? 'duckduckgo';
	const retries = opts.retries ?? 2;
	const referer = engine === 'brave' ? 'https://search.brave.com/' : engine === 'startpage' ? 'https://www.startpage.com/' : engine === 'duckduckgo' ? 'https://lite.duckduckgo.com/' : '';
	// 202 is DuckDuckGo's soft throttle on a first hit — it serves results on the retry.
	const throttled = (status: number, url: string, html: string): boolean => status === 429 || status === 503 || status === 202 || BLOCKED.test(url) || BLOCKED.test(html);
	for (let attempt = 0; ; attempt++) {
		const r = await btFetch(endpoint(engine, query), {
			persona: opts.persona ?? 'chrome',
			proxy: opts.proxy,
			timeoutMs: opts.timeoutMs ?? 20000,
			headers: referer ? { referer } : {}
		});
		const html = await r.text();
		const results = throttled(r.status, r.url, html) ? [] : PARSE[engine](html);
		// Retry a throttle, or a 2xx that parsed nothing (an interstitial before the results).
		if (!results.length && attempt < retries) {
			await sleep(700 * 2 ** attempt);
			continue;
		}
		if (throttled(r.status, r.url, html) && !results.length) {
			const hint = engine === 'brave' || engine === 'startpage' ? ` — ${engine} gates its search endpoint by IP; pass a residential \`proxy\`` : '';
			throw new Error(`search: ${engine} blocked the request (status ${r.status})${hint}`);
		}
		return results.slice(0, opts.limit ?? 10);
	}
}
