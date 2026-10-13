// Crawling on top of scrape(): follow same-origin links (crawl), discover URLs from
// sitemaps + robots.txt (map), and fetch many URLs concurrently (batch). All run through
// bun-tls, so the whole crawl carries the chosen persona's fingerprint.
import { fetch as btFetch } from './fetchlike';
import { scrape, type ScrapeOptions, type ScrapeResult } from './scrape';

export interface CrawlOptions extends ScrapeOptions {
	/** Max pages to fetch (default 20). */
	limit?: number;
	/** Max link depth from the start URL (default 2). */
	depth?: number;
	/** Pages fetched in parallel (default 5). */
	concurrency?: number;
	/** Stay on the start URL's origin (default true). */
	sameOrigin?: boolean;
	/** Only follow URLs matching this. */
	allow?: RegExp;
	/** Never follow URLs matching this. */
	deny?: RegExp;
}

/** Strip the fragment so #a and #b aren't treated as different pages. */
function norm(href: string): string {
	try {
		const u = new URL(href);
		u.hash = '';
		return u.toString();
	} catch {
		return '';
	}
}

/** Breadth-first crawl of same-origin links from `start`, up to depth/limit. */
export async function crawl(start: string, opts: CrawlOptions = {}): Promise<{ pages: ScrapeResult[]; count: number }> {
	const limit = opts.limit ?? 20;
	const maxDepth = opts.depth ?? 2;
	const conc = opts.concurrency ?? 5;
	const origin = new URL(start).origin;
	const scrapeOpts: ScrapeOptions = { ...opts, formats: opts.formats ?? ['markdown', 'json', 'links'] };
	const seen = new Set<string>([norm(start)]);
	let queue: { url: string; depth: number }[] = [{ url: start, depth: 0 }];
	const pages: ScrapeResult[] = [];

	while (queue.length && pages.length < limit) {
		const wave = queue.splice(0, conc);
		const results = await Promise.all(wave.map(async ({ url, depth }) => {
			try {
				return { r: await scrape(url, scrapeOpts), depth };
			} catch {
				return null;
			}
		}));
		for (const item of results) {
			if (!item || pages.length >= limit) continue;
			pages.push(item.r);
			if (item.depth >= maxDepth) continue;
			for (const l of item.r.links) {
				const u = norm(l.href);
				if (!u || seen.has(u)) continue;
				if (opts.sameOrigin !== false && new URL(u).origin !== origin) continue;
				if (opts.deny && opts.deny.test(u)) continue;
				if (opts.allow && !opts.allow.test(u)) continue;
				if (seen.size >= limit * 50) break; // bound the frontier
				seen.add(u);
				queue.push({ url: u, depth: item.depth + 1 });
			}
		}
	}
	return { pages, count: pages.length };
}

export interface MapOptions extends Omit<ScrapeOptions, 'formats' | 'as' | 'extract'> {
	/** Max URLs to return (default 5000). */
	limit?: number;
	/** Rank URLs containing this substring first. */
	search?: string;
}

/** Discover a site's URLs from robots.txt sitemaps + sitemap.xml + the homepage links. */
export async function map(url: string, opts: MapOptions = {}): Promise<{ links: string[] }> {
	const limit = opts.limit ?? 5000;
	const origin = new URL(url).origin;
	const persona = opts.persona ?? 'chrome';
	const found = new Set<string>();
	const get = async (u: string): Promise<string> => {
		try {
			const r = await btFetch(u, { persona, timeoutMs: opts.timeoutMs ?? 15000, proxy: opts.proxy, verify: opts.verify });
			return r.status === 200 ? await r.text() : '';
		} catch {
			return '';
		}
	};

	const smQueue: string[] = [];
	const smSeen = new Set<string>();
	for (const m of (await get(origin + '/robots.txt')).matchAll(/sitemap:\s*(\S+)/gi)) smQueue.push(m[1]!.trim());
	if (!smQueue.length) smQueue.push(origin + '/sitemap.xml');
	// Walk the sitemap tree: a <loc> ending in .xml (or inside a <sitemapindex>) is a
	// SUB-sitemap to fetch, anything else is a page URL. Bounded number of fetches.
	for (let fetches = 0; smQueue.length && found.size < limit && fetches < 40; fetches++) {
		const sm = smQueue.shift()!;
		if (smSeen.has(sm)) continue;
		smSeen.add(sm);
		for (const m of (await get(sm)).matchAll(/<loc>\s*([^<\s]+)\s*<\/loc>/gi)) {
			const loc = m[1]!.trim();
			if (/\.xml(\.gz)?$/i.test(loc) || /sitemap/i.test(loc)) {
				if (!smSeen.has(loc)) smQueue.push(loc);
			} else found.add(loc);
			if (found.size >= limit) break;
		}
	}
	if (found.size < limit) {
		try {
			for (const l of (await scrape(url, { formats: ['links'], persona, proxy: opts.proxy, verify: opts.verify })).links) found.add(l.href);
		} catch {
			/* homepage link fallback failed */
		}
	}
	let links = [...found];
	if (opts.search) {
		const q = opts.search.toLowerCase();
		const hit = links.filter((l) => l.toLowerCase().includes(q));
		links = hit.concat(links.filter((l) => !l.toLowerCase().includes(q)));
	}
	return { links: links.slice(0, limit) };
}

/** Scrape many URLs concurrently (default 5 at a time). */
export async function batch(urls: string[], opts: ScrapeOptions & { concurrency?: number } = {}): Promise<ScrapeResult[]> {
	const conc = opts.concurrency ?? 5;
	const out: ScrapeResult[] = [];
	let i = 0;
	const worker = async () => {
		while (i < urls.length) {
			const u = urls[i++]!;
			try {
				out.push(await scrape(u, opts));
			} catch (e) {
				out.push({ url: u, status: 0, title: '', description: '', canonical: '', og: {}, twitter: {}, meta: {}, jsonld: [], markdown: '', links: [], images: [] });
			}
		}
	};
	await Promise.all(Array.from({ length: Math.min(conc, urls.length) }, worker));
	return out;
}
