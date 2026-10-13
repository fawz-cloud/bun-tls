// LLM-ready scraping: fetch a page through bun-tls (so it clears the fingerprint WAF) and
// hand back TOKEN-CHEAP structured data instead of raw HTML — JSON-LD / OpenGraph / meta
// (the structured data sites already embed), a readable Markdown rendering of the main
// content, and resolved links/images. A 200 KB page (~50k tokens) becomes a few KB.
// Zero dependencies: uses Bun's native HTMLRewriter (streaming HTML parser).
import { fetch as btFetch, type FetchInit } from './fetchlike';

export interface ScrapeResult {
	url: string;
	status: number;
	title: string;
	description: string;
	canonical: string;
	/** OpenGraph (og:*) without the prefix. */
	og: Record<string, string>;
	/** Twitter card (twitter:*) without the prefix. */
	twitter: Record<string, string>;
	/** Other <meta name=…> values. */
	meta: Record<string, string>;
	/** Parsed JSON-LD blocks (schema.org Product/Article/etc.) — the richest, cheapest data. */
	jsonld: unknown[];
	/** Main content as Markdown (boilerplate stripped). Empty unless `as` includes it. */
	markdown: string;
	links: { href: string; text: string }[];
	images: { src: string; alt: string }[];
}

export interface ScrapeOptions extends Omit<FetchInit, 'method' | 'body'> {
	/** What to produce: 'data' = structured only (cheapest); 'markdown'/'readable' add content
	 *  (readable also drops nav/header/footer/aside); 'auto' (default) = everything. */
	as?: 'data' | 'markdown' | 'readable' | 'auto';
	/** Truncate the Markdown to this many characters (token budget). */
	maxChars?: number;
}

const abs = (href: string | null, base: string): string => {
	if (!href) return '';
	try {
		return new URL(href, base).toString();
	} catch {
		return href;
	}
};

const decode = (s: string): string =>
	s
		.replace(/&amp;/g, '&')
		.replace(/&lt;/g, '<')
		.replace(/&gt;/g, '>')
		.replace(/&quot;/g, '"')
		.replace(/&#39;/g, "'")
		.replace(/&nbsp;/g, ' ')
		.replace(/&#(\d+);/g, (_, n) => String.fromCodePoint(+n));

/** Pass 1 — pull structured data (title/meta/og/twitter/canonical/JSON-LD/links/images). */
async function extractData(html: string, base: string): Promise<Omit<ScrapeResult, 'url' | 'status' | 'markdown'>> {
	const og: Record<string, string> = {};
	const twitter: Record<string, string> = {};
	const meta: Record<string, string> = {};
	const jsonld: unknown[] = [];
	const links: { href: string; text: string }[] = [];
	const images: { src: string; alt: string }[] = [];
	let title = '';
	let description = '';
	let canonical = '';
	let inTitle = false;
	let inLd = false;
	let ld = '';

	const rw = new HTMLRewriter()
		.on('title', { element: () => void (inTitle = true), text: (t) => { if (inTitle) title += t.text; if (t.lastInTextNode) inTitle = false; } })
		.on('link[rel=canonical]', { element: (e) => void (canonical = abs(e.getAttribute('href'), base)) })
		.on('meta', {
			element(e) {
				const prop = (e.getAttribute('property') || '').toLowerCase();
				const name = (e.getAttribute('name') || '').toLowerCase();
				const content = e.getAttribute('content') || '';
				if (prop.startsWith('og:')) og[prop.slice(3)] = content;
				else if (name.startsWith('twitter:')) twitter[name.slice(8)] = content;
				else if (name === 'description') description = content;
				else if (name) meta[name] = content;
			}
		})
		.on('script', {
			element(e) {
				inLd = (e.getAttribute('type') || '').toLowerCase().includes('ld+json');
				if (inLd) {
					ld = '';
					e.onEndTag(() => {
						try {
							jsonld.push(JSON.parse(ld.trim()));
						} catch {
							/* malformed block — skip */
						}
						inLd = false;
					});
				}
			},
			text(t) {
				if (inLd) ld += t.text;
			}
		})
		.on('a[href]', {
			element(e) {
				const href = abs(e.getAttribute('href'), base);
				if (href && !href.startsWith('javascript:')) links.push({ href, text: '' });
			}
		})
		.on('img[src]', { element: (e) => void images.push({ src: abs(e.getAttribute('src'), base), alt: e.getAttribute('alt') || '' }) });

	await rw.transform(new Response(html)).arrayBuffer();
	return { title: decode(title).trim(), description, canonical, og, twitter, meta, jsonld, links, images };
}

const BLOCK = 'p,div,section,article,main,ul,ol,tr,table,figure,figcaption,header,footer,blockquote';
const DROP = 'script,style,noscript,svg,iframe,head,template,link,meta,form,button,input,select,textarea';

/** Pass 2 — render the body to Markdown. Boilerplate elements are REMOVED (their content
 *  leaves the output stream), Markdown markers are injected around the kept elements, then
 *  we take the transformed output and strip any residual tags. Removal is what keeps
 *  script/style/nav text out — a manual text collector would still see those nodes. */
async function toMarkdown(html: string, readable: boolean): Promise<string> {
	const h = (n: number) => '\n\n' + '#'.repeat(n) + ' ';
	const rw = new HTMLRewriter()
		.on(readable ? `${DROP},nav,aside` : DROP, { element: (e) => { e.remove(); } })
		.on('h1,h2,h3,h4,h5,h6', { element: (e) => { e.before(h(+e.tagName[1]!), { html: false }); e.onEndTag((t) => { t.after('\n\n', { html: false }); }); } })
		.on(BLOCK, { element: (e) => { e.before('\n', { html: false }); } })
		.on('li', { element: (e) => { e.before('\n- ', { html: false }); } })
		.on('br', { element: (e) => { e.before('\n', { html: false }); } })
		.on('hr', { element: (e) => { e.before('\n\n---\n\n', { html: false }); } })
		.on('a[href]', { element: (e) => { const u = e.getAttribute('href'); e.before('[', { html: false }); e.onEndTag((t) => { t.after(`](${u})`, { html: false }); }); } })
		.on('strong,b', { element: (e) => { e.before('**', { html: false }); e.onEndTag((t) => { t.after('**', { html: false }); }); } })
		.on('em,i', { element: (e) => { e.before('_', { html: false }); e.onEndTag((t) => { t.after('_', { html: false }); }); } })
		.on('code', { element: (e) => { e.before('`', { html: false }); e.onEndTag((t) => { t.after('`', { html: false }); }); } });

	const out = await rw.transform(new Response(html)).text();
	return decode(out.replace(/<[^>]+>/g, '')) // drop residual tags; injected markers survive
		.replace(/[ \t]+/g, ' ')
		.replace(/ *\n */g, '\n')
		.replace(/\n{3,}/g, '\n\n')
		.trim();
}

/** Fetch a URL via bun-tls and return LLM-ready structured data + Markdown. */
export async function scrape(url: string, opts: ScrapeOptions = {}): Promise<ScrapeResult> {
	const as = opts.as ?? 'auto';
	const r = await btFetch(url, { persona: opts.persona ?? 'chrome', http2: opts.http2, fingerprint: opts.fingerprint, proxy: opts.proxy, verify: opts.verify, tls12: opts.tls12, http3: opts.http3, headers: opts.headers, timeoutMs: opts.timeoutMs });
	const html = await r.text();
	const data = await extractData(html, url);
	let markdown = '';
	if (as === 'markdown' || as === 'readable' || as === 'auto') {
		markdown = await toMarkdown(html, as === 'readable');
		if (opts.maxChars && markdown.length > opts.maxChars) markdown = markdown.slice(0, opts.maxChars) + '\n…[truncated]';
	}
	// fill anchor text into links for the top ones (cheap: from the markdown pass we skipped text;
	// leave link.text empty — the href list is the useful part for crawl/LLM).
	return { url, status: r.status, markdown, ...data };
}
