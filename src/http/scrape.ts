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
	/** Cleaned HTML (script/style/boilerplate removed) — only when 'html' is requested. */
	html?: string;
	/** Records from a CSS `extract` schema — only when `extract` is given. */
	extracted?: Record<string, string>[];
}

/** CSS-selector extraction (like crawl4ai's JsonCssExtractionStrategy): one record per
 *  `baseSelector` match, each field read from a descendant selector (text, or an attribute). */
export interface CssSchema {
	baseSelector: string;
	fields: { name: string; selector?: string; attr?: string }[];
}

export type Format = 'markdown' | 'readable' | 'html' | 'links' | 'json' | 'text';

export interface ScrapeOptions extends Omit<FetchInit, 'method' | 'body'> {
	/** Firecrawl-style output selection. Default ['markdown']. 'json' = the structured data
	 *  (jsonld/og/meta), 'html' = cleaned HTML, 'readable' = main-content Markdown. */
	formats?: Format[];
	/** Shorthand (back-compat): 'data'→['json'], 'markdown', 'readable', 'auto'→everything. */
	as?: 'data' | 'markdown' | 'readable' | 'auto';
	/** Drop nav/header/footer/aside in the Markdown/HTML (main content only). */
	onlyMainContent?: boolean;
	/** CSS-schema extraction → ScrapeResult.extracted. */
	extract?: CssSchema;
	/** Prune low-value blocks (nav/menu residue, link-dense short blocks) from the Markdown. */
	fit?: boolean;
	/** Truncate the Markdown to this many characters (token budget). */
	maxChars?: number;
}

/** An LLM call: a function you provide, or an OpenAI-compatible chat endpoint (OpenAI,
 *  Ollama at http://localhost:11434/v1/chat/completions, any compatible gateway). */
export type LlmFn = (prompt: string) => Promise<string>;
export interface LlmConfig {
	endpoint: string;
	apiKey?: string;
	model: string;
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

/** Cleaned HTML: boilerplate removed, noisy attributes (class, style, on-handlers, data-) stripped. */
async function cleanHtml(html: string, readable: boolean): Promise<string> {
	const rw = new HTMLRewriter()
		.on(readable ? `${DROP},nav,aside` : DROP, { element: (e) => { e.remove(); } })
		.on('*', { element: (e) => { for (const [k] of e.attributes) if (/^(class|style|on|data-)/i.test(k)) e.removeAttribute(k); } });
	return (await rw.transform(new Response(html)).text()).replace(/\n{3,}/g, '\n\n').trim();
}

/** CSS-schema extraction: one record per baseSelector match; fields read as text or attr. */
async function extractSchema(html: string, schema: CssSchema): Promise<Record<string, string>[]> {
	const records: Record<string, string>[] = [];
	let cur: Record<string, string> | null = null;
	const rw = new HTMLRewriter().on(schema.baseSelector, {
		element(e) {
			cur = {};
			records.push(cur);
			e.onEndTag(() => { cur = null; });
		}
	});
	for (const f of schema.fields) {
		const sel = f.selector ? `${schema.baseSelector} ${f.selector}` : schema.baseSelector;
		rw.on(sel, {
			element(e) {
				if (cur && f.attr) cur[f.name] = e.getAttribute(f.attr) ?? '';
			},
			text(t) {
				if (cur && !f.attr) cur[f.name] = ((cur[f.name] ?? '') + t.text).trim();
			}
		});
	}
	await rw.transform(new Response(html)).arrayBuffer();
	return records.map((r) => Object.fromEntries(Object.entries(r).map(([k, v]) => [k, decode(v).trim()])));
}

/** Drop low-value Markdown blocks (nav/menu residue): link-dense short blocks and link-only
 *  lists. Keeps headings and text-dense paragraphs (crawl4ai's "fit markdown" idea, heuristic). */
export function fitMarkdown(md: string): string {
	const linkRe = /\[[^\]]*\]\([^)]*\)/g;
	return md
		.split(/\n{2,}/)
		.filter((raw) => {
			const t = raw.trim();
			if (!t) return false;
			if (/^#{1,6}\s/.test(t)) return true; // keep headings
			const linkChars = (t.match(linkRe) || []).join('').length;
			const density = linkChars / t.length;
			if (density > 0.6 && t.length < 400) return false; // nav / link list
			if (t.length < 30 && density > 0.3) return false; // stray menu link
			return true;
		})
		.join('\n\n')
		.replace(/\n{3,}/g, '\n\n')
		.trim();
}

const AS_FORMATS: Record<string, Format[]> = { data: ['json'], markdown: ['markdown', 'json'], readable: ['readable', 'json'], auto: ['markdown', 'json', 'links'] };

/** Fetch a URL via bun-tls and return LLM-ready output (Firecrawl-style `formats`). */
export async function scrape(url: string, opts: ScrapeOptions = {}): Promise<ScrapeResult> {
	const formats = new Set<Format>(opts.formats ?? AS_FORMATS[opts.as ?? 'auto']!);
	const readable = opts.onlyMainContent ?? (opts.as === 'readable' || formats.has('readable'));
	const r = await btFetch(url, { persona: opts.persona ?? 'chrome', http2: opts.http2, fingerprint: opts.fingerprint, proxy: opts.proxy, verify: opts.verify, tls12: opts.tls12, http3: opts.http3, headers: opts.headers, timeoutMs: opts.timeoutMs });
	const html = await r.text();
	const data = await extractData(html, url); // structured data is cheap — always available

	let markdown = '';
	if (formats.has('markdown') || formats.has('readable') || formats.has('text')) {
		markdown = await toMarkdown(html, readable);
		if (opts.fit) markdown = fitMarkdown(markdown);
		if (opts.maxChars && markdown.length > opts.maxChars) markdown = markdown.slice(0, opts.maxChars) + '\n…[truncated]';
	}
	const result: ScrapeResult = { url, status: r.status, markdown, ...data };
	if (formats.has('html')) result.html = await cleanHtml(html, readable);
	if (opts.extract) result.extracted = await extractSchema(html, opts.extract);
	return result;
}

async function callLlm(llm: LlmFn | LlmConfig, prompt: string): Promise<string> {
	if (typeof llm === 'function') return llm(prompt);
	const res = await globalThis.fetch(llm.endpoint, {
		method: 'POST',
		headers: { 'content-type': 'application/json', ...(llm.apiKey ? { authorization: `Bearer ${llm.apiKey}` } : {}) },
		body: JSON.stringify({ model: llm.model, messages: [{ role: 'user', content: prompt }], temperature: 0, response_format: { type: 'json_object' } })
	});
	const j = (await res.json()) as { choices?: { message?: { content?: string } }[] };
	return j.choices?.[0]?.message?.content ?? '';
}

export interface ExtractLLMOptions extends ScrapeOptions {
	/** JSON Schema the output should match (sent to the model as a contract). */
	schema?: object;
	/** Extra instruction, e.g. "Extract the product name, price and rating." */
	prompt?: string;
	/** The LLM to call — a function, or an OpenAI-compatible endpoint config. */
	llm: LlmFn | LlmConfig;
	/** Feed the model Markdown (default) or cleaned HTML. */
	from?: 'markdown' | 'html';
}

/**
 * LLM-powered structured extraction (like Firecrawl's Agent / crawl4ai's LLMExtractionStrategy):
 * scrape the page to Markdown (or HTML), hand it to your LLM with the schema + prompt, and
 * return the parsed JSON. bun-tls does the fetch (clearing the WAF) and token-cheap Markdown;
 * you bring any model (OpenAI, a local Ollama endpoint, or your own function).
 */
export async function extractLLM(url: string, opts: ExtractLLMOptions): Promise<unknown> {
	const from = opts.from ?? 'markdown';
	const r = await scrape(url, { ...opts, formats: from === 'html' ? ['html'] : ['markdown'], fit: opts.fit ?? true, maxChars: opts.maxChars ?? 16000 });
	const content = (from === 'html' ? r.html : r.markdown) ?? '';
	const prompt =
		`${opts.prompt ?? 'Extract the structured data from the content below.'}\n\n` +
		`Return ONLY a valid JSON object${opts.schema ? ' matching this JSON Schema:\n' + JSON.stringify(opts.schema) : ''}. No prose, no code fences.\n\n` +
		`--- CONTENT (${url}) ---\n${content}`;
	const raw = await callLlm(opts.llm, prompt);
	const text = raw.trim().replace(/^```(?:json)?\s*/i, '').replace(/```$/i, '').trim();
	try {
		return JSON.parse(text);
	} catch {
		const m = text.match(/\{[\s\S]*\}/);
		if (m) try { return JSON.parse(m[0]); } catch { /* fall through */ }
		return { _raw: raw };
	}
}
