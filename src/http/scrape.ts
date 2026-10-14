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
	/** The most token-efficient representation that still carries the full context: the
	 *  structured data (JSON-LD/OG) first, then the main text with URLs stripped + deduped.
	 *  Only when 'llm' is requested. */
	llm?: string;
}

/** CSS-selector extraction (like crawl4ai's JsonCssExtractionStrategy): one record per
 *  `baseSelector` match, each field read from a descendant selector (text, or an attribute). */
export interface CssSchema {
	baseSelector: string;
	fields: { name: string; selector?: string; attr?: string }[];
}

export type Format = 'markdown' | 'readable' | 'html' | 'links' | 'json' | 'text' | 'llm';

export interface ScrapeOptions extends Omit<FetchInit, 'method' | 'body'> {
	/** Firecrawl-style output selection; default from `as` ('auto' = ['markdown', 'json',
	 *  'links']). 'markdown' (or 'text') = Markdown, 'readable' = main-content Markdown,
	 *  'html' = cleaned HTML, 'llm' = the LLM view. The structured data and links are always
	 *  extracted (one cheap pass), so 'json' and 'links' only name what you want back. */
	formats?: Format[];
	/** Shorthand: 'llm' = the token-cheapest full-context view (recommended for LLMs);
	 *  'data' = structured only; 'markdown'/'readable'; 'auto' = everything. */
	as?: 'llm' | 'data' | 'markdown' | 'readable' | 'auto';
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

// ponytail: the common named entities only; an unknown one stays literal. Numeric
// references (&#39; and &#x27;) decode generically.
const ENTITIES: Record<string, string> = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', ensp: ' ', emsp: ' ', thinsp: ' ', shy: '', zwj: '', zwnj: '', ndash: '–', mdash: '—', hellip: '…', lsquo: '‘', rsquo: '’', sbquo: '‚', ldquo: '“', rdquo: '”', bdquo: '„', laquo: '«', raquo: '»', bull: '•', middot: '·', copy: '©', reg: '®', trade: '™', deg: '°', times: '×', divide: '÷', plusmn: '±', euro: '€', pound: '£', yen: '¥', cent: '¢', sect: '§', para: '¶', larr: '←', rarr: '→', uarr: '↑', darr: '↓', harr: '↔', hearts: '♥', check: '✓', star: '☆' };
const decode = (s: string): string =>
	s.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (m, e: string) => {
		if (e[0] !== '#') return ENTITIES[e] ?? ENTITIES[e.toLowerCase()] ?? m;
		const n = e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : +e.slice(1);
		return n > 0 && n <= 0x10ffff ? String.fromCodePoint(n) : m;
	});

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
	let titles = 0;
	let inLd = false;
	let ld = '';
	let link: { href: string; text: string } | null = null;

	const rw = new HTMLRewriter()
		// Only the document <title>: inline SVG icons carry <title> elements of their own.
		.on('title', { element: () => void (inTitle = titles++ === 0), text: (t) => { if (inTitle) title += t.text; if (t.lastInTextNode) inTitle = false; } })
		.on('link[rel=canonical]', { element: (e) => void (canonical = abs(e.getAttribute('href'), base)) })
		.on('meta', {
			element(e) {
				const prop = (e.getAttribute('property') || '').toLowerCase();
				const name = (e.getAttribute('name') || '').toLowerCase();
				const content = decode(e.getAttribute('content') || '');
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
				link = href && !href.startsWith('javascript:') ? { href, text: '' } : null;
				if (link) links.push(link);
			},
			text(t) {
				if (link) link.text += t.text;
			}
		})
		.on('img[src]', { element: (e) => void images.push({ src: abs(e.getAttribute('src'), base), alt: e.getAttribute('alt') || '' }) });

	await rw.transform(new Response(html)).arrayBuffer();
	for (const l of links) l.text = squash(decode(l.text));
	return { title: decode(title).trim(), description, canonical, og, twitter, meta, jsonld, links, images };
}

const BLOCK = 'p,div,section,article,main,ul,ol,dl,dt,tr,table,figure,figcaption,header,footer,blockquote,details,summary';
// No <form>: ASP.NET-style pages wrap the whole body in one. <title> is listed for fragments
// with no <head> (the title is read separately).
const DROP = 'script,style,noscript,svg,iframe,head,title,template,link,meta,button,input,select,textarea';
// Page chrome dropped in readable mode — Firecrawl's onlyMainContent set minus <header>,
// which often holds the article title — plus language-switcher links (hreflang) and
// MediaWiki "[edit]" section links.
const CHROME = 'nav,aside,footer,dialog,[role=navigation],[role=contentinfo],[role=search],[role=dialog],a[hreflang],.mw-editsection';

// Private-use sentinels the rewriter injects (never in real text): a line break we emit,
// the bounds of a <pre> block, the bounds of an in-page anchor link.
const [NL, PRE, PRE_END, ANCHOR, ANCHOR_END] = [0xe000, 0xe001, 0xe002, 0xe003, 0xe004].map((c) => String.fromCharCode(c)) as [string, string, string, string, string];
const ANCHORED = new RegExp(`${ANCHOR}([^${ANCHOR}${ANCHOR_END}]*)${ANCHOR_END}`, 'g');
// In-page anchor text that is pure navigation: citation markers [1], footnote numbers,
// heading permalinks (#, ¶), back-references (↑, ^), "Skip to content" links.
const ANCHOR_JUNK = /^(\[[^\]]{0,20}\]|\d{1,3}|[a-z]|[#¶§↑^*†‡]+|(skip|jump) to\b.*)$/i;

/** Text outside <pre>: HTML whitespace semantics (a source whitespace run is one space, line
 *  breaks only where we injected NL), then drop what is left of empty cells/bullets/headings. */
function tidy(s: string): string {
	return decode(s)
		.replace(/\s+/g, ' ')
		.replaceAll(NL, '\n')
		.replace(/ *\n */g, '\n')
		.replace(/(\| )+/g, '| ')
		.replace(/^\| /gm, '')
		.replace(/( \|)+$/gm, '')
		.replace(/^([-*•·|]|#{1,6})$/gm, '')
		.replace(/ +$/, '');
}

/** Pass 2 — render the body to Markdown. `plain` is the LLM view: no link URLs or emphasis
 *  markers, in-page anchor junk dropped. Boilerplate elements are REMOVED (their content
 *  leaves the stream) and every other tag is unwrapped by the rewriter itself, so attribute
 *  values containing '>' can't leak the way a tag-stripping regex lets them. */
async function toMarkdown(html: string, base: string, readable: boolean, plain = false): Promise<string> {
	const text = { html: false };
	const emphasis: Record<string, string> = plain ? {} : { strong: '**', b: '**', em: '_', i: '_' };
	let pre = 0;
	let code = 0;
	let cell = 0;
	// An inline element's end tag was the last thing emitted. Element-after-element with no
	// whitespace between is visually separated by CSS (flex rows, tag pills, label/value
	// spans), so a space goes in: "Kõrgus 24 cm", not "Kõrgus24 cm". Not inside code.
	let glued = false;
	const rw = new HTMLRewriter()
		.on(readable ? `${DROP},${CHROME}` : DROP, { element: (e) => { e.remove(); } })
		.on('pre', { element: (e) => { if (pre++ === 0) e.before(PRE, text); e.onEndTag((t) => { if (--pre === 0) t.after(PRE_END, text); }); } })
		.on('h1,h2,h3,h4,h5,h6', { element: (e) => { e.before(NL + NL + '#'.repeat(+e.tagName[1]!) + ' ', text); e.onEndTag((t) => { t.after(NL + NL, text); }); } })
		.on(BLOCK, { element: (e) => { e.before(NL, text); } })
		.on('tr', { element: () => void (cell = 0) })
		.on('td,th', { element: (e) => { if (cell++) e.before(' | ', text); } })
		.on('dd', { element: (e) => { e.before(': ', text); } })
		.on('li', { element: (e) => { e.before(NL + '- ', text); } })
		.on('br', { element: (e) => { e.before(NL, text); } })
		.on('hr', { element: (e) => { e.before(NL + NL + '---' + NL + NL, text); } })
		// One handler per inline element: an element keeps only its last onEndTag callback.
		.on('a,code,span,strong,b,em,i,small,label,time,abbr,mark,data,cite', {
			element(e) {
				if (e.removed) return; // before/after text would outlive a removed element
				const tag = e.tagName;
				const href = tag === 'a' ? e.getAttribute('href') : null;
				const lead = glued && !pre && !code ? ' ' : '';
				glued = false;
				let open = '';
				let close = '';
				if (tag === 'code') {
					if (!pre) open = close = '`';
					code++;
				} else if (href !== null) {
					// plain: no URLs, but in-page anchors are marked so their junk text can go
					if (!plain) [open, close] = ['[', `](${abs(href, base)})`];
					else if (href.startsWith('#')) [open, close] = [ANCHOR, ANCHOR_END];
				} else if (emphasis[tag]) open = close = emphasis[tag];
				open = lead + open;
				if (open) e.before(open, text);
				e.onEndTag((t) => {
					if (close) t.after(close, text);
					if (tag === 'code') code--;
					glued = true;
				});
			}
		})
		.on('*', { element: (e) => { if (!e.removed) e.removeAndKeepContent(); } })
		.onDocument({ comments: (c) => { c.remove(); }, text: (t) => { if (t.text) glued = false; } });

	let out = (await rw.transform(new Response(html)).text()).replace(/<!doctype[^>]*>/gi, '');
	if (plain) out = out.replace(ANCHORED, (_, t: string) => (ANCHOR_JUNK.test(decode(t).replaceAll(NL, '').trim()) ? '' : t));
	// <pre> content stays verbatim — indentation is meaning in code — and fenced.
	return out
		.split(PRE)
		.map((seg, i) => {
			if (!i) return tidy(seg);
			const [code = '', rest = ''] = seg.split(PRE_END);
			return '\n```\n' + decode(code).replaceAll(NL, '\n').replace(/^\n|\s+$/g, '') + '\n```\n' + tidy(rest);
		})
		.join('')
		.replace(/\n{3,}/g, '\n\n')
		.trim();
}

/** Cleaned HTML: boilerplate removed, noisy attributes (class, style, on-handlers, data-) stripped. */
async function cleanHtml(html: string, readable: boolean): Promise<string> {
	const rw = new HTMLRewriter()
		.on(readable ? `${DROP},${CHROME}` : DROP, { element: (e) => { e.remove(); } })
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

// Citation bookkeeping in CS1 style (Wikipedia and most MediaWiki sites): archive/access
// dates and database IDs. ponytail: English citation styles only; stripped only on
// citation lines (a dated "Retrieved"/"Archived" line, or a list item under a references
// heading), so an ISBN in a shop's product text stays.
const DATE = String.raw`(?:\d{4}-\d{2}-\d{2}|\d{1,2} [A-Z][a-z]+ \d{4}|[A-Z][a-z]+ \d{1,2}, \d{4})`;
const CITE_DATES = new RegExp(String.raw`\s*(?:Archived(?: \(PDF\))? from the original on ${DATE}|Retrieved (?:on )?${DATE})\.`, 'g');
const CITE_IDS = /\s*\b(?:doi|ISSN|eISSN|ISBN|S2CID|Bibcode|OCLC|PMID|PMC|arXiv|hdl|JSTOR|LCCN|OSTI|SSRN|Zbl|MR)\b:?\s?[\w.\-/():]+\.?/g;
const REFS_HEADING = /^#{1,6} (references|notes|citations|sources|bibliography|works cited|footnotes)\b/i;

/** Remove repeats and bookkeeping from the prose, leaving fenced code blocks untouched: a
 *  code block is atomic — never split on a blank line inside it, never deduped. In the prose
 *  it drops consecutive duplicate lines (blank lines between don't count; a line repeating
 *  the heading above it neither), lines seen before once they are 80+ chars (a repeated long
 *  sentence is boilerplate, not a per-item value), whole repeated paragraphs, and citation
 *  archive/access dates + IDs. A short line is never deduped on its own — "2 hrs ago" or "€4"
 *  repeat once per item, and dropping the copy would detach it from its item. */
function condense(s: string): string {
	const seenLine = new Set<string>();
	const seenBlock = new Set<string>();
	const out: string[] = [];
	let refs = false;
	// Split out fenced code blocks (the odd parts); condense only the prose between them.
	for (const part of s.split(/(```\n[\s\S]*?\n```)/g)) {
		if (!part) continue;
		if (part.startsWith('```')) {
			out.push(part);
			continue;
		}
		const lines: string[] = [];
		let prev = '';
		for (let line of part.split('\n')) {
			if (line.startsWith('#')) refs = REFS_HEADING.test(line);
			const undated = line.replace(CITE_DATES, '');
			if (undated !== line || (refs && line.startsWith('- '))) line = undated.replace(CITE_IDS, '');
			if (line && (line === prev || line === prev.replace(/^#{1,6} /, '') || (line.length >= 80 && seenLine.has(line)))) continue;
			if (line.length >= 80) seenLine.add(line);
			lines.push(line);
			if (line) prev = line;
		}
		for (const b of lines.join('\n').split(/\n\n+/)) {
			if (b.length < 40 && !b.includes('\n')) out.push(b); // short line: a per-item value, keep
			else if (!seenBlock.has(b)) { out.push(b); seenBlock.add(b); }
		}
	}
	return out.join('\n\n').replace(/\n{3,}/g, '\n\n').trim();
}

const squash = (s: string): string => s.replace(/\s+/g, ' ').trim();

// Keys that are pure boilerplate or URL/media (tokens without text meaning) and whole
// block @types that are navigation/media rather than content. Dropped from the LLM view —
// the names/prices/descriptions/ratings that carry meaning stay; see ScrapeResult.jsonld
// for the untouched data.
const JSONLD_DROP_KEYS = new Set(['@context', '@id', 'url', 'image', 'logo', 'sameAs', 'contentUrl', 'thumbnailUrl', 'thumbnail', 'embedUrl', 'encoding', 'encodingFormat', 'potentialAction', 'mainEntityOfPage', 'isPartOf', 'publisher']);
const JSONLD_DROP_TYPES = new Set(['BreadcrumbList', '3DModel', 'WebSite', 'WebPage', 'ImageObject', 'VideoObject', 'SearchAction', 'ListItem']);

/** JSON-LD condensed for an LLM: navigation/media blocks and boilerplate keys dropped, URL
 *  values dropped (schema.org enums shortened: …/InStock → InStock), strings the page text
 *  already carries dropped, empties pruned. `printed` = the squashed text around it. */
function minifyJsonld(blocks: unknown[], printed: string): string {
	const strip = (v: unknown): unknown => {
		if (typeof v === 'string') {
			if (/^https?:\/\/schema\.org\/\w+$/i.test(v)) return v.slice(v.lastIndexOf('/') + 1);
			if (/^(https?:)?\/\/\S+$/i.test(v)) return undefined;
			const s = squash(decode(v).replace(/<\/?[a-z][^>]*>/gi, ' '));
			return s && !(s.length >= 40 && printed.includes(s)) ? s : undefined;
		}
		if (Array.isArray(v)) {
			const a = v.map(strip).filter((x) => x !== undefined);
			return a.length ? a : undefined;
		}
		if (v && typeof v === 'object') {
			const o: Record<string, unknown> = {};
			for (const [k, val] of Object.entries(v)) {
				const s = JSONLD_DROP_KEYS.has(k) ? undefined : strip(val);
				if (s !== undefined) o[k] = s;
			}
			return Object.keys(o).some((k) => k !== '@type') ? o : undefined;
		}
		return v;
	};
	const typeOf = (b: unknown): string => (b && typeof b === 'object' ? String((b as Record<string, unknown>)['@type'] ?? '') : '');
	const flat = blocks.flatMap((b) => (b && typeof b === 'object' && '@graph' in (b as object) ? ((b as { '@graph': unknown[] })['@graph'] as unknown[]) : [b]));
	const kept = flat.filter((b) => !JSONLD_DROP_TYPES.has(typeOf(b))).map(strip).filter((b) => b !== undefined);
	return kept.length ? JSON.stringify(kept.length === 1 ? kept[0] : kept) : '';
}

/** The token-cheapest representation that keeps full context: title, description (unless
 *  the text repeats it), the structured data most scrapers drop, then the main text — no
 *  URLs (they stay in ScrapeResult.links), no emphasis markers, repeats removed. */
function buildLlm(r: ScrapeResult, body: string): string {
	const text = condense(body);
	const printed = squash(text.replaceAll('`', ''));
	const head: string[] = [];
	if (r.title) head.push('# ' + r.title);
	const desc = squash(r.description || r.og.description || '');
	if (desc && !printed.includes(desc) && !r.title.includes(desc)) head.push(desc);
	const data = r.jsonld.length ? minifyJsonld(r.jsonld, squash(head.join(' ')) + ' ' + printed) : '';
	return [...head, data && '<structured>\n' + data + '\n</structured>', text].filter(Boolean).join('\n\n');
}

const AS_FORMATS: Record<string, Format[]> = { llm: ['llm'], data: ['json'], markdown: ['markdown', 'json'], readable: ['readable', 'json'], auto: ['markdown', 'json', 'links'] };

/** Fetch a URL via bun-tls and return LLM-ready output (Firecrawl-style `formats`). */
export async function scrape(url: string, opts: ScrapeOptions = {}): Promise<ScrapeResult> {
	// Every fetch() option applies (ocsp, signal, redirect too); fetch ignores the scrape-only ones.
	const r = await btFetch(url, { ...opts, persona: opts.persona ?? 'chrome' });
	// r.url is the FINAL url after redirects — the base for resolving the page's relative links.
	return scrapeHtml(await r.text(), r.url || url, opts, r.status);
}

/** The same LLM-ready output from HTML you already have (a cache, a browser, a file). */
export async function scrapeHtml(html: string, url: string, opts: ScrapeOptions = {}, status = 200): Promise<ScrapeResult> {
	const formats = new Set<Format>(opts.formats ?? AS_FORMATS[opts.as ?? 'auto']!);
	const readable = opts.onlyMainContent ?? (opts.as === 'readable' || formats.has('readable'));
	const data = await extractData(html, url); // structured data is cheap — always available

	let markdown = '';
	if (formats.has('markdown') || formats.has('readable') || formats.has('text')) {
		markdown = await toMarkdown(html, url, readable);
		if (opts.fit) markdown = fitMarkdown(markdown);
		if (opts.maxChars && markdown.length > opts.maxChars) markdown = markdown.slice(0, opts.maxChars) + '\n…[truncated]';
	}
	const result: ScrapeResult = { url, status, markdown, ...data };
	if (formats.has('html')) result.html = await cleanHtml(html, readable);
	if (opts.extract) result.extracted = await extractSchema(html, opts.extract);
	if (formats.has('llm')) {
		let llm = buildLlm(result, await toMarkdown(html, url, true, true));
		if (opts.maxChars && llm.length > opts.maxChars) llm = llm.slice(0, opts.maxChars) + '\n…[truncated]';
		result.llm = llm;
	}
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
	/** What the model reads: the 'llm' view (default — cheapest, but no URLs; a schema that
	 *  mentions url/link/href switches the default to 'markdown'), Markdown, or cleaned HTML. */
	from?: 'llm' | 'markdown' | 'html';
}

/** Coerce a parsed object to a JSON Schema's declared field types: a numeric string where
 *  the schema says number/integer becomes a number, "true"/"false" where it says boolean
 *  becomes a boolean — models (and the response_format JSON mode) often return everything as
 *  strings. Nested `type: object` is coerced recursively; arrays by their `items` schema.
 *  ponytail: types + nested objects/arrays only — not a full validator (no required/enum/
 *  pattern); the schema is primarily the model's contract. */
export function coerceToSchema(value: unknown, schema: unknown): unknown {
	if (!schema || typeof schema !== 'object') return value;
	const s = schema as Record<string, unknown>;
	const type = s.type;
	if ((type === 'number' || type === 'integer') && typeof value === 'string' && value.trim() !== '' && Number.isFinite(Number(value))) {
		const n = Number(value);
		return type === 'integer' ? Math.trunc(n) : n;
	}
	if (type === 'boolean' && typeof value === 'string' && /^(true|false)$/i.test(value.trim())) return value.trim().toLowerCase() === 'true';
	if (type === 'array' && Array.isArray(value) && s.items) return value.map((v) => coerceToSchema(v, s.items));
	if (value && typeof value === 'object' && !Array.isArray(value) && s.properties && typeof s.properties === 'object') {
		const props = s.properties as Record<string, unknown>;
		const o = value as Record<string, unknown>;
		for (const k of Object.keys(o)) if (k in props) o[k] = coerceToSchema(o[k], props[k]);
	}
	return value;
}

/**
 * LLM-powered structured extraction (like Firecrawl's Agent / crawl4ai's LLMExtractionStrategy):
 * scrape the page, hand it to your LLM with the schema + prompt, and return the parsed JSON.
 * bun-tls does the fetch (clearing the WAF) and the token-cheap rendering; you bring any
 * model (OpenAI, a local Ollama endpoint, or your own function). The result is coerced to the
 * schema's field types (see `coerceToSchema`); it is not otherwise validated.
 */
export async function extractLLM(url: string, opts: ExtractLLMOptions): Promise<unknown> {
	const from = opts.from ?? (/url|link|href/i.test(JSON.stringify(opts.schema ?? {}) + (opts.prompt ?? '')) ? 'markdown' : 'llm');
	const r = await scrape(url, { ...opts, formats: [from], onlyMainContent: opts.onlyMainContent ?? true, maxChars: opts.maxChars ?? 16000 });
	const content = (from === 'html' ? r.html : from === 'llm' ? r.llm : r.markdown) ?? '';
	const prompt =
		`${opts.prompt ?? 'Extract the structured data from the content below.'}\n\n` +
		`Return ONLY a valid JSON object${opts.schema ? ' matching this JSON Schema:\n' + JSON.stringify(opts.schema) : ''}. No prose, no code fences.\n\n` +
		`--- CONTENT (${url}) ---\n${content}`;
	const raw = await callLlm(opts.llm, prompt);
	const text = raw.trim().replace(/^```(?:json)?\s*/i, '').replace(/```$/i, '').trim();
	const parse = (t: string): unknown => coerceToSchema(JSON.parse(t), opts.schema);
	try {
		return parse(text);
	} catch {
		const m = text.match(/\{[\s\S]*\}/);
		if (m) try { return parse(m[0]); } catch { /* fall through */ }
		return { _raw: raw };
	}
}
