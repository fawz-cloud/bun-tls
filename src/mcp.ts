#!/usr/bin/env bun
// A Model Context Protocol (MCP) server exposing bun-tls scraping to LLM agents (Claude
// Desktop/Code, Cursor, …): tools `scrape`, `crawl`, `map`, `extract`. JSON-RPC 2.0 over
// stdio, newline-delimited — hand-rolled, zero dependencies.
//   claude mcp add bun-tls -- bun /abs/path/to/src/mcp.ts
import { scrape, type Format } from './http/scrape';
import { crawl, map } from './http/crawl';

const TOOLS = [
	{
		name: 'scrape',
		description: 'Fetch a web page through a browser TLS fingerprint (clears many bot walls) and return LLM-ready content: Markdown, structured data (JSON-LD/OpenGraph/meta), links. Prefer formats ["json"] for the cheapest structured answer, add "markdown" for the readable body.',
		inputSchema: {
			type: 'object',
			properties: {
				url: { type: 'string', description: 'The https URL to fetch.' },
				formats: { type: 'array', items: { type: 'string', enum: ['llm', 'markdown', 'readable', 'html', 'links', 'json', 'text'] }, description: "Default [\"llm\"] = token-cheapest full-context view. Use [\"json\"] for structured-only, [\"markdown\"] for the full body." },
				onlyMainContent: { type: 'boolean', description: 'Drop nav/header/footer/aside.' },
				fit: { type: 'boolean', description: 'Prune nav/menu residue from the Markdown (token-cheaper).' },
				persona: { type: 'string', enum: ['chrome', 'edge', 'firefox', 'safari'], description: 'Browser fingerprint (default chrome).' },
				maxChars: { type: 'number', description: 'Truncate Markdown to this many characters.' }
			},
			required: ['url']
		}
	},
	{
		name: 'crawl',
		description: 'Breadth-first crawl of same-origin links from a start URL. Returns a list of pages with their structured data + Markdown.',
		inputSchema: {
			type: 'object',
			properties: {
				url: { type: 'string' },
				limit: { type: 'number', description: 'Max pages (default 15).' },
				depth: { type: 'number', description: 'Max link depth (default 2).' },
				persona: { type: 'string', enum: ['chrome', 'edge', 'firefox', 'safari'] }
			},
			required: ['url']
		}
	},
	{
		name: 'map',
		description: "Discover a site's URLs from robots.txt + sitemaps (and the homepage links) WITHOUT fetching each page. Optional `search` ranks matching URLs first.",
		inputSchema: {
			type: 'object',
			properties: { url: { type: 'string' }, limit: { type: 'number', description: 'Max URLs (default 2000).' }, search: { type: 'string' } },
			required: ['url']
		}
	},
	{
		name: 'extract',
		description: 'Extract repeating records from a page with a CSS schema (like a product grid or a list): one record per baseSelector match, each field read from a descendant selector as text or an attribute.',
		inputSchema: {
			type: 'object',
			properties: {
				url: { type: 'string' },
				baseSelector: { type: 'string', description: 'CSS selector for each record, e.g. ".product-card".' },
				fields: { type: 'array', items: { type: 'object', properties: { name: { type: 'string' }, selector: { type: 'string' }, attr: { type: 'string' } }, required: ['name'] } }
			},
			required: ['url', 'baseSelector', 'fields']
		}
	}
];

interface Args {
	[k: string]: unknown;
}

async function runTool(name: string, a: Args): Promise<unknown> {
	const persona = (a.persona as string) ?? 'chrome';
	if (name === 'scrape') {
		const r = await scrape(a.url as string, { formats: (a.formats as Format[]) ?? ['llm'], onlyMainContent: a.onlyMainContent as boolean, fit: a.fit as boolean, persona, maxChars: a.maxChars as number });
		return slim(r);
	}
	if (name === 'crawl') {
		const { pages, count } = await crawl(a.url as string, { limit: (a.limit as number) ?? 15, depth: (a.depth as number) ?? 2, persona });
		return { count, pages: pages.map(slim) };
	}
	if (name === 'map') {
		return await map(a.url as string, { limit: (a.limit as number) ?? 2000, search: a.search as string, persona });
	}
	if (name === 'extract') {
		const r = await scrape(a.url as string, { formats: [], persona, extract: { baseSelector: a.baseSelector as string, fields: a.fields as { name: string; selector?: string; attr?: string }[] } });
		return { url: r.url, status: r.status, records: r.extracted ?? [] };
	}
	throw new Error('unknown tool: ' + name);
}

// Compact, token-cheap view of a scrape result (drop empty fields).
function slim(r: Awaited<ReturnType<typeof scrape>>): Record<string, unknown> {
	const o: Record<string, unknown> = { url: r.url, status: r.status };
	// The 'llm' view already folds title + structured data + text into one cheap string.
	if (r.llm) {
		o.content = r.llm;
		if (r.extracted?.length) o.extracted = r.extracted;
		return o;
	}
	if (r.title) o.title = r.title;
	const desc = r.description || r.og.description;
	if (desc) o.description = desc;
	if (Object.keys(r.og).length) o.og = r.og;
	if (r.jsonld.length) o.jsonld = r.jsonld;
	if (r.markdown) o.markdown = r.markdown;
	if (r.html) o.html = r.html;
	if (r.extracted?.length) o.extracted = r.extracted;
	if (r.links.length) o.links = r.links.slice(0, 100).map((l) => l.href);
	return o;
}

// ── JSON-RPC 2.0 over stdio (newline-delimited) ──
function send(msg: unknown): void {
	process.stdout.write(JSON.stringify(msg) + '\n');
}

async function handle(req: { id?: unknown; method: string; params?: Args }): Promise<void> {
	const { id, method, params } = req;
	if (method === 'initialize') {
		send({ jsonrpc: '2.0', id, result: { protocolVersion: '2024-11-05', capabilities: { tools: {} }, serverInfo: { name: 'bun-tls-scrape', version: '0.1.0' } } });
	} else if (method === 'tools/list') {
		send({ jsonrpc: '2.0', id, result: { tools: TOOLS } });
	} else if (method === 'tools/call') {
		try {
			const out = await runTool(params!.name as string, (params!.arguments as Args) ?? {});
			send({ jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: JSON.stringify(out) }] } });
		} catch (e) {
			send({ jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: 'error: ' + (e as Error).message }], isError: true } });
		}
	} else if (method === 'ping') {
		send({ jsonrpc: '2.0', id, result: {} });
	} else if (id !== undefined && !method.startsWith('notifications/')) {
		send({ jsonrpc: '2.0', id, error: { code: -32601, message: 'method not found: ' + method } });
	}
	// notifications (no id) get no response
}

/** Start the MCP server on stdio. */
export function startMcp(): void {
	let buf = '';
	process.stdin.setEncoding('utf8');
	process.stdin.on('data', (chunk: string) => {
		buf += chunk;
		let nl: number;
		while ((nl = buf.indexOf('\n')) >= 0) {
			const line = buf.slice(0, nl).trim();
			buf = buf.slice(nl + 1);
			if (!line) continue;
			try {
				void handle(JSON.parse(line));
			} catch {
				/* ignore malformed line */
			}
		}
	});
	process.stdin.on('end', () => process.exit(0));
}

if (import.meta.main) startMcp();
