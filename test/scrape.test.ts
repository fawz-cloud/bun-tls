// HTML → 'llm' view / readable Markdown (offline): context kept, token junk dropped.
import assert from 'node:assert';
import { scrapeHtml, coerceToSchema } from '../src/http/scrape';

const page = `<!doctype html><html><head><title>T &amp; Co</title><meta name="description" content="Say &quot;hi&quot;"></head><body>
<svg><title>Logo</title></svg><a href="#main">Skip to content</a>
<nav><a href="/">Home</a></nav>
<div data-mw='{"x":"<br>leak"}'>Infobox</div>
<h2>Specs<a href="#specs">#</a></h2><h3>Contributing</h3><p>Contributing</p>
<ul><li><span>Height</span><span>24 cm</span></li></ul>
<p><a href="/t/bun">bun</a><a href="/t/zig">zig</a> it&#x27;s &mdash; ok<sup><a href="#cite_note-1">&#91;1&#93;</a></sup></p>
<table><tr><td></td><td>1.</td><td>Story one</td></tr><tr><td></td><td>9 points</td><td>2 hrs ago</td></tr><tr><td>2.</td><td>Story two</td></tr><tr><td></td><td>9 points</td><td>2 hrs ago</td></tr></table>
<pre><code><span>def</span> <span>f</span>():
    return  1</code></pre>
<form><p>Inside a form</p><input value="x"></form>
<p>Same line here</p><p>Same line here</p>
<ul><li><a href="/ar" hreflang="ar">Arabic</a></li></ul>
<h2>References</h2><ol><li>"SSL/TLS in Detail". TechNet. October 8, 2009. Archived from the original on 2022-08-13. Retrieved 2021-10-24.</li><li>R. Khare (May 2000). Upgrading to TLS. doi:10.17487/RFC2817. RFC 2817.</li></ol>
</body></html>`;

const r = await scrapeHtml(page, 'https://x.test/', { formats: ['llm', 'readable'] });
const llm = r.llm!;
assert.equal(r.title, 'T & Co', 'document <title> only (not the SVG one), entities decoded');
assert.equal(r.description, 'Say "hi"', 'meta content decoded');
// context kept
assert.ok(llm.includes('Height 24 cm'), 'adjacent spans separated');
assert.ok(llm.includes('bun zig'), 'adjacent links separated');
assert.ok(llm.includes("it's — ok"), 'hex + named entities decoded');
assert.ok(llm.includes('```\ndef f():\n    return  1\n```'), '<pre> fenced, indentation verbatim');
assert.ok(llm.includes('Inside a form'), 'a <form> wrapper keeps its content');
assert.equal(llm.match(/9 points \| 2 hrs ago/g)?.length, 2, 'repeated short per-item lines are not deduped');
assert.ok(llm.includes('Story one') && llm.includes('Story two'), 'link-free table rows kept');
assert.ok(llm.includes('"SSL/TLS in Detail". TechNet. October 8, 2009.'), 'citation title/date kept');
// junk dropped
assert.ok(!llm.includes('leak'), 'attribute values never leak as text');
assert.ok(!/Skip to|Home|Arabic|\[1\]|Specs#|Logo|doi:|Retrieved|Archived|\]\(/.test(llm), 'skip link, nav, hreflang, citation marker, permalink, SVG title, citation bookkeeping, URLs dropped');
assert.equal(llm.match(/Same line here/g)?.length, 1, 'consecutive duplicate line dropped');
assert.equal(llm.match(/Contributing/g)?.length, 1, 'line repeating its heading dropped');
assert.ok(!/^- ?$/m.test(r.markdown), 'no empty bullet left by a removed link');
assert.ok(r.markdown.includes('[bun](https://x.test/t/bun) [zig](https://x.test/t/zig)'), 'Markdown keeps links, absolute');
assert.deepEqual(r.links.find((l) => l.href === 'https://x.test/t/bun'), { href: 'https://x.test/t/bun', text: 'bun' }, 'links carry their anchor text');
const nested = await scrapeHtml('<a href="/a"><span>Deep</span> <b>text</b></a>', 'https://x.test/');
assert.equal(nested.links[0]?.text, 'Deep text', 'anchor text includes nested elements');
const frag = await scrapeHtml('<title>Hi</title><main><h1>Hello</h1></main>', 'https://x.test/', { formats: ['llm'] });
assert.equal(frag.llm, '# Hi\n\n# Hello', 'a fragment without <head> does not repeat its <title> in the text');

// A code block with a blank line inside stays whole in the llm view — the opening fence and
// the first line are not split off and dropped (MDN JS examples, Statements/for).
const code = await scrapeHtml('<p>before</p><pre><code>let i = 0;\n\nwhile (i &lt;= 3) {\n  i++;\n}</code></pre><p>after</p>', 'https://x.test/', { formats: ['llm'] });
assert.ok(code.llm!.includes('```\nlet i = 0;\n\nwhile (i <= 3) {\n  i++;\n}\n```'), 'a code block with an internal blank line is kept whole');

// extractLLM coerces the model's reply (strings) to the schema's field types.
const schema = { type: 'object', properties: { price: { type: 'number' }, qty: { type: 'integer' }, ok: { type: 'boolean' }, dims: { type: 'object', properties: { w: { type: 'number' } } }, tags: { type: 'array', items: { type: 'number' } } } };
const out = coerceToSchema({ price: '4.50', qty: '3', ok: 'true', dims: { w: '46' }, tags: ['1', '2'] }, schema);
assert.deepEqual(out, { price: 4.5, qty: 3, ok: true, dims: { w: 46 }, tags: [1, 2] }, 'coerces number/integer/boolean, nested objects and array items');
assert.equal(coerceToSchema('keep', { type: 'string' }), 'keep', 'a string stays a string');
assert.equal(coerceToSchema('n/a', { type: 'number' }), 'n/a', 'a non-numeric string is left for the caller to see');

console.log('scrape: llm view + Markdown rendering OK');
