// search() result parsers (offline): each engine's real result markup → {title,url,snippet}.
import assert from 'node:assert';
import { parseSearchResults } from '../src/http/search';

// DuckDuckGo HTML/Lite: an <a class="result-link" href="…/l/?uddg=<dest>"> then a result-snippet cell.
const ddg = `<table>
<tr><td><a rel="nofollow" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fbun.sh%2F&rut=abc" class='result-link'>Bun — A fast all-in-one JavaScript runtime</a></td></tr>
<tr><td>&nbsp;</td><td class='result-snippet'>Bundle, install, and run <b>JavaScript</b> &amp; TypeScript — all in Bun.</td></tr>
<tr><td><a href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fgithub.com%2Foven-sh%2Fbun&rut=def" class='result-link'>GitHub - oven-sh/bun</a></td></tr>
<tr><td>&nbsp;</td><td class='result-snippet'>Incredibly fast JavaScript runtime.</td></tr>
</table>`;
const d = parseSearchResults('duckduckgo', ddg);
assert.equal(d.length, 2, 'ddg: two results');
assert.deepEqual(d[0], { title: 'Bun — A fast all-in-one JavaScript runtime', url: 'https://bun.sh/', snippet: 'Bundle, install, and run JavaScript & TypeScript — all in Bun.' }, 'ddg: uddg decoded, title + snippet, entities decoded');
assert.equal(d[1]!.url, 'https://github.com/oven-sh/bun', 'ddg: second destination decoded');

// Bing: <li class="b_algo">…<h2><a href="…/ck/a?…&u=a1<base64url>">title</a>…<p class="b_lineclamp2">snippet</p>.
const b64 = Buffer.from('https://bun.sh/').toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const bing = `<ol><li class="b_algo"><h2><a target="_blank" href="https://www.bing.com/ck/a?!&&p=x&u=a1${b64}&ntb=1">Bun — all-in-one runtime</a></h2><div class="b_caption"><p class="b_lineclamp2"><span class="news_dt">Jan 22, 2022</span>&#0183; Bundle, install, and run.</p></div></li></ol>`;
const bg = parseSearchResults('bing', bing);
assert.equal(bg.length, 1, 'bing: one result');
assert.equal(bg[0]!.url, 'https://bun.sh/', 'bing: ck/a redirect decoded to the destination');
assert.equal(bg[0]!.title, 'Bun — all-in-one runtime', 'bing: title');
assert.ok(bg[0]!.snippet.includes('Bundle, install, and run'), 'bing: snippet');

// Brave / Startpage: generic external-link extraction — skips the engine's own domain, assets
// and duplicates; keeps links whose anchor text reads like a title.
const brave = `<div>
<a href="https://search.brave.com/settings">Settings</a>
<a href="https://bun.sh/">Bun — A fast all-in-one JavaScript runtime</a>
<a href="https://bun.sh/">Bun — A fast all-in-one JavaScript runtime</a>
<a href="https://gstatic.com/x.png">img</a>
<a href="https://x.com">hi</a>
<a href="https://github.com/oven-sh/bun">GitHub - oven-sh/bun runtime</a>
</div>`;
const br = parseSearchResults('brave', brave);
assert.deepEqual(br.map((r) => r.url), ['https://bun.sh/', 'https://github.com/oven-sh/bun'], 'brave: own domain, assets, short anchors and duplicates dropped');

console.log('search: result parsers OK');
