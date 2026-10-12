// Generates the README figures as self-contained SVGs (no external assets, system
// fonts only, one accent color, real numbers). Run: bun assets/gen.ts
import { writeFileSync } from 'node:fs';

// Flat, near-monochrome, warm. One restrained ochre accent, used sparingly.
const C = {
	bg: '#141518',
	panel: '#1B1C20',
	line: '#2C2D33',
	text: '#E8E6E0',
	dim: '#9A968C',
	faint: '#5C5A54',
	accent: '#C8A24A', // muted ochre — highlights only
	amber: '#C8A24A',
	curl: '#3A3B41' // comparison bars
};
const FS = 'font-family="ui-sans-serif,-apple-system,Segoe UI,Roboto,sans-serif"';
const FM = 'font-family="ui-monospace,SFMono-Regular,Menlo,monospace"';
const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;');

function frame(w: number, h: number, inner: string): string {
	return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="${w}" height="${h}" role="img">
<rect width="${w}" height="${h}" rx="14" fill="${C.bg}"/>
<rect x="0.5" y="0.5" width="${w - 1}" height="${h - 1}" rx="13.5" fill="none" stroke="${C.line}"/>
${inner}
</svg>`;
}

// ── 1. Hero ───────────────────────────────────────────────────────────────────
function hero(): string {
	const w = 1200, h = 340;
	const ja3cipher = '771,4867-4865-4866-52393-52392-49195-49199-49196-49200';
	const ja3rest = '…-156-157-47-53,0-23-65281-10-11-35-13-51-45-43,29-23-24,0';
	// faint byte-column motif on the right
	const bytes = '16 03 01 02 00 01 00 01 fc 03 03 1b c3 ce b6 bb e3 9c ff 93 83 55 b5 a5 0a db 6d b2 1b 7a 6a f6 49 d7 b4 bc 41 9d 78 76 48 7d 95 00 00 06 13 01 13 03 13 02 01 00 01 cd 00 00 00 0b 00 09 00 00 06 73 65 72 76 65 72 ff 01 00 01 00 00 0a 00 14 00 12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 33 00 26 00 24 00 1d 00 20'.split(' ');
	let grid = '';
	const cols = 15, cellW = 25, cellH = 26, gx = 720, gy = 54;
	bytes.forEach((b, i) => {
		const r = Math.floor(i / cols), c = i % cols;
		const hot = i >= 45 && i <= 51; // the cipher-suite bytes
		grid += `<text class="m" x="${gx + c * cellW}" y="${gy + r * cellH}" ${FM} font-size="15" fill="${hot ? C.accent : C.faint}" opacity="${hot ? 1 : 0.5}">${b}</text>`;
	});
	return frame(w, h, `
<text x="64" y="118" ${FM} font-size="62" font-weight="700" fill="${C.text}" letter-spacing="-1">bun-tls</text>
<text x="66" y="162" ${FS} font-size="21" fill="${C.dim}">A TLS 1.3 client written from scratch — with a fingerprint you control.</text>
<text x="66" y="212" ${FS} font-size="15" fill="${C.faint}">Pure TypeScript on Bun. No Python, no Dart, no native .dll. Every ClientHello byte is yours.</text>
<text x="66" y="276" ${FM} font-size="14" fill="${C.dim}">${esc(ja3cipher)}</text>
<text x="66" y="298" ${FM} font-size="14" fill="${C.faint}">${esc(ja3rest)}</text>
<rect x="66" y="252" width="520" height="1" fill="${C.line}"/>
<circle cx="574" cy="100" r="0"/>
${grid}
<rect x="708" y="34" width="462" height="272" rx="10" fill="none" stroke="${C.line}"/>
<text x="722" y="296" ${FM} font-size="13" fill="${C.accent}">ja3 cipher bytes — verbatim on the wire</text>`);
}

// ── 2. Architecture (layers, imports point down) ──────────────────────────────
function architecture(): string {
	const w = 1000, h = 430;
	const layers = [
		['http', 'request, session, http1', 'request() and Session — the public API'],
		['fp', 'fingerprints, clients, ja3', 'browser presets, named clients, fromJa3()'],
		['tls', 'clienthello, handshake, record, verify, extensions, transport', 'the TLS 1.3 state machine + records'],
		['core', 'bytes, consts, crypto, chacha', 'byte I/O + crypto primitives']
	];
	const x = 60, bw = 760, bh = 72, gap = 22, top = 70;
	let bands = '';
	layers.forEach((L, i) => {
		const y = top + i * (bh + gap);
		bands += `
<rect x="${x}" y="${y}" width="${bw}" height="${bh}" rx="10" fill="${C.panel}" stroke="${C.line}"/>
<text x="${x + 22}" y="${y + 31}" ${FM} font-size="19" font-weight="700" fill="${C.text}">${L[0]}</text>
<text x="${x + 22}" y="${y + 55}" ${FM} font-size="14" fill="${C.text}">${esc(L[1]!)}</text>
<text x="${x + bw - 16}" y="${y + bh - 14}" ${FS} font-size="12.5" fill="${C.dim}" text-anchor="end">${esc(L[2]!)}</text>`;
	});
	const ax = x + bw + 46;
	const ay0 = top + 20, ay1 = top + 3 * (bh + gap) + bh - 20;
	return frame(w, h, `
<text x="60" y="44" ${FS} font-size="20" font-weight="700" fill="${C.text}">Four layers, one direction</text>
${bands}
<line x1="${ax}" y1="${ay0}" x2="${ax}" y2="${ay1}" stroke="${C.faint}" stroke-width="1.5"/>
<path d="M ${ax - 5} ${ay1 - 10} L ${ax} ${ay1} L ${ax + 5} ${ay1 - 10}" fill="none" stroke="${C.faint}" stroke-width="1.5"/>
<text x="${ax + 12}" y="${(ay0 + ay1) / 2 - 6}" ${FS} font-size="13" fill="${C.dim}">imports</text>
<text x="${ax + 12}" y="${(ay0 + ay1) / 2 + 12}" ${FS} font-size="13" fill="${C.dim}">point down</text>`);
}

// ── 3. Full handshake vs 0-RTT (round trips) ──────────────────────────────────
function handshake(): string {
	const w = 1000, h = 392;
	const lineTop = 128, lineBot = 300, boxY = lineBot + 30;
	function panel(ox: number, title: string, sub: string, flights: [string, boolean][], rtt: string, rttColor: string): string {
		const cx = ox + 10, sx = ox + 380;
		let arrows = '';
		flights.forEach(([label, toServer], row) => {
			const y = lineTop + 26 + row * 42;
			const x1 = toServer ? cx : sx, x2 = toServer ? sx : cx;
			const hx = x2 + (toServer ? -9 : 9);
			arrows += `
<text x="${(cx + sx) / 2}" y="${y - 11}" ${FM} font-size="12.5" fill="${C.dim}" text-anchor="middle">${esc(label)}</text>
<line x1="${x1}" y1="${y}" x2="${x2}" y2="${y}" stroke="${C.faint}" stroke-width="1.5"/>
<path d="M ${hx} ${y - 5} L ${x2} ${y} L ${hx} ${y + 5} Z" fill="${C.faint}"/>`;
		});
		return `
<text x="${cx}" y="74" ${FS} font-size="16" font-weight="700" fill="${C.text}">${title}</text>
<text x="${cx}" y="97" ${FS} font-size="12.5" fill="${C.dim}">${esc(sub)}</text>
<line x1="${cx}" y1="${lineTop}" x2="${cx}" y2="${lineBot}" stroke="${C.line}"/>
<line x1="${sx}" y1="${lineTop}" x2="${sx}" y2="${lineBot}" stroke="${C.line}"/>
${arrows}
<text x="${cx}" y="${lineBot + 20}" ${FS} font-size="12" fill="${C.dim}">client</text>
<text x="${sx}" y="${lineBot + 20}" ${FS} font-size="12" fill="${C.dim}" text-anchor="end">server</text>
<rect x="${cx}" y="${boxY}" width="${sx - cx}" height="28" rx="7" fill="none" stroke="${rttColor}"/>
<text x="${(cx + sx) / 2}" y="${boxY + 18}" ${FS} font-size="12.5" fill="${rttColor}" text-anchor="middle">${esc(rtt)}</text>`;
	}
	return frame(w, h, `
<text x="60" y="44" ${FS} font-size="20" font-weight="700" fill="${C.text}">0-RTT saves a round trip (opt-in)</text>
${panel(70, 'Full handshake', 'first visit to a host', [
		['ClientHello', true],
		['ServerHello + cert + Finished', false],
		['Finished + request', true],
		['response', false]
	], '2 round trips before data', C.dim)}
${panel(540, '0-RTT resumption', 'returning, with a cached ticket', [
		['ClientHello + request', true],
		['response', false]
	], '1 round trip — request rides along', C.accent)}`);
}

// ── 5. Comparison matrix vs other clients ─────────────────────────────────────
function comparison(): string {
	const w = 1000, h = 370;
	const cols = ['bun-tls', 'curl_cffi', 'utls', 'node fetch', 'requests'];
	// true = yes, false = no, or a short string. Only properties checked for every column.
	const rows: [string, (string | boolean)[]][] = [
		['Language', ['TypeScript', 'Python', 'Go', 'JavaScript', 'Python']],
		['No FFI / extra native library', [true, false, true, true, true]],
		['JA3 / JA4 control', [true, true, true, false, false]],
		['Browser presets', [true, true, true, false, false]],
		['HTTP/2', [false, true, 'TLS only', true, false]],
		['Cert verification by default', [true, true, true, true, true]]
	];
	const lx = 60, labelW = 300, c0 = lx + labelW, cw = (w - c0 - 40) / cols.length;
	const colX = (i: number) => c0 + cw * i + cw / 2;
	let head = '';
	cols.forEach((c, i) => {
		const mine = i === 0;
		head += `<text x="${colX(i)}" y="98" ${FM} font-size="14" font-weight="${mine ? 700 : 400}" fill="${mine ? C.accent : C.dim}" text-anchor="middle">${c}</text>`;
	});
	const top = 124, step = 38;
	let body = '';
	rows.forEach((r, ri) => {
		const y = top + ri * step;
		if (ri % 2 === 0) body += `<rect x="${lx - 14}" y="${y - 25}" width="${w - 2 * (lx - 14)}" height="${step}" rx="6" fill="${C.panel}"/>`;
		body += `<text x="${lx}" y="${y}" ${FS} font-size="14" fill="${C.text}">${esc(r[0])}</text>`;
		r[1].forEach((v, ci) => {
			const x = colX(ci);
			if (typeof v === 'string') body += `<text x="${x}" y="${y}" ${FM} font-size="12.5" fill="${ci === 0 ? C.text : C.dim}" text-anchor="middle">${esc(v)}</text>`;
			else if (v) body += `<circle cx="${x}" cy="${y - 4}" r="5.5" fill="${ci === 0 ? C.accent : C.dim}"/>`;
			else body += `<line x1="${x - 6}" y1="${y - 4}" x2="${x + 6}" y2="${y - 4}" stroke="${C.faint}" stroke-width="2"/>`;
		});
	});
	return frame(w, h, `
<text x="60" y="44" ${FS} font-size="20" font-weight="700" fill="${C.text}">How it compares</text>
<text x="60" y="68" ${FS} font-size="13" fill="${C.dim}">filled = yes, dash = no. utls is a TLS library; HTTP/2 comes from the HTTP layer you pair it with.</text>
${head}
<line x1="${lx - 14}" y1="108" x2="${w - (lx - 14)}" y2="108" stroke="${C.line}"/>
${body}`);
}

// ── 4. Throughput vs curl_cffi ────────────────────────────────────────────────
function benchmark(): string {
	const w = 1000, h = 460;
	// bench/bun.ts vs bench/curl_bench.py, same machine, interleaved run (see README).
	const rows: [string, number, number][] = [
		['1 connection', 11618, 2227],
		['10 concurrent', 17029, 3020],
		['50 concurrent', 5848, 1320]
	];
	const max = 18000, x0 = 230, barW = 600, top = 108, gh = 104, bh = 30;
	const sx = (v: number) => (v / max) * barW;
	let body = '';
	rows.forEach((r, i) => {
		const y = top + i * gh;
		body += `
<text x="${x0 - 18}" y="${y + bh + 6}" ${FS} font-size="14" fill="${C.text}" text-anchor="end">${esc(r[0])}</text>
<rect x="${x0}" y="${y}" width="${sx(r[1])}" height="${bh}" rx="5" fill="${C.accent}"/>
<text x="${x0 + sx(r[1]) + 10}" y="${y + 21}" ${FM} font-size="14" font-weight="700" fill="${C.accent}">${r[1].toLocaleString()}</text>
<rect x="${x0}" y="${y + bh + 8}" width="${sx(r[2])}" height="${bh}" rx="5" fill="${C.curl}"/>
<text x="${x0 + sx(r[2]) + 10}" y="${y + bh + 29}" ${FM} font-size="14" fill="${C.dim}">${r[2].toLocaleString()}</text>`;
	});
	return frame(w, h, `
<text x="60" y="44" ${FS} font-size="20" font-weight="700" fill="${C.text}">Throughput — 1000 requests, connections reused</text>
<text x="60" y="68" ${FS} font-size="13" fill="${C.dim}">requests per second on localhost, median of one interleaved run. Higher is better.</text>
<rect x="60" y="86" width="13" height="13" rx="3" fill="${C.accent}"/><text x="80" y="97" ${FS} font-size="13" fill="${C.text}">bun-tls</text>
<rect x="166" y="86" width="13" height="13" rx="3" fill="${C.curl}"/><text x="186" y="97" ${FS} font-size="13" fill="${C.dim}">curl_cffi</text>
${body}
<text x="60" y="${top + 3 * gh + 6}" ${FS} font-size="12" fill="${C.faint}">bun-tls Session vs curl_cffi AsyncSession, self-signed cert (verification off for both), Bun 1.4.2, curl_cffi 0.15.0. Scripts in bench/.</text>`);
}

const out = import.meta.dir;
writeFileSync(`${out}/hero.svg`, hero());
writeFileSync(`${out}/architecture.svg`, architecture());
writeFileSync(`${out}/handshake.svg`, handshake());
writeFileSync(`${out}/benchmark.svg`, benchmark());
writeFileSync(`${out}/comparison.svg`, comparison());
console.log('wrote hero.svg architecture.svg handshake.svg benchmark.svg comparison.svg');
