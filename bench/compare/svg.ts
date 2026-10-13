// Renders results.json as three self-contained SVGs (speed, CPU, memory) in the README figure
// style: flat, warm near-monochrome, bun-tls in the ochre accent, attribute styling only so
// GitHub renders them. Run after run.ts: bun bench/compare/svg.ts
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';

const dir = import.meta.dir;
const res = JSON.parse(readFileSync(`${dir}/results.json`, 'utf8'));
const RATE: number = res.cyclesPerMs;

const C = { bg: '#141518', panel: '#1B1C20', line: '#2C2D33', text: '#E8E6E0', dim: '#9A968C', faint: '#5C5A54', accent: '#C8A24A', bar: '#3A3B41' };
const FS = 'font-family="ui-sans-serif,-apple-system,Segoe UI,Roboto,sans-serif"';
const FM = 'font-family="ui-monospace,SFMono-Regular,Menlo,monospace"';
const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;');

interface Run { v: number; cyc: number; wall: number; n: number; idle: number; peak: number }
const CLIENTS = Object.keys(res.results);
const SCEN: [string, string, string, 'lower' | 'higher', boolean][] = [
	// label in results.json, short id, unit, better, per-request CPU in µs
	['latency, new connection', 'fresh_local', 'ms', 'lower', false],
	['latency, reused connection', 'reuse_local', 'ms', 'lower', true],
	['throughput, 10 concurrent', 'tp10', 'req/s', 'higher', true],
	['throughput, 100 concurrent', 'tp100', 'req/s', 'higher', true],
	['upload 10 MiB', 'up10', 'MB/s', 'higher', false],
	['download 10 MiB', 'down10', 'MB/s', 'higher', false],
	['remote latency, new connection', 'fresh_remote', 'ms', 'lower', false],
	['remote latency, reused connection', 'reuse_remote', 'ms', 'lower', true]
];

const median = (a: number[]) => {
	const s = [...a].sort((x, y) => x - y);
	const m = s.length >> 1;
	return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
};
const runs = (client: string, label: string): { ok: Run[]; total: number } => {
	const all = res.results[client][label] as (Run | string)[];
	return { ok: all.filter((x): x is Run => typeof x !== 'string'), total: all.length };
};
interface Row { client: string; v: number; lo: number; hi: number; note: string }
const rowsOf = (label: string, pick: (r: Run) => number): Row[] =>
	CLIENTS.map((client) => {
		const { ok, total } = runs(client, label);
		const vals = ok.map(pick);
		return { client, v: median(vals), lo: Math.min(...vals), hi: Math.max(...vals), note: ok.length < total ? `${ok.length}/${total} rounds` : '' };
	});

const sig3 = (v: number) => (v >= 100 ? Math.round(v).toLocaleString('en-US') : v >= 10 ? v.toFixed(1) : v >= 1 ? v.toFixed(2) : v.toFixed(3));
const int = (v: number) => Math.round(v).toLocaleString('en-US');
const fmtFor = (unit: string) => (unit === 'ms' || unit === 'cpu' ? sig3 : unit === 'MiB' || unit === 'cores' ? (v: number) => v.toFixed(unit === 'cores' ? 2 : 1) : int);
const niceMax = (v: number) => {
	const p = 10 ** Math.floor(Math.log10(v));
	return [1, 1.2, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10].find((m) => m * p >= v)! * p;
};
const tickFmt = (t: number) => (t >= 1000 ? Math.round(t).toLocaleString('en-US') : String(+t.toPrecision(3)));
const cap = (s: string) => s[0].toUpperCase() + s.slice(1);

interface Panel { title: string; note: string; rows: Row[]; fmt: (v: number) => string; better?: 'lower' | 'higher' }

// One panel: title, note, five bars (median), thin line from fastest to slowest round.
function panel(x: number, y: number, w: number, p: Panel): [string, number] {
	const pad = 18, nameW = 104, rowH = 26, barH = 12, titleH = 46, axisH = 22;
	const valW = Math.max(...p.rows.map((r) => (p.fmt(r.v).length + (r.note ? r.note.length + 1 : 0)) * 7.8)) + 10;
	const x0 = x + pad + nameW, x1 = x + w - pad - valW;
	const max = niceMax(Math.max(...p.rows.map((r) => Math.max(r.v, r.hi))));
	const sx = (v: number) => x0 + (v / max) * (x1 - x0);
	const h = titleH + p.rows.length * rowH + axisH + pad;
	const best = p.better ? (p.better === 'lower' ? Math.min : Math.max)(...p.rows.map((r) => r.v)) : NaN;
	let s = `
<rect x="${x}" y="${y}" width="${w}" height="${h}" rx="10" fill="${C.panel}" stroke="${C.line}"/>
<text x="${x + pad}" y="${y + 26}" ${FS} font-size="14" font-weight="700" fill="${C.text}">${esc(p.title)}</text>
<text x="${x + pad}" y="${y + 43}" ${FS} font-size="12" fill="${C.dim}">${esc(p.note)}</text>`;
	const top = y + titleH + 4, bottom = top + p.rows.length * rowH;
	for (const t of [0, max / 2, max]) {
		s += `<line x1="${sx(t)}" x2="${sx(t)}" y1="${top}" y2="${bottom}" stroke="${C.line}"/>`;
		s += `<text x="${sx(t)}" y="${bottom + 15}" ${FM} font-size="10.5" fill="${C.faint}" text-anchor="middle">${tickFmt(t)}</text>`;
	}
	p.rows.forEach((r, i) => {
		const cy = top + i * rowH + rowH / 2;
		const mine = r.client === 'bun-tls';
		const isBest = r.v === best;
		s += `
<text x="${x0 - 12}" y="${cy + 4.5}" ${FS} font-size="13" fill="${mine ? C.text : C.dim}" text-anchor="end">${esc(r.client)}</text>
<rect x="${x0}" y="${cy - barH / 2}" width="${Math.max(2, sx(r.v) - x0)}" height="${barH}" rx="3" fill="${mine ? C.accent : C.bar}"/>`;
		if (r.hi > r.lo)
			s += `<path d="M${sx(r.lo)} ${cy}H${sx(r.hi)}M${sx(r.lo)} ${cy - 4}V${cy + 4}M${sx(r.hi)} ${cy - 4}V${cy + 4}" stroke="${C.text}" stroke-opacity="0.45" stroke-width="1.25" fill="none"/>`;
		const vx = sx(Math.max(r.v, r.hi)) + 7;
		s += `<text x="${vx}" y="${cy + 4.5}" ${FM} font-size="13"${isBest ? ' font-weight="700"' : ''} fill="${mine ? C.accent : isBest ? C.text : C.dim}">${esc(p.fmt(r.v))}${r.note ? `<tspan fill="${C.faint}" font-weight="400"> ${esc(r.note)}</tspan>` : ''}</text>`;
	});
	return [s, h];
}

type Block = { heading: string; sub?: string } | { panels: Panel[]; cols: 1 | 2 };
function figure(title: string, sub: string, blocks: Block[], foot: string): string {
	const W = 1040, M = 40, gap = 20;
	let y = 96, body = '';
	for (const b of blocks) {
		if ('heading' in b) {
			y += 8;
			body += `<text x="${M}" y="${y + 14}" ${FS} font-size="15" font-weight="700" fill="${C.text}">${esc(b.heading)}</text>`;
			if (b.sub) body += `<text x="${M}" y="${y + 33}" ${FS} font-size="12" fill="${C.dim}">${esc(b.sub)}</text>`;
			y += b.sub ? 46 : 28;
			continue;
		}
		const pw = b.cols === 2 ? (W - 2 * M - gap) / 2 : W - 2 * M;
		for (let i = 0; i < b.panels.length; i += b.cols) {
			let rowH = 0;
			b.panels.slice(i, i + b.cols).forEach((p, j) => {
				const [s, h] = panel(M + j * (pw + gap), y, pw, p);
				body += s;
				rowH = Math.max(rowH, h);
			});
			y += rowH + gap;
		}
	}
	const H = y + 30;
	return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" role="img">
<rect width="${W}" height="${H}" rx="14" fill="${C.bg}"/>
<rect x="0.5" y="0.5" width="${W - 1}" height="${H - 1}" rx="13.5" fill="none" stroke="${C.line}"/>
<text x="${M}" y="46" ${FS} font-size="20" font-weight="700" fill="${C.text}">${esc(title)}</text>
<text x="${M}" y="70" ${FS} font-size="13" fill="${C.dim}">${esc(sub)}</text>
<rect x="${W - M - 230}" y="34" width="13" height="13" rx="3" fill="${C.accent}"/><text x="${W - M - 211}" y="45" ${FS} font-size="13" fill="${C.text}">bun-tls</text>
<rect x="${W - M - 140}" y="34" width="13" height="13" rx="3" fill="${C.bar}"/><text x="${W - M - 121}" y="45" ${FS} font-size="13" fill="${C.dim}">other clients</text>
${body}
<text x="${M}" y="${H - 22}" ${FS} font-size="11.5" fill="${C.faint}">${esc(foot)}</text>
</svg>`;
}

const cpuMs = (r: Run) => r.cyc / RATE;
const FOOT = `Median of ${res.rounds} rounds, thin line = fastest to slowest round, bold = best. i5-14450HX, Windows 11; local Go server, TLS 1.3, HTTP/1.1; every client uses its Chrome profile. Scripts: bench/compare.`;
const better = (b: 'lower' | 'higher') => `${b} is better`;
const unitName: Record<string, string> = { ms: 'milliseconds', 'req/s': 'requests per second', 'MB/s': 'megabytes per second' };
const speedPanel = ([label, , unit, b]: (typeof SCEN)[number]): Panel => ({ title: cap(label.replace('remote ', '')), note: `${unitName[unit]} · ${better(b)}`, rows: rowsOf(label, (r) => r.v), fmt: fmtFor(unit), better: b });
const cpuPanel = ([label, id, , , micro]: (typeof SCEN)[number]): Panel => ({
	title: cap(label),
	note: `${micro ? 'µs' : 'ms'} CPU per ${id.startsWith('up') || id.startsWith('down') ? 'MB' : 'request'} · lower is better`,
	rows: rowsOf(label, (r) => (cpuMs(r) / r.n) * (micro ? 1000 : 1)),
	fmt: fmtFor('cpu'),
	better: 'lower'
});
const MiB = 1024 * 1024;

mkdirSync(`${dir}/svg`, { recursive: true });
writeFileSync(
	`${dir}/svg/speed.svg`,
	figure('Speed', 'bun-tls vs impers (Node, Bun), curl_cffi, go-utls', [
		{ heading: 'Local server' },
		{ panels: SCEN.slice(0, 6).map(speedPanel), cols: 2 },
		{ heading: 'Over the internet, example.com', sub: 'Round trips dominate here, so the clients land close together.' },
		{ panels: SCEN.slice(6).map(speedPanel), cols: 2 }
	], FOOT)
);
writeFileSync(
	`${dir}/svg/cpu.svg`,
	figure('CPU', 'Process CPU time, every thread included, per unit of work', [
		{ panels: SCEN.map(cpuPanel), cols: 2 },
		{ heading: 'Cores kept busy', sub: 'CPU time ÷ wall time during the throughput runs. More cores can mean a faster run that still costs more CPU.' },
		{
			panels: SCEN.filter((s) => s[1].startsWith('tp')).map(([label]) => ({ title: cap(label), note: 'cores', rows: rowsOf(label, (r) => cpuMs(r) / r.wall), fmt: fmtFor('cores') })),
			cols: 2
		}
	], FOOT)
);
const idleRows: Row[] = CLIENTS.map((client) => {
	const vals = SCEN.flatMap(([label]) => runs(client, label).ok.map((r) => r.idle / MiB));
	return { client, v: median(vals), lo: Math.min(...vals), hi: Math.max(...vals), note: '' };
});
writeFileSync(
	`${dir}/svg/memory.svg`,
	figure('Memory', 'Working set of the client process, MiB', [
		{ panels: [{ title: 'Idle, after one warm-up request', note: `MiB, median over every run · ${better('lower')}`, rows: idleRows, fmt: fmtFor('MiB'), better: 'lower' }], cols: 1 },
		{ heading: 'Peak during each scenario' },
		{ panels: SCEN.slice(0, 6).map(([label]) => ({ title: cap(label), note: `peak MiB · ${better('lower')}`, rows: rowsOf(label, (r) => r.peak / MiB), fmt: fmtFor('MiB'), better: 'lower' as const })), cols: 2 }
	], FOOT)
);
console.log('wrote svg/speed.svg, svg/cpu.svg, svg/memory.svg');
