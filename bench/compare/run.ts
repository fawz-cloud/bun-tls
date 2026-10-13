// bench/compare: bun-tls vs impers (Node, Bun) vs curl_cffi vs go-utls — speed, CPU, RAM.
// Builds the Go pieces, starts the local TLS 1.3 server, runs every client × scenario in its
// own process for R rounds (client order rotated per round) and prints medians as tables.
// Every client impersonates Chrome and speaks HTTP/1.1; local runs skip cert verification
// (self-signed), remote runs verify. CPU = process CPU cycles (all threads, QueryProcessCycleTime)
// during the measured phase, converted to ms with a rate calibrated here; RAM = working set
// after setup (idle) and the process peak. Windows-only (kernel32/psapi counters).
// Usage: bun bench/compare/run.ts [rounds=3]
import { $ } from 'bun';
import { dlopen, FFIType, ptr } from 'bun:ffi';
import { writeFileSync } from 'node:fs';

// Cycle counter rate (cycles per ms): spin one thread for 500 ms and read our own counter.
const { symbols: k32 } = dlopen('kernel32.dll', { QueryProcessCycleTime: { args: [FFIType.i64, FFIType.ptr], returns: FFIType.i32 } });
const cycBuf = new BigUint64Array(1);
const ownCycles = () => (k32.QueryProcessCycleTime(-1n, ptr(cycBuf)), Number(cycBuf[0]));
const RATE = (() => {
	const c0 = ownCycles();
	const t0 = performance.now();
	while (performance.now() - t0 < 500);
	return (ownCycles() - c0) / (performance.now() - t0);
})();

const dir = import.meta.dir;
const exe = process.platform === 'win32' ? '.exe' : '';
const L = 'https://localhost:48443';
const REMOTE = 'https://example.com/';
const ROUNDS = Number(process.argv[2] ?? 3);

const clients: [string, string[]][] = [
	['bun-tls', ['bun', 'bun_tls.ts']],
	['impers (node)', ['node', 'impers.mjs']],
	['impers (bun)', ['bun', 'impers.mjs']],
	['curl_cffi', ['python', 'curl_cffi_bench.py']],
	['go-utls', [`bin/utls${exe}`]]
];
// label, scenario, url, n, warmup, arg (concurrency or MiB), verify, unit
type Scenario = [string, string, string, number, number, number, number, string];
const scenarios: Scenario[] = [
	['latency, new connection', 'fresh', `${L}/`, 300, 10, 0, 0, 'ms'],
	['latency, reused connection', 'reuse', `${L}/`, 5000, 300, 0, 0, 'ms'],
	['throughput, 10 concurrent', 'tp', `${L}/`, 10000, 1000, 10, 0, 'req/s'],
	['throughput, 100 concurrent', 'tp', `${L}/`, 10000, 1000, 100, 0, 'req/s'],
	['upload 10 MiB', 'up', `${L}/`, 20, 2, 10, 0, 'MB/s'],
	['download 10 MiB', 'down', `${L}/10mb`, 20, 2, 0, 0, 'MB/s'],
	['remote latency, new connection', 'fresh', REMOTE, 20, 2, 0, 1, 'ms'],
	['remote latency, reused connection', 'reuse', REMOTE, 50, 3, 0, 1, 'ms']
];
interface Run { v: number; cyc: number; wall: number; n: number; idle: number; peak: number }

await $`go build -o bin/server${exe} ./server`.cwd(dir);
await $`go build -o bin/utls${exe} ./utls`.cwd(dir);
const server = Bun.spawn([`${dir}/bin/server${exe}`, `${dir}/..`], { stdout: 'ignore', stderr: 'inherit' });
for (let i = 0; ; i++) {
	try {
		const s = await Bun.connect({ hostname: '127.0.0.1', port: 48443, socket: { data() {} } });
		s.end();
		break;
	} catch {
		if (i > 100) throw new Error('bench server did not start');
		await Bun.sleep(100);
	}
}

async function runOne(cmd: string[], s: Scenario): Promise<Run | string> {
	const [, scen, url, n, warm, arg, verify] = s;
	const p = Bun.spawn([...cmd, scen, url, String(n), String(warm), String(arg), String(verify)], { cwd: dir, stdout: 'pipe', stderr: 'pipe' });
	const timer = setTimeout(() => p.kill(), 300_000);
	const [out, err, code] = await Promise.all([new Response(p.stdout).text(), new Response(p.stderr).text(), p.exited]);
	clearTimeout(timer);
	const line = out.trim().split('\n').pop() ?? '';
	try {
		return JSON.parse(line) as Run;
	} catch {
		return `exit ${code}: ${(err || out).trim().split('\n').slice(-2).join(' | ').slice(0, 200)}`;
	}
}

const results: Record<string, Record<string, (Run | string)[]>> = {};
for (let r = 0; r < ROUNDS; r++) {
	const order = clients.map((_, i) => clients[(i + r) % clients.length]);
	for (const s of scenarios) {
		for (const [name, cmd] of order) {
			const res = await runOne(cmd, s);
			((results[name] ??= {})[s[0]] ??= []).push(res);
			const shown = typeof res === 'string' ? `FAIL ${res}` : `${res.v.toFixed(s[7] === 'ms' ? 3 : 0)} ${s[7]}`;
			console.error(`[round ${r + 1}/${ROUNDS}] ${s[0].padEnd(34)} ${name.padEnd(14)} ${shown}`);
		}
	}
}
server.kill();
writeFileSync(`${dir}/results.json`, JSON.stringify({ when: new Date().toISOString(), rounds: ROUNDS, cyclesPerMs: RATE, results }, null, 1));
const cpuMs = (x: Run) => x.cyc / RATE;

// ---- tables: medians across rounds ----
const med = (a: number[]) => (a.length ? a.sort((x, y) => x - y)[a.length >> 1] : NaN);
const ok = (name: string, label: string) => (results[name]?.[label] ?? []).filter((x): x is Run => typeof x !== 'string');
const names = clients.map(([n]) => n);
const fmt = (x: number, d: number) => (Number.isFinite(x) ? x.toFixed(d) : 'fail');
function table(title: string, rows: [string, (name: string) => number, number, boolean][]) {
	// rows: label, value per client, decimals, lowerIsBetter
	console.log(`\n### ${title}\n\n| | ${names.join(' | ')} |\n|---|${names.map(() => '---').join('|')}|`);
	for (const [label, get, d, low] of rows) {
		const vals = names.map(get);
		const finite = vals.filter(Number.isFinite);
		const best = low ? Math.min(...finite) : Math.max(...finite);
		console.log(`| ${label} | ${vals.map((x) => (x === best ? `**${fmt(x, d)}**` : fmt(x, d))).join(' | ')} |`);
	}
}
const unitOf = (s: Scenario) => s[7];
table(
	'Speed (median of rounds)',
	scenarios.map((s) => [`${s[0]} (${unitOf(s)})`, (n: string) => med(ok(n, s[0]).map((x) => x.v)), unitOf(s) === 'ms' ? 2 : 0, unitOf(s) === 'ms'])
);
table(
	'CPU (process CPU time per unit, all threads)',
	scenarios.map((s) => {
		const perMb = unitOf(s) === 'MB/s';
		const lbl = perMb ? 'ms CPU / MB' : s[1] === 'fresh' ? 'ms CPU / request' : 'µs CPU / request';
		const scale = perMb || s[1] === 'fresh' ? 1 : 1000;
		return [`${s[0]} (${lbl})`, (n: string) => med(ok(n, s[0]).map((x) => (cpuMs(x) / x.n) * scale)), perMb || s[1] === 'fresh' ? 2 : 0, true];
	})
);
table('CPU cores busy during throughput (CPU time ÷ wall time)', scenarios.filter((s) => s[1] === 'tp').map((s) => [s[0], (n: string) => med(ok(n, s[0]).map((x) => cpuMs(x) / x.wall)), 2, true]));
const MB = 1024 * 1024;
table('RAM (working set, MiB)', [
	['idle after setup (median of all runs)', (n: string) => med(scenarios.flatMap((s) => ok(n, s[0]).map((x) => x.idle / MB))), 1, true],
	...scenarios.filter((s) => !s[0].startsWith('remote')).map((s) => [`peak, ${s[0]}`, (n: string) => med(ok(n, s[0]).map((x) => x.peak / MB)), 1, true] as [string, (n: string) => number, number, boolean])
]);
const fails = names.flatMap((n) => scenarios.flatMap((s) => (results[n]?.[s[0]] ?? []).filter((x) => typeof x === 'string').map((e) => `${n} / ${s[0]}: ${e}`)));
if (fails.length) console.log(`\nFailures:\n${fails.map((f) => `- ${f}`).join('\n')}`);
