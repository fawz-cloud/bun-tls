// Interleaved A/B for crypto work: the same scenarios against bench/compare's local Go TLS 1.3
// server, each run in its own process, variants alternating every round. The metric that
// matters on a laptop is CPU per unit (process cycles, all threads) — wall time swings with
// P/E-core scheduling. A variant = a source root (this tree, or a baseline copy made with
// `git archive <rev> | tar -x -C <dir>`) plus optional env (e.g. BUN_TLS_CRYPTO=node).
// Usage: bun bench/crypto/ab.ts [rounds=6] label=root[:ENV=V,...] ...   (default: this tree)
//        filter scenarios with SCEN=fresh,tp10 (names below). Windows-only (cycle counter).
import { dlopen, FFIType, ptr } from 'bun:ffi';

const { symbols: k32 } = dlopen('kernel32.dll', { QueryProcessCycleTime: { args: [FFIType.i64, FFIType.ptr], returns: FFIType.i32 } });
const cyc = new BigUint64Array(1);
const ownCycles = () => (k32.QueryProcessCycleTime(-1n, ptr(cyc)), Number(cyc[0]));
const RATE = (() => {
	const c0 = ownCycles();
	const t0 = performance.now();
	while (performance.now() - t0 < 500);
	return (ownCycles() - c0) / (performance.now() - t0); // cycles per ms
})();

const here = import.meta.dir;
const tree = `${here}/../..`;
const args = process.argv.slice(2);
const rounds = /^\d+$/.test(args[0] ?? '') ? Number(args.shift()) : 6;
const variants = (args.length ? args : [`this=${tree}`]).map((a) => {
	const [label, rest] = a.split(/=(.*)/s) as [string, string];
	const [root, envs] = rest.split(/:(?=[A-Z_]+=)/);
	const env = Object.fromEntries((envs ?? '').split(',').filter(Boolean).map((kv) => kv.split('=') as [string, string]));
	return { label, root: root!, env };
});

const L = 'https://localhost:48443';
// name, scenario, url, n, warmup, arg, unit of v, unit of CPU
const all: [string, string, string, number, number, number, string, string][] = [
	['fresh', 'fresh', `${L}/`, 500, 100, 0, 'ms', 'µs/req'],
	['tp10', 'tp', `${L}/`, 5000, 500, 10, 'req/s', 'µs/req'],
	['up10', 'up', `${L}/`, 10, 2, 10, 'MB/s', 'ms/MB'],
	['down10', 'down', `${L}/10mb`, 10, 2, 0, 'MB/s', 'ms/MB']
];
const only = process.env.SCEN?.split(',');
const scenarios = only ? all.filter((s) => only.includes(s[0])) : all;

const server = Bun.spawn([`${here}/../compare/bin/server.exe`, `${here}/..`], { stdout: 'ignore', stderr: 'inherit' });
for (let i = 0; ; i++) {
	try {
		(await Bun.connect({ hostname: '127.0.0.1', port: 48443, socket: { data() {} } })).end();
		break;
	} catch {
		if (i > 100) throw new Error('bench server did not start (build it: cd bench/compare && go build -o bin/server.exe ./server)');
		await Bun.sleep(50);
	}
}

const res = new Map<string, { v: number[]; cpu: number[] }>();
try {
	for (let r = 0; r < rounds; r++) {
		const order = r % 2 ? [...variants].reverse() : variants;
		for (const [name, scen, url, n, warm, arg] of scenarios)
			for (const v of order) {
				const p = Bun.spawn(['bun', `${here}/client.ts`, v.root, scen, url, String(n), String(warm), String(arg), '0'], {
					env: { ...process.env, ...v.env },
					stdout: 'pipe',
					stderr: 'inherit'
				});
				const out = await new Response(p.stdout).text();
				await p.exited;
				const j = JSON.parse(out.trim().split('\n').pop()!) as { v: number; cyc: number; n: number };
				const cpuMs = j.cyc / RATE;
				const perUnit = scen === 'up' || scen === 'down' ? cpuMs / j.n : (cpuMs * 1000) / j.n; // ms/MB or µs/req
				const e = res.get(`${name}|${v.label}`) ?? res.set(`${name}|${v.label}`, { v: [], cpu: [] }).get(`${name}|${v.label}`)!;
				e.v.push(j.v);
				e.cpu.push(perUnit);
			}
		process.stderr.write(`round ${r + 1}/${rounds} done\n`);
	}
} finally {
	server.kill();
}

const med = (a: number[]) => [...a].sort((x, y) => x - y)[a.length >> 1]!;
const f = (x: number) => (x >= 100 ? x.toFixed(0) : x >= 10 ? x.toFixed(1) : x.toFixed(2));
console.log(`\n| scenario | ${variants.map((v) => v.label).join(' | ')} |\n|---|${variants.map(() => '---|').join('')}`);
for (const [name, , , , , , vu, cu] of scenarios) {
	console.log(`| ${name} (${vu}) | ${variants.map((v) => f(med(res.get(`${name}|${v.label}`)!.v))).join(' | ')} |`);
	console.log(`| ${name} CPU (${cu}) | ${variants.map((v) => f(med(res.get(`${name}|${v.label}`)!.cpu))).join(' | ')} |`);
}
