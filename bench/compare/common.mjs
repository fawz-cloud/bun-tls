// Scenario runner shared by the JS clients (bun-tls on Bun, impers on Node and Bun).
// An adapter supplies fresh(url) and session(conc) → { get(url), post(url, body), close() };
// get/post resolve to the response body length.
// Usage: <runtime> <client> <scenario> <url> <n> <warm> <arg> <verify>; prints one JSON line.

// CPU = QueryProcessCycleTime (all threads, cycle-exact). process.cpuUsage() on Windows only
// moves in 15.6 ms clock ticks, too coarse per scenario. run.ts converts cycles to ms.
async function cycleCounter() {
	if (globalThis.Bun) {
		const { dlopen, FFIType, ptr } = await import('bun:ffi');
		const { symbols } = dlopen('kernel32.dll', { QueryProcessCycleTime: { args: [FFIType.i64, FFIType.ptr], returns: FFIType.i32 } });
		const out = new BigUint64Array(1);
		return () => (symbols.QueryProcessCycleTime(-1n, ptr(out)), Number(out[0])); // -1 = current process
	}
	const koffi = (await import('koffi')).default; // Node: koffi comes with impers
	const q = koffi.load('kernel32.dll').func('int __stdcall QueryProcessCycleTime(intptr_t h, _Out_ uint64_t *c)');
	return () => {
		const out = [0];
		q(-1, out);
		return Number(out[0]);
	};
}
const cycles = await cycleCounter();
const median = (a) => a.sort((x, y) => x - y)[a.length >> 1];

async function timed(fn, n, warm) {
	for (let i = 0; i < warm; i++) await fn();
	const t = [];
	const c0 = cycles();
	const w0 = performance.now();
	for (let i = 0; i < n; i++) {
		const a = performance.now();
		await fn();
		t.push(performance.now() - a);
	}
	return [median(t), cycles() - c0, performance.now() - w0];
}

export async function main(adapter) {
	const [scen, url] = process.argv.slice(2, 4);
	const [n, warm, arg] = process.argv.slice(4, 7).map(Number);

	await adapter.fresh(url); // setup: everything loaded and one handshake done
	const idle = process.memoryUsage().rss;

	let v, cpu, wall, units;
	if (scen === 'fresh') {
		[v, cpu, wall] = await timed(() => adapter.fresh(url), n, warm);
		units = n;
	} else if (scen === 'reuse') {
		const s = adapter.session(1);
		[v, cpu, wall] = await timed(() => s.get(url), n, warm);
		await s.close();
		units = n;
	} else if (scen === 'tp') {
		const run = async (total) => {
			const s = adapter.session(arg);
			let next = 0;
			const t0 = performance.now();
			await Promise.all(
				Array.from({ length: arg }, async () => {
					while (next < total) {
						next++;
						await s.get(url);
					}
				})
			);
			const sec = (performance.now() - t0) / 1000;
			await s.close();
			return sec;
		};
		await run(warm);
		const c0 = cycles();
		const w0 = performance.now();
		const sec = await run(n);
		[cpu, wall] = [cycles() - c0, performance.now() - w0];
		[v, units] = [n / sec, n];
	} else {
		// up / down: one keep-alive connection, arg MiB per POST (up) or the body size (down)
		const s = adapter.session(1);
		const body = scen === 'up' ? Buffer.alloc(arg << 20, 65) : null;
		const once = () => (body ? s.post(url, body).then(() => body.length) : s.get(url));
		const size = await once();
		let med;
		[med, cpu, wall] = await timed(once, n, warm);
		await s.close();
		const mb = size / 1e6;
		[v, units] = [mb / (med / 1000), mb * n];
	}
	const peak = process.resourceUsage().maxRSS * 1024;
	console.log(JSON.stringify({ v, cyc: cpu, wall, n: units, idle, peak }));
	process.exit(0);
}
